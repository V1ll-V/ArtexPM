package server

import (
	"context"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"log"
	"strconv"
	"time"
)

const (
	closingDrainGrace = 90 * time.Second
	closingPollEvery  = 300 * time.Millisecond
)

type closingExecution struct {
	epoch  int64
	cancel context.CancelFunc
}

func intentFinalStateOnClosing(reason string) string {
	if reason == db.ClosingGoalSatisfied {
		return "stopped"
	}
	return "exhausted"
}
func (e *Engine) closingSnapshot(id string) (string, bool) {
	if !e.isSettling(id) {
		return "", false
	}
	v, _ := e.closingReason.Load(id)
	s, _ := v.(string)
	return s, true
}
func (e *Engine) currentRunEpoch(id string) int64 {
	v, _ := e.runEpoch.Load(id)
	n, _ := v.(int64)
	return n
}

func (e *Engine) enterClosing(ctx context.Context, t *Task, reason string) {
	if t == nil {
		return
	}
	e.enterClosingAtEpoch(ctx, t, reason, e.currentRunEpoch(t.ID))
}
func (e *Engine) enterClosingAtEpoch(ctx context.Context, t *Task, reason string, epoch int64) {
	if t == nil || e.m == nil || e.m.pg == nil || ctx.Err() != nil {
		return
	}
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	e.closingMu.Lock()
	defer e.closingMu.Unlock()
	if e.IsDeleting(t.ID) || e.IsPaused(t.ID) || e.currentRunEpoch(t.ID) != epoch {
		return
	}
	if _, ok := e.closingStarted.Load(t.ID); ok {
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return
	}
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	result, err := e.m.pg.EnterClosing(bounded, id, epoch, reason)
	if err != nil {
		log.Printf("[closing] task %s enter: %v", t.ID, err)
		return
	}
	if result != db.ClosingEntered && result != db.ClosingAlready {
		return
	}
	e.closingStarted.Store(t.ID, epoch)
	e.settling.Store(t.ID, true)
	e.closingReason.Store(t.ID, reason)
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	closingCtx, cancel := context.WithCancel(rt.ctx)
	execution := &closingExecution{epoch: epoch, cancel: cancel}
	e.closingExecutions.Store(t.ID, execution)
	runTaskRoutine(rt, func(loop context.Context) {
		defer cancel()
		defer e.closingExecutions.CompareAndDelete(t.ID, execution)
		e.closingCoordinator(closingCtx, t, reason, epoch)
	})
}

// The coordinator is not an inflight operation. Every destructive local action
// checks the persisted generation while holding the local transition mutex.
func (e *Engine) closingOwner(ctx context.Context, t *Task, epoch int64) (bool, error) {
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false, err
	}
	state, err := e.m.pg.TaskRuntimeState(ctx, id)
	return err == nil && state.Closing && state.RunEpoch == epoch && state.ClosingEpoch == epoch && !e.IsPaused(t.ID) && !e.IsDeleting(t.ID), err
}
func (e *Engine) closingCoordinator(ctx context.Context, t *Task, reason string, epoch int64) {
	defer func() {
		e.abortClosing(t.ID, epoch)
		// Wake only after removing our barrier; otherwise the wake-up can be
		// consumed while settling is still true and no new round will run.
		if ctx.Err() == nil {
			t.Notify()
		}
	}()
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	hardStop := time.Now().Add(closingDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if ctx.Err() != nil {
			return
		}
		e.closingMu.Lock()
		owned, err := e.closingOwner(ctx, t, epoch)
		if err == nil && owned && time.Now().After(hardStop) {
			e.cancelExec(t.ID, agent.AbortSettleDrainTimeout)
		}
		e.closingMu.Unlock()
		if err != nil {
			if sleepCtx(ctx, closingPollEvery) {
				return
			}
			continue
		}
		if !owned {
			return
		}
		if time.Now().After(hardStop) {
			if sleepCtx(ctx, 3*time.Second) {
				return
			}
			break
		}
		if sleepCtx(ctx, closingPollEvery) {
			return
		}
	}
	// Final planning is bounded even without a model. It never grants completion:
	// PostgreSQL rechecks the frozen basis, including actual goal evaluations.
	if reason == db.ClosingDeadline {
		owned, err := e.closingOwner(ctx, t, epoch)
		if err != nil || !owned {
			return
		}
		final, cancel := context.WithTimeout(ctx, 30*time.Second)
		e.runFinalPlannerRound(final, t)
		cancel()
	}
	for ctx.Err() == nil {
		e.deleteMu.RLock()
		e.closingMu.Lock()
		if e.IsPaused(t.ID) || e.IsDeleting(t.ID) {
			e.closingMu.Unlock()
			e.deleteMu.RUnlock()
			return
		}
		commitCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		status, err := e.m.CompleteTaskClosing(commitCtx, t.ID, epoch, reason)
		if err == nil && status == "" {
			// A changed requirement/proof or a pause invalidates the old basis. Revoke
			// only our own epoch; a resumed/new closing must remain untouched.
			var next int64
			next, err = e.m.pg.CancelClosing(commitCtx, id, epoch)
			if err == nil && next > 0 && e.currentRunEpoch(t.ID) == epoch {
				e.runEpoch.Store(t.ID, next)
			}
		}
		stop()
		e.closingMu.Unlock()
		e.deleteMu.RUnlock()
		if err == nil {
			if status != "" {
				e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: "收尾完成，终态=" + status})
			}
			return
		}
		log.Printf("[closing] task %s commit failed, retaining barrier: %v", t.ID, err)
		if sleepCtx(ctx, time.Second) {
			return
		}
	}
}
func (e *Engine) abortClosing(id string, epoch int64) {
	e.closingMu.Lock()
	defer e.closingMu.Unlock()
	if e.closingStarted.CompareAndDelete(id, epoch) {
		e.settling.Delete(id)
		e.closingReason.Delete(id)
	}
}

// Admission/goal edits already atomically revoked persistent closing. Adopt that
// committed generation before releasing the local pause/settling barriers.
func (e *Engine) resumeFromClosing(t *Task) error {
	if t == nil || e.m == nil || e.m.pg == nil {
		return nil
	}
	e.closingMu.Lock()
	defer e.closingMu.Unlock()
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, err := e.m.pg.TaskRuntimeState(ctx, id)
	if err != nil {
		return err
	}
	if state.RunEpoch != e.currentRunEpoch(t.ID) {
		if v, ok := e.closingExecutions.Load(t.ID); ok {
			run := v.(*closingExecution)
			if run.epoch != state.RunEpoch {
				run.cancel()
			}
		}
		e.runEpoch.Store(t.ID, state.RunEpoch)
		e.closingStarted.Delete(t.ID)
		e.settling.Delete(t.ID)
		e.closingReason.Delete(t.ID)
	}
	return nil
}
