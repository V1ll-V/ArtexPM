package server

import (
	"context"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"strconv"
	"testing"
	"time"
)

func closingServerFixture(t *testing.T) (*Server, *Task, int64) {
	t.Helper()
	d := privateVerificationDB(t)
	task, err := d.CreateTask(t.Name(), "closing lifecycle", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{pg: d, dir: t.TempDir(), tasks: map[string]*Task{}}
	m.LoadExisting()
	live, ok := m.Task(strconv.FormatInt(task.ID, 10))
	if !ok {
		t.Fatal("task not loaded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	e := NewEngine(m)
	s := &Server{m: m, engine: e, ctx: ctx, chatBusy: map[string]bool{}, chatCancel: map[string]context.CancelCauseFunc{}}
	epoch, err := d.BumpRunEpoch(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.runEpoch.Store(live.ID, epoch)
	t.Cleanup(func() { cancel(); e.StopTask(live.ID) })
	return s, live, epoch
}
func waitClosingRoutines(t *testing.T, e *Engine, id string) {
	t.Helper()
	e.runtimeMu.Lock()
	rt := e.runtimes[id]
	e.runtimeMu.Unlock()
	if rt == nil {
		return
	}
	done := make(chan struct{})
	go func() { rt.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("closing did not finish")
	}
}
func TestClosingCoordinatorDrainDoesNotWaitForItself(t *testing.T) {
	s, task, epoch := closingServerFixture(t)
	e := s.engine
	if !e.beginTaskOperation(task.ID) {
		t.Fatal("operation not admitted")
	}
	e.enterClosing(s.ctx, task, db.ClosingGoalSatisfied)
	if got := e.inflightCount(task.ID); got != 1 {
		t.Fatalf("coordinator added itself to inflight: %d", got)
	}
	if !e.isSettling(task.ID) {
		t.Fatal("no local barrier")
	}
	e.decInflight(task.ID)
	waitClosingRoutines(t, e, task.ID)
	if got := task.lifecycleSnapshot().Status; got != "done" {
		t.Fatalf("status=%s", got)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	state, err := s.m.pg.TaskRuntimeState(t.Context(), id)
	if err != nil || state.Closing || state.RunEpoch != epoch {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}
func TestClosingAdmissionRevokesAndOldCoordinatorCannotClearSuccessor(t *testing.T) {
	s, task, old := closingServerFixture(t)
	e := s.engine
	e.beginTaskOperation(task.ID)
	defer e.decInflight(task.ID)
	e.enterClosing(s.ctx, task, db.ClosingGoalSatisfied)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	// The actual persistent admission statement fences closing in one commit.
	if err := s.m.ApplyTaskAdmission(task.ID, task.lifecycleSnapshot().Status, task.lifecycleSnapshot().Status, false, "resume", false); err != nil {
		t.Fatal(err)
	}
	e.Resume(task)
	next := e.currentRunEpoch(task.ID)
	if next <= old || e.isSettling(task.ID) {
		t.Fatal("resume failed to adopt revoked closing")
	}
	if r, err := s.m.pg.EnterClosing(t.Context(), id, next, db.ClosingGoalSatisfied); err != nil || r != db.ClosingEntered {
		t.Fatalf("successor: %s %v", r, err)
	}
	e.closingMu.Lock()
	e.closingStarted.Store(task.ID, next)
	e.settling.Store(task.ID, true)
	e.closingReason.Store(task.ID, db.ClosingGoalSatisfied)
	e.closingMu.Unlock()
	e.abortClosing(task.ID, old)
	if !e.isSettling(task.ID) {
		t.Fatal("old cleanup removed successor")
	}
	if status, err := s.m.CompleteTaskClosing(t.Context(), task.ID, old, db.ClosingGoalSatisfied); err != nil || status != "" {
		t.Fatalf("old terminal commit: %s %v", status, err)
	}
	waitClosingRoutines(t, e, task.ID)
	if !e.isSettling(task.ID) {
		t.Fatal("old running coordinator removed successor")
	}
}
func TestClosingRestoreRevokesBarrierBeforeStartingLoops(t *testing.T) {
	s, task, old := closingServerFixture(t)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := s.m.pg.Exec(`UPDATE tasks SET closing_reason='goal_satisfied',closing_run_epoch=run_epoch,closing_since=now(),paused=true,deadline_at=now()+interval '1 hour' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var deadline time.Time
	if err := s.m.pg.QueryRow(`SELECT deadline_at FROM tasks WHERE id=$1`, id).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	// Simulate a fresh process: use real LoadExisting/restoreTaskRuntimes.
	fresh := &Manager{pg: s.m.pg, dir: s.m.dir, tasks: map[string]*Task{}}
	engine := NewEngine(fresh)
	restored := &Server{m: fresh, engine: engine, ctx: s.ctx}
	restored.restoreTaskRuntimes()
	t.Cleanup(func() { engine.StopTask(task.ID) })
	state, err := s.m.pg.TaskRuntimeState(t.Context(), id)
	if err != nil || state.Closing || state.RunEpoch <= old {
		t.Fatalf("restart barrier=%+v err=%v", state, err)
	}
	if !engine.Started(task.ID) || !engine.IsPaused(task.ID) {
		t.Fatal("restart lost user pause or failed to restore runtime")
	}
	var after time.Time
	if err = s.m.pg.QueryRow(`SELECT deadline_at FROM tasks WHERE id=$1`, id).Scan(&after); err != nil || !after.Equal(deadline) {
		t.Fatal("recovery extended deadline")
	}
}
func TestClosingEpochFailureDoesNotLaunchUnprotectedRuntime(t *testing.T) {
	s, task, _ := closingServerFixture(t)
	_, err := s.m.pg.Exec(`CREATE FUNCTION reject_epoch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.run_epoch<>OLD.run_epoch THEN RAISE EXCEPTION 'epoch failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_epoch BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION reject_epoch()`)
	if err != nil {
		t.Fatal(err)
	}
	s.engine.Run(s.ctx, task)
	if s.engine.Started(task.ID) {
		t.Fatal("failed epoch left started marker")
	}
	s.engine.runtimeMu.Lock()
	count := len(s.engine.runtimes)
	s.engine.runtimeMu.Unlock()
	if count != 0 {
		t.Fatal("failed epoch registered unstarted routines")
	}
	if _, err = s.m.pg.Exec(`DROP TRIGGER reject_epoch ON tasks`); err != nil {
		t.Fatal(err)
	}
	s.engine.Run(s.ctx, task)
	if !s.engine.Started(task.ID) {
		t.Fatal("failed start cannot retry")
	}
}
func TestClosingPauseAndDeleteDoNotFinishTask(t *testing.T) {
	for _, action := range []string{"pause", "delete"} {
		t.Run(action, func(t *testing.T) {
			s, task, _ := closingServerFixture(t)
			e := s.engine
			e.beginTaskOperation(task.ID)
			e.enterClosing(s.ctx, task, db.ClosingGoalSatisfied)
			if action == "pause" {
				e.Pause(task.ID, agent.AbortPausedByUser)
				if err := s.m.ApplyTaskPause(task.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				e.BeginDelete(task.ID)
			}
			e.decInflight(task.ID)
			waitClosingRoutines(t, e, task.ID)
			if db.IsTerminal(task.lifecycleSnapshot().Status) {
				t.Fatal("paused/deleting task completed")
			}
		})
	}
}
func TestClosingStalePlannerCannotEnterForResumedRun(t *testing.T) {
	s, task, old := closingServerFixture(t)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := s.m.pg.BumpRunEpoch(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	s.engine.Resume(task)
	s.engine.enterClosingAtEpoch(s.ctx, task, db.ClosingGoalSatisfied, old)
	state, err := s.m.pg.TaskRuntimeState(t.Context(), id)
	if err != nil || state.Closing || s.engine.isSettling(task.ID) {
		t.Fatal("old planner closed resumed run")
	}
}

func TestClosingResumeCancelsObsoleteFinalPlannerWait(t *testing.T) {
	s, task, old := closingServerFixture(t)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := s.m.pg.Exec(`UPDATE tasks SET deadline_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	s.engine.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
		select {
		case entered <- struct{}{}:
		default:
		}
		return nil, nil
	})
	s.engine.enterClosing(s.ctx, task, db.ClosingDeadline)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final planner wait did not start")
	}
	if err := s.m.ApplyTaskAdmission(task.ID, task.lifecycleSnapshot().Status, task.lifecycleSnapshot().Status, false, "resume", false); err != nil {
		t.Fatal(err)
	}
	s.engine.Resume(task)
	waitClosingRoutines(t, s.engine, task.ID)
	if s.engine.currentRunEpoch(task.ID) <= old || db.IsTerminal(task.lifecycleSnapshot().Status) {
		t.Fatal("obsolete final planning survived resume")
	}
}

func TestClosingAdmissionStartFailureDoesNotLaunchDeadline(t *testing.T) {
	s, task, _ := closingServerFixture(t)
	task.TimeoutSeconds = 60
	_, err := s.m.pg.Exec(`CREATE FUNCTION reject_admission_epoch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.run_epoch<>OLD.run_epoch THEN RAISE EXCEPTION 'epoch failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_admission_epoch BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION reject_admission_epoch()`)
	if err != nil {
		t.Fatal(err)
	}
	s.engine.Pause(task.ID, agent.AbortPausedByUser)
	s.startAdmittedTask(task, "resume")
	if s.engine.Started(task.ID) || !s.engine.IsPaused(task.ID) {
		t.Fatal("admission bypassed failed epoch allocation")
	}
	if _, ok := s.engine.coordStarted.Load(task.ID); ok {
		t.Fatal("deadline started after failed runtime start")
	}
}

func TestClosingLostAcknowledgementRepairsLiveStatus(t *testing.T) {
	s, task, epoch := closingServerFixture(t)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if result, err := s.m.pg.EnterClosing(t.Context(), id, epoch, db.ClosingGoalSatisfied); err != nil || result != db.ClosingEntered {
		t.Fatal(result, err)
	}
	if status, err := s.m.pg.CompleteClosing(t.Context(), id, epoch, db.ClosingGoalSatisfied); err != nil || status != "done" {
		t.Fatal(status, err)
	}
	// Database committed, but the process missed the acknowledgement/mirror.
	if status, err := s.m.CompleteTaskClosing(t.Context(), task.ID, epoch, db.ClosingGoalSatisfied); err != nil || status != "done" || task.lifecycleSnapshot().Status != "done" {
		t.Fatal("retry did not repair live terminal state", status, err)
	}
}
func TestClosingRestoreQueuedTaskRevokesWithoutAdmission(t *testing.T) {
	s, task, old := closingServerFixture(t)
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if _, err := s.m.pg.Exec(`UPDATE tasks SET queued=true,queue_mode='resume',closing_reason='goal_satisfied',closing_run_epoch=run_epoch,closing_since=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	fresh := &Manager{pg: s.m.pg, dir: s.m.dir, tasks: map[string]*Task{}}
	engine := NewEngine(fresh)
	restored := &Server{m: fresh, engine: engine, ctx: s.ctx}
	restored.restoreTaskRuntimes()
	t.Cleanup(func() { engine.StopTask(task.ID) })
	state, err := s.m.pg.TaskRuntimeState(t.Context(), id)
	if err != nil || state.Closing || state.RunEpoch <= old || engine.Started(task.ID) {
		t.Fatalf("queued recovery: %+v %v", state, err)
	}
	loaded, _ := fresh.Task(task.ID)
	if !loaded.lifecycleSnapshot().Queued {
		t.Fatal("restart bypassed FIFO")
	}
}

func TestClosingFreshAdmissionStartsWithPersistentEpoch(t *testing.T) {
	s, task, old := closingServerFixture(t)
	if err := s.m.SetConcurrency(false, 1); err != nil {
		t.Fatal(err)
	}
	queued, err := s.admitTask(task, "resume")
	if err != nil || queued {
		t.Fatalf("admission: %v %v", queued, err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	state, err := s.m.pg.TaskRuntimeState(t.Context(), id)
	if err != nil || state.RunEpoch <= old || !s.engine.Started(task.ID) || s.engine.IsPaused(task.ID) {
		t.Fatalf("runtime was not safely started: %+v %v", state, err)
	}
}
