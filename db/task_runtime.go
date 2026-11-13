package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const (
	ClosingGoalSatisfied   = "goal_satisfied"
	ClosingDeadline        = "deadline"
	ClosingBudgetExhausted = "budget_exhausted"
	ClosingAllBlocked      = "all_blocked"
	ClosingEntered         = "entered"
	ClosingAlready         = "already_closing"
	ClosingStaleRun        = "stale_run"
	ClosingTerminal        = "terminal"
	ClosingNotReady        = "not_ready"
)

var ErrTaskNotFound = errors.New("task not found")

// Allocate a new runtime and revoke its predecessor in the SAME statement.
// Used on first start/restart; admission handles explicit continuations.
func (d *DB) BumpRunEpoch(ctx context.Context, id int64) (int64, error) {
	var epoch int64
	err := d.QueryRowContext(ctx, `UPDATE tasks SET run_epoch=run_epoch+1,
 closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis=''
 WHERE id=$1 AND deleted_at IS NULL AND status NOT IN ('done','failed','timeout')
 AND NOT EXISTS(SELECT 1 FROM task_archives a WHERE a.task_id=tasks.id AND a.state<>$2)
 RETURNING run_epoch`, id, ArchiveFailed).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrTaskNotFound
	}
	return epoch, err
}
func (d *DB) RunEpoch(ctx context.Context, id int64) (int64, error) {
	var n int64
	err := d.QueryRowContext(ctx, `SELECT run_epoch FROM tasks WHERE id=$1`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrTaskNotFound
	}
	return n, err
}

type ClosingState struct {
	Closing      bool   `json:"closing"`
	Reason       string `json:"reason,omitempty"`
	RunEpoch     int64  `json:"run_epoch"`
	ClosingEpoch int64  `json:"closing_run_epoch,omitempty"`
}

func (d *DB) TaskRuntimeState(ctx context.Context, id int64) (out ClosingState, err error) {
	err = d.QueryRowContext(ctx, `SELECT closing_reason,run_epoch,closing_run_epoch FROM tasks WHERE id=$1`, id).Scan(&out.Reason, &out.RunEpoch, &out.ClosingEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrTaskNotFound
	}
	out.Closing = out.Reason != ""
	return
}

type closingTask struct {
	status, reason, basis, goal string
	mode, challengeType         string
	epoch, closingEpoch, expID  int64
	paused, queued, expired     bool
	deleted                     sql.NullTime
	deadline                    sql.NullTime
}

func closingTaskTx(ctx context.Context, tx *sql.Tx, id int64) (r closingTask, err error) {
	err = tx.QueryRowContext(ctx, `SELECT status,closing_reason,closing_basis,COALESCE(goal,''),mode,COALESCE(challenge_type,''),run_epoch,closing_run_epoch,
 exploration_id,paused,queued,COALESCE(deadline_at<=clock_timestamp(),false),deleted_at,deadline_at FROM tasks WHERE id=$1 FOR UPDATE`, id).
		Scan(&r.status, &r.reason, &r.basis, &r.goal, &r.mode, &r.challengeType, &r.epoch, &r.closingEpoch, &r.expID, &r.paused, &r.queued, &r.expired, &r.deleted, &r.deadline)
	return
}

// The evidence advisory lock fences graph/evidence edits; task locks fence
// pause/admission/deletion. A cached node state alone never proves completion.
func completionBasisTx(ctx context.Context, tx *sql.Tx, r closingTask) (string, bool, error) {
	type goalRow struct {
		ID, Version          int64
		State, Payload, Hash string
		Job                  int64
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,content_version,state,payload::text FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' ORDER BY id FOR UPDATE`, r.expID)
	if err != nil {
		return "", false, err
	}
	goals := []goalRow{}
	for rows.Next() {
		var g goalRow
		if err = rows.Scan(&g.ID, &g.Version, &g.State, &g.Payload); err != nil {
			rows.Close()
			return "", false, err
		}
		goals = append(goals, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", false, err
	}
	ready := true
	active := 0
	for i := range goals {
		g := &goals[i]
		if g.State == "abandoned" {
			continue
		}
		active++
		if g.State != "met" {
			ready = false
			continue
		}
		var state, verdict, policy, hash, reason string
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT id,state,committed_verdict,policy_version,input_hash,request_reason,input_revision FROM verification_jobs
   WHERE subject_kind='goal' AND subject_id=$1 ORDER BY id DESC LIMIT 1`, g.ID).Scan(&g.Job, &state, &verdict, &policy, &hash, &reason, &revision)
		if errors.Is(err, sql.ErrNoRows) {
			ready = false
			continue
		}
		if err != nil {
			return "", false, err
		}
		b, e := buildGoalBundleTx(ctx, tx, r.expID, g.ID, reason)
		if e != nil {
			return "", false, e
		}
		g.Hash = b.InputHash
		if state != JobCommitted || verdict != "met" || policy != VerdictPolicyVersion || hash != b.InputHash || revision != b.InputRevision || !goalProofActive(b) {
			ready = false
		}
	}
	if active == 0 {
		var work bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running'))`, r.expID).Scan(&work); err != nil {
			return "", false, err
		}
		ready = !work
	}
	hash, err := canonicalReportHash(struct {
		Goal     string
		Goals    []goalRow
		Ready    bool
		Deadline sql.NullTime
	}{r.goal, goals, ready, r.deadline})
	return hash, ready, err
}

func (d *DB) EnterClosing(ctx context.Context, id, epoch int64, reason string) (result string, err error) {
	if reason != ClosingGoalSatisfied && reason != ClosingDeadline {
		return "", fmt.Errorf("unsupported closing reason %q", reason)
	}
	result = ClosingEntered
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		r, e := closingTaskTx(ctx, tx, id)
		if errors.Is(e, sql.ErrNoRows) {
			result = ClosingTerminal
			return nil
		}
		if e != nil {
			return e
		}
		if r.deleted.Valid || IsTerminal(r.status) {
			result = ClosingTerminal
			return nil
		}
		if e = LockTaskEvidenceTx(tx, id); e != nil {
			return e
		}
		if r.epoch != epoch {
			result = ClosingStaleRun
			return nil
		}
		if r.paused || r.queued {
			result = ClosingNotReady
			return nil
		}
		if r.reason != "" {
			if r.closingEpoch == epoch && r.reason == reason {
				result = ClosingAlready
			} else {
				result = ClosingStaleRun
			}
			return nil
		}
		basis, ready, e := completionBasisTx(ctx, tx, r)
		if e != nil {
			return e
		}
		if reason == ClosingGoalSatisfied && !ready || reason == ClosingDeadline && !r.expired {
			result = ClosingNotReady
			return nil
		}
		_, e = tx.ExecContext(ctx, `UPDATE tasks SET closing_reason=$2,closing_run_epoch=$3,closing_since=clock_timestamp(),closing_basis=$4 WHERE id=$1`, id, reason, epoch, basis)
		return e
	})
	return
}

// CompleteClosing checks all authority and completion inputs under the same
// transaction that writes terminal status. Errors NEVER fall through to done.
func (d *DB) CompleteClosing(ctx context.Context, id, epoch int64, reason string) (status string, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		r, e := closingTaskTx(ctx, tx, id)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		// A commit acknowledgement can be lost. Re-reading a terminal in the same
		// epoch repairs the live mirror without writing or ending a newer run.
		if !r.deleted.Valid && IsTerminal(r.status) && r.epoch == epoch {
			status = r.status
			return nil
		}
		if r.deleted.Valid || IsTerminal(r.status) || r.paused || r.queued || r.epoch != epoch || r.closingEpoch != epoch || r.reason != reason || r.basis == "" {
			return nil
		}
		if e = LockTaskEvidenceTx(tx, id); e != nil {
			return e
		}
		basis, ready, e := completionBasisTx(ctx, tx, r)
		if e != nil {
			return e
		}
		if basis != r.basis {
			return nil
		}
		next := ""
		switch reason {
		case ClosingGoalSatisfied:
			if ready {
				next = "done"
			}
		case ClosingDeadline:
			if r.expired {
				next = "timeout"
				if ready {
					next = "done"
				}
			}
		}
		if next == "" {
			return nil
		}
		_, e = tx.ExecContext(ctx, `UPDATE tasks SET status=$2,completed_at=COALESCE(completed_at,clock_timestamp()),
    closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis='' WHERE id=$1`, id, next)
		if e == nil {
			status = next
		}
		return e
	})
	if err != nil {
		status = ""
	}
	return
}

// Only the owner of this epoch can revoke a closing. A revocation allocates a
// successor so a delayed coordinator cannot cancel a replacement closing.
func (d *DB) CancelClosing(ctx context.Context, id, epoch int64) (int64, error) {
	var next int64
	err := d.QueryRowContext(ctx, `UPDATE tasks SET run_epoch=run_epoch+1,closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis=''
 WHERE id=$1 AND run_epoch=$2 AND closing_run_epoch=$2 AND closing_reason<>'' AND deleted_at IS NULL
 AND status NOT IN ('done','failed','timeout') RETURNING run_epoch`, id, epoch).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return next, err
}

// Deprecated compatibility entry: revocation itself also fences old execution.
func (d *DB) ExitClosing(ctx context.Context, id int64) error {
	_, err := d.BumpRunEpoch(ctx, id)
	return err
}
func (d *DB) ClearClosingIfTerminal(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `UPDATE tasks SET closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis=''
 WHERE id=$1 AND status IN ('done','failed','timeout')`, id)
	return err
}

func (d *DB) ClaimIntentGuarded(ctx context.Context, taskID, intentID int64, owner string, epochs ...int64) (claimed bool, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		r, e := closingTaskTx(ctx, tx, taskID)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if r.deleted.Valid || r.paused || r.queued || r.reason != "" || IsTerminal(r.status) || r.expired {
			return nil
		}
		if len(epochs) > 0 && epochs[0] != r.epoch {
			return nil
		}
		if e = LockTaskEvidenceTx(tx, taskID); e != nil {
			return e
		}
		if strings.EqualFold(r.mode, "ctf") && (strings.EqualFold(r.challengeType, "pwn") || strings.EqualFold(r.challengeType, "reverse")) {
			var targetPhase string
			if e = tx.QueryRowContext(ctx, `SELECT lower(COALESCE(payload->>'phase','')) FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`, intentID, r.expID).Scan(&targetPhase); e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if targetPhase == "exploit" {
				var active bool
				if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state IN ('running','paused') AND id<>$2 AND lower(COALESCE(payload->>'phase',''))='exploit')`, r.expID, intentID).Scan(&active); e != nil {
					return e
				}
				if active {
					return nil
				}
			}
		}
		result, e := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='running',owner=$2 WHERE id=$1 AND kind='intent' AND state='open' AND exploration_id=$3`, intentID, owner, r.expID)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		claimed = n == 1
		return e
	})
	return
}

// Called inside explicit goal edits, before locking the goal row.
func lockExplorationTasksTx(tx *sql.Tx, expID int64) error {
	rows, err := tx.Query(`SELECT id FROM tasks WHERE exploration_id=$1 ORDER BY id`, expID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = LockTaskEvidenceTx(tx, id); err != nil {
			return err
		}
	}
	return nil
}
func revokeClosingForGoalEditTx(tx *sql.Tx, expID int64) error {
	if err := lockExplorationTasksTx(tx, expID); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE tasks SET run_epoch=run_epoch+CASE WHEN closing_reason<>'' THEN 1 ELSE 0 END,
 closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis='' WHERE exploration_id=$1 AND deleted_at IS NULL`, expID)
	return err
}
