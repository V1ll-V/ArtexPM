package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestClosingRejectsUnverifiedCompletion(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask(t.Name(), "unverified goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exploration(task.ExplorationID).AddGoal(map[string]any{"text": "must be verified"}, "user"); err != nil {
		t.Fatal(err)
	}
	epoch, err := d.BumpRunEpoch(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := d.EnterClosing(t.Context(), task.ID, epoch, ClosingGoalSatisfied)
	if err != nil {
		t.Fatal(err)
	}
	if result == ClosingEntered {
		t.Fatal("unverified goal was accepted as a completion basis")
	}
}

func TestClosingClaimRejectsPausedTask(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask(t.Name(), "pause", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.Exploration(task.ExplorationID).AddIntent(map[string]any{"summary": "work"}, 0, nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	won, err := d.ClaimIntentGuarded(t.Context(), task.ID, id, "test")
	if err != nil {
		t.Fatal(err)
	}
	if won {
		t.Fatal("paused task admitted a new claim")
	}
}

func TestClosingNewEpochAtomicallyRevokesPersistedBarrier(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask(t.Name(), "recover", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE tasks SET run_epoch=7,closing_reason='goal_satisfied',closing_run_epoch=7,closing_since=now(),deadline_at=now()+interval '1 hour' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	next, err := d.BumpRunEpoch(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := d.TaskRuntimeState(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if next != 8 || state.Closing || state.ClosingEpoch != 0 {
		t.Fatalf("new epoch retained old barrier: %+v", state)
	}
}

func verifiedClosingFixture(t *testing.T, d *DB) (*ExplorationStore, int64, int64, int64, int64) {
	t.Helper()
	es, g, f, j := goalInputFixture(t, d)
	if _, err := d.PrepareVerificationInput(t.Context(), j.ID, j.LeaseGeneration); err != nil {
		t.Fatal(err)
	}
	if result, err := es.CommitGoalEvaluation(t.Context(), j.ID, j.LeaseGeneration, "met"); err != nil || result != CommitOK {
		t.Fatalf("verify: %s %v", result, err)
	}
	var id int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, es.ID()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	epoch, err := d.BumpRunEpoch(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return es, id, g, f, epoch
}
func enterVerifiedClosing(t *testing.T, d *DB, id, epoch int64) {
	t.Helper()
	r, e := d.EnterClosing(t.Context(), id, epoch, ClosingGoalSatisfied)
	if e != nil || r != ClosingEntered {
		t.Fatalf("enter: %s %v", r, e)
	}
}
func TestClosingAtomicCommitAndRejection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DB, *ExplorationStore, int64, int64, int64) error
		want   string
	}{
		{"unchanged", func(*DB, *ExplorationStore, int64, int64, int64) error { return nil }, "done"},
		{"pause", func(d *DB, _ *ExplorationStore, id, g, f int64) error { return d.SetPaused(id, true) }, ""},
		{"queue", func(d *DB, _ *ExplorationStore, id, g, f int64) error { return d.Enqueue(id, "resume") }, ""},
		{"delete", func(d *DB, _ *ExplorationStore, id, g, f int64) error {
			_, e := d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, id)
			return e
		}, ""},
		{"new_epoch", func(d *DB, _ *ExplorationStore, id, g, f int64) error {
			_, e := d.BumpRunEpoch(t.Context(), id)
			return e
		}, ""},
		{"requirement_edit", func(_ *DB, s *ExplorationStore, id, g, f int64) error {
			return s.UpdateGoalPayload(g, "new requirement", "")
		}, ""},
		{"goal_add", func(_ *DB, s *ExplorationStore, id, g, f int64) error {
			_, e := s.AddGoal(map[string]any{"text": "new goal"}, "user")
			return e
		}, ""},
		{"goal_delete", func(_ *DB, s *ExplorationStore, id, g, f int64) error { return s.DeleteGoal(g) }, ""},
		{"proof_retracted", func(_ *DB, s *ExplorationStore, id, g, f int64) error { return s.SetNodeState(f, "dismissed") }, ""},
		{"proof_payload", func(d *DB, _ *ExplorationStore, id, g, f int64) error {
			_, e := d.Exec(`UPDATE exploration_nodes SET payload='{"detail":"changed"}' WHERE id=$1`, f)
			return e
		}, ""},
		{"policy", func(d *DB, _ *ExplorationStore, id, g, f int64) error {
			_, e := d.Exec(`UPDATE verification_jobs SET policy_version='old-policy' WHERE subject_kind='goal' AND subject_id=$1`, g)
			return e
		}, ""},
		{"task_requirement", func(d *DB, _ *ExplorationStore, id, g, f int64) error {
			_, e := d.Exec(`UPDATE tasks SET goal='new contract' WHERE id=$1`, id)
			return e
		}, ""},
	}
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			es, id, g, f, epoch := verifiedClosingFixture(t, d)
			enterVerifiedClosing(t, d, id, epoch)
			if err := tc.mutate(d, es, id, g, f); err != nil {
				t.Fatal(err)
			}
			status, err := d.CompleteClosing(t.Context(), id, epoch, ClosingGoalSatisfied)
			if err != nil || status != tc.want {
				t.Fatalf("commit=%q want=%q err=%v", status, tc.want, err)
			}
			var actual string
			var completed bool
			if err = d.QueryRow(`SELECT status,completed_at IS NOT NULL FROM tasks WHERE id=$1`, id).Scan(&actual, &completed); err != nil {
				t.Fatal(err)
			}
			if tc.want == "done" {
				if actual != "done" || !completed {
					t.Fatal("terminal state not committed")
				}
				state, _ := d.TaskRuntimeState(t.Context(), id)
				if state.Closing {
					t.Fatal("terminal retained barrier")
				}
			} else if IsTerminal(actual) || completed {
				t.Fatal("rejected commit stamped terminal state")
			}
		})
	}
}
func TestClosingDatabaseFailureRollsBackAndCanRetry(t *testing.T) {
	d, e := privateVerificationInputDB(t)
	if e != nil {
		t.Fatal(e)
	}
	_, id, _, _, epoch := verifiedClosingFixture(t, d)
	enterVerifiedClosing(t, d, id, epoch)
	_, e = d.Exec(`CREATE FUNCTION reject_closing_terminal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='done' THEN RAISE EXCEPTION 'injected closing failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_closing_terminal BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION reject_closing_terminal()`)
	if e != nil {
		t.Fatal(e)
	}
	if status, e := d.CompleteClosing(t.Context(), id, epoch, ClosingGoalSatisfied); e == nil || status != "" {
		t.Fatal("database failure accepted as done")
	}
	state, e := d.TaskRuntimeState(t.Context(), id)
	if e != nil || !state.Closing {
		t.Fatal("rollback lost retryable barrier")
	}
	if _, e = d.Exec(`DROP TRIGGER reject_closing_terminal ON tasks`); e != nil {
		t.Fatal(e)
	}
	if status, e := d.CompleteClosing(t.Context(), id, epoch, ClosingGoalSatisfied); e != nil || status != "done" {
		t.Fatalf("retry: %s %v", status, e)
	}
}
func waitClosingBlock(t *testing.T, d *DB, pid int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for {
		var blocked bool
		e := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND $1::integer=ANY(pg_blocking_pids(a.pid)))`, pid).Scan(&blocked)
		if e != nil {
			t.Fatal(e)
		}
		if blocked {
			return
		}
	}
}
func TestClosingClaimOrderingWithTaskLock(t *testing.T) {
	for _, claimFirst := range []bool{true, false} {
		t.Run(fmt.Sprint("claim_first_", claimFirst), func(t *testing.T) {
			d, e := privateVerificationInputDB(t)
			if e != nil {
				t.Fatal(e)
			}
			es, id, _, _, epoch := verifiedClosingFixture(t, d)
			intent, e := es.AddIntent(map[string]any{"summary": "already accepted work"}, 0, nil, "user")
			if e != nil {
				t.Fatal(e)
			}
			blocker, e := d.BeginTx(t.Context(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer blocker.Rollback()
			var pid int
			if e = blocker.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); e != nil {
				t.Fatal(e)
			}
			if e = LockTaskEvidenceTx(blocker, id); e != nil {
				t.Fatal(e)
			}
			claims := make(chan bool, 1)
			closes := make(chan string, 1)
			errs := make(chan error, 2)
			claim := func() {
				won, e := d.ClaimIntentGuarded(t.Context(), id, intent, "test", epoch)
				claims <- won
				errs <- e
			}
			close := func() { r, e := d.EnterClosing(t.Context(), id, epoch, ClosingGoalSatisfied); closes <- r; errs <- e }
			if claimFirst {
				go claim()
			} else {
				go close()
			}
			waitClosingBlock(t, d, pid)
			if claimFirst {
				go close()
			} else {
				go claim()
			}
			if e = blocker.Commit(); e != nil {
				t.Fatal(e)
			}
			for range 2 {
				if e = <-errs; e != nil {
					t.Fatal(e)
				}
			}
			if won := <-claims; won != claimFirst {
				t.Fatalf("claim=%v", won)
			}
			if r := <-closes; r != ClosingEntered {
				t.Fatalf("closing=%s", r)
			}
		})
	}
}
func TestClosingConcurrentResumeCannotCommitOldEpoch(t *testing.T) {
	d, e := privateVerificationInputDB(t)
	if e != nil {
		t.Fatal(e)
	}
	_, id, _, _, epoch := verifiedClosingFixture(t, d)
	enterVerifiedClosing(t, d, id, epoch)
	blocker, e := d.BeginTx(t.Context(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Rollback()
	var pid int
	if e = blocker.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); e != nil {
		t.Fatal(e)
	}
	if e = LockTaskEvidenceTx(blocker, id); e != nil {
		t.Fatal(e)
	}
	type result struct {
		s string
		e error
	}
	done := make(chan result, 1)
	go func() { s, e := d.CompleteClosing(t.Context(), id, epoch, ClosingGoalSatisfied); done <- result{s, e} }()
	waitClosingBlock(t, d, pid)
	if _, e = blocker.Exec(`UPDATE tasks SET run_epoch=run_epoch+1,closing_run_epoch=run_epoch+1,closing_since=clock_timestamp() WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if e = blocker.Commit(); e != nil {
		t.Fatal(e)
	}
	r := <-done
	if r.e != nil || r.s != "" {
		t.Fatalf("old commit: %+v", r)
	}
	if n, e := d.CancelClosing(t.Context(), id, epoch); e != nil || n != 0 {
		t.Fatal("old cancellation changed successor")
	}
	state, e := d.TaskRuntimeState(t.Context(), id)
	if e != nil || !state.Closing || state.RunEpoch != epoch+1 {
		t.Fatal("successor barrier lost")
	}
}
func TestClosingGoalEditRollbackAndDeadline(t *testing.T) {
	d, e := privateVerificationInputDB(t)
	if e != nil {
		t.Fatal(e)
	}
	es, id, _, _, epoch := verifiedClosingFixture(t, d)
	if _, e = d.Exec(`UPDATE tasks SET deadline_at=now()+interval '1 hour' WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	enterVerifiedClosing(t, d, id, epoch)
	if e = es.UpdateGoalPayload(-1, "missing", ""); e == nil {
		t.Fatal("missing goal succeeded")
	}
	state, e := d.TaskRuntimeState(t.Context(), id)
	if e != nil || state.RunEpoch != epoch || !state.Closing {
		t.Fatal("failed edit revoked closing")
	}
	if _, e = d.CancelClosing(t.Context(), id, epoch); e != nil {
		t.Fatal(e)
	}
	next, e := d.RunEpoch(t.Context(), id)
	if e != nil {
		t.Fatal(e)
	}
	if r, e := d.EnterClosing(t.Context(), id, next, ClosingDeadline); e != nil || r != ClosingNotReady {
		t.Fatalf("early deadline=%s %v", r, e)
	}
	if _, e = d.Exec(`UPDATE tasks SET deadline_at=now()-interval '1 second' WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e = es.AddGoal(map[string]any{"text": "unfinished"}, "user"); e != nil {
		t.Fatal(e)
	}
	if r, e := d.EnterClosing(t.Context(), id, next, ClosingDeadline); e != nil || r != ClosingEntered {
		t.Fatalf("deadline enter=%s %v", r, e)
	}
	if status, e := d.CompleteClosing(t.Context(), id, next, ClosingDeadline); e != nil || status != "timeout" {
		t.Fatalf("deadline commit=%s %v", status, e)
	}
}

func TestClosingSchemaUpgradeAndLegacyRecovery(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask(t.Name(), "legacy closing", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`ALTER TABLE tasks DROP COLUMN closing_basis`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE tasks SET run_epoch=9,closing_run_epoch=9,closing_reason='goal_satisfied',closing_since=now() WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = d.Exec(schemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	if status, err := d.CompleteClosing(t.Context(), task.ID, 9, ClosingGoalSatisfied); err != nil || status != "" {
		t.Fatalf("unfrozen legacy completion: %s %v", status, err)
	}
	epoch, err := d.BumpRunEpoch(t.Context(), task.ID)
	if err != nil || epoch != 10 {
		t.Fatalf("recovery: %d %v", epoch, err)
	}
	state, err := d.TaskRuntimeState(t.Context(), task.ID)
	if err != nil || state.Closing {
		t.Fatal("legacy closing survived recovery")
	}
}

func TestClosingArchiveBarrierAndReadFailure(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	es, id, _, _, epoch := verifiedClosingFixture(t, d)
	enterVerifiedClosing(t, d, id, epoch)
	if _, err = d.Exec(`INSERT INTO task_archives(task_id) VALUES($1)`, id); err != nil {
		t.Fatal(err)
	}
	if status, err := d.CompleteClosing(t.Context(), id, epoch, ClosingGoalSatisfied); err == nil || status != "" {
		t.Fatal("archive barrier bypassed")
	}
	if _, err = d.BumpRunEpoch(t.Context(), id); err == nil {
		t.Fatal("archived task started a run")
	}
	if _, err = es.AddGoal(map[string]any{"text": "archived edit"}, "user"); err == nil {
		t.Fatal("goal edit bypassed archive barrier")
	}
	if _, err = d.Exec(`UPDATE task_archives SET state=$2 WHERE task_id=$1`, id, ArchiveFailed); err != nil {
		t.Fatal(err)
	}
	next, err := d.BumpRunEpoch(t.Context(), id)
	if err != nil || next != epoch+1 {
		t.Fatalf("failed archive should permit recovery: %d %v", next, err)
	}
	enterVerifiedClosing(t, d, id, next)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if status, err := d.CompleteClosing(cancelled, id, next, ClosingGoalSatisfied); err == nil || status != "" {
		t.Fatal("read failure fell through to done")
	}
	var status string
	if err = d.QueryRow(`SELECT status FROM tasks WHERE id=$1`, id).Scan(&status); err != nil || IsTerminal(status) {
		t.Fatal("read failure changed terminal state")
	}
}
