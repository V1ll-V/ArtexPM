package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func ctfCompletionFixture(t *testing.T) (*DB, *Task, CTFCandidate, int64, int64) {
	t.Helper()
	pg, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("local finish fixture", "recover flag", TaskCreateOptions{Mode: "ctf"})
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.SyncCTFInput(t.Context(), task.ID, "input-a"); err != nil {
		t.Fatal(err)
	}
	store := pg.Exploration(task.ExplorationID)
	goal, err := store.AddGoal(map[string]any{"text": "analysis probe"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.AddIntent(map[string]any{"summary": "local probe"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	e := &CTFExecution{ID: uuid.NewString(), TaskID: task.ID, InputHash: "input-a", StartedAt: time.Now()}
	if err = pg.SaveCTFExecution(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	id, err := pg.AddCTFCandidate(t.Context(), task.ID, e.ID, "flag{local_finish}")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatal(rows, err)
	}
	return pg, task, rows[0], goal, intent
}

func TestCTFConfirmAndFinishIsAtomicAuditableAndRevocable(t *testing.T) {
	pg, task, c, goal, intent := ctfCompletionFixture(t)
	if err := pg.CompleteCTFSubmission(t.Context(), task.ID, c.ID, c.Revision); err == nil {
		t.Fatal("unconfirmed flag completed task")
	}
	c, err := pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "accepted", "platform correct", true)
	if err != nil {
		t.Fatal(err)
	}
	row, err := pg.GetTask(task.ID)
	if err != nil || row.Status != "done" || row.CompletedAt == nil || row.Paused || row.Queued {
		t.Fatal(row, err)
	}
	store := pg.Exploration(task.ExplorationID)
	g, _ := store.GetNode(goal)
	in, _ := store.GetNode(intent)
	if g.State != "abandoned" || in.State != "stopped" {
		t.Fatal("unfinished work falsely marked met/done", g, in)
	}
	var auditCount int
	if err = pg.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND payload->>'subtype'='ctf_completion' AND origin='human' AND state='confirmed'`, task.ExplorationID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatal(auditCount, err)
	}
	if err = pg.CompleteCTFSubmission(t.Context(), task.ID, c.ID, c.Revision); err != nil {
		t.Fatal("idempotent finish failed", err)
	}
	after, _ := pg.GetTask(task.ID)
	if !after.CompletedAt.Equal(*row.CompletedAt) {
		t.Fatal("repeat finish changed completion time")
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "rejected", "platform rejected after recheck"); err != nil {
		t.Fatal(err)
	}
	row, err = pg.GetTask(task.ID)
	g, _ = store.GetNode(goal)
	if err != nil || row.Status == "done" || row.CompletedAt != nil || !row.Paused || g.State != "open" {
		t.Fatal("revoked success remained completed", row, g, err)
	}
}

func TestCTFConfirmOnlyPreservesOtherGoals(t *testing.T) {
	pg, task, c, goal, intent := ctfCompletionFixture(t)
	if _, err := pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "accepted", "first of multiple flags", false); err != nil {
		t.Fatal(err)
	}
	row, _ := pg.GetTask(task.ID)
	g, _ := pg.Exploration(task.ExplorationID).GetNode(goal)
	in, _ := pg.Exploration(task.ExplorationID).GetNode(intent)
	if row.Status == "done" || row.CompletedAt != nil || g.State != "open" || in.State != "open" {
		t.Fatal("confirm-only finished other goals", row, g, in)
	}
}

func TestCTFInputChangeReopensOperatorCompletedTask(t *testing.T) {
	pg, task, c, goal, _ := ctfCompletionFixture(t)
	if _, err := pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "accepted", "correct", true); err != nil {
		t.Fatal(err)
	}
	if err := pg.SyncCTFInput(t.Context(), task.ID, "new-input"); err != nil {
		t.Fatal(err)
	}
	row, _ := pg.GetTask(task.ID)
	g, _ := pg.Exploration(task.ExplorationID).GetNode(goal)
	if row.Status == "done" || row.CompletedAt != nil || !row.Paused || g.State != "open" {
		t.Fatal("old input remained completed", row, g)
	}
}

func TestCTFRevocationReopensLegacyCompletedTask(t *testing.T) {
	pg, task, c, _, _ := ctfCompletionFixture(t)
	c, err := pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "accepted", "old confirmation")
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.SetStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "rejected", "recheck failed"); err != nil {
		t.Fatal(err)
	}
	row, _ := pg.GetTask(task.ID)
	if row.Status == "done" || row.CompletedAt != nil || !row.Paused {
		t.Fatal("legacy success remained terminal", row)
	}
}

func TestCTFFinishRejectsOldInputStaleRevisionAndGenericTasks(t *testing.T) {
	for _, kind := range []string{"old_input", "stale_revision", "generic"} {
		t.Run(kind, func(t *testing.T) {
			pg, task, c, _, _ := ctfCompletionFixture(t)
			c, err := pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "accepted", "local")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "old_input" {
				if err = pg.SyncCTFInput(t.Context(), task.ID, "input-b"); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "stale_revision" {
				c.Revision--
			}
			if kind == "generic" {
				if _, err = pg.Exec(`UPDATE tasks SET mode='pentest' WHERE id=$1`, task.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err = pg.CompleteCTFSubmission(t.Context(), task.ID, c.ID, c.Revision); err == nil {
				t.Fatal("invalid finish accepted")
			}
			row, _ := pg.GetTask(task.ID)
			if row.Status == "done" {
				t.Fatal("invalid finish changed task")
			}
		})
	}
}
