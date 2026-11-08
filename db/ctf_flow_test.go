package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCTFSubmissionWaitAndRejectedOutputDeduplication(t *testing.T) {
	pg, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("local", "flag", TaskCreateOptions{Mode: "ctf"})
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.SyncCTFInput(t.Context(), task.ID, "input-a"); err != nil {
		t.Fatal(err)
	}
	add := func() int64 {
		t.Helper()
		e := &CTFExecution{ID: uuid.NewString(), TaskID: task.ID, InputHash: "input-a", StartedAt: time.Now()}
		if err := pg.SaveCTFExecution(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		id, err := pg.AddCTFOutputCandidate(t.Context(), task.ID, e.ID, "flag{local}")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	add()
	add()
	pending, err := pg.PendingCTFSubmission(t.Context(), task.ID)
	if err != nil || pending == nil {
		t.Fatal(pending, err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, pending.ID, pending.Revision, "rejected", "wrong answer"); err != nil {
		t.Fatal(err)
	}
	if pending, err = pg.PendingCTFSubmission(t.Context(), task.ID); err != nil || pending != nil {
		t.Fatal("duplicate still blocks", pending, err)
	}
	if id := add(); id != 0 {
		t.Fatal("rejected output created another wait", id)
	}
	if _, err = pg.Exec(`UPDATE tasks SET mode='pentest' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE ctf_candidates SET state='candidate' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err = pg.PendingCTFSubmission(t.Context(), task.ID); err != nil || pending != nil {
		t.Fatal("generic task blocked by CTF evidence", err)
	}
	if _, err = pg.Exec(`UPDATE tasks SET mode='ctf',ctf_input_hash='input-b' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err = pg.PendingCTFSubmission(t.Context(), task.ID); err != nil || pending != nil {
		t.Fatal("old input blocked new task input", err)
	}
}
