package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestCTFSubmissionWaitStopsClaimsWithoutChangingGenericTasksOrManualPause(t *testing.T) {
	pg := privateVerificationDB(t)
	engine := NewEngine(&Manager{pg: pg})
	var ctfTask *Task
	var ctfIntent int64
	for _, mode := range []string{"ctf", "pentest"} {
		row, err := pg.CreateTaskWithOptions("local wait fixture", "local goal", db.TaskCreateOptions{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		task := &Task{ID: fmt.Sprint(row.ID), Mode: mode, Store: pg.Exploration(row.ExplorationID)}
		intent, err := task.Store.AddIntent(map[string]any{"summary": "local intention"}, 5, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if mode == "ctf" {
			if err = pg.SyncCTFInput(t.Context(), row.ID, "current-input"); err != nil {
				t.Fatal(err)
			}
			e := &db.CTFExecution{ID: uuid.NewString(), TaskID: row.ID, InputHash: "current-input", StartedAt: time.Now()}
			if err = pg.SaveCTFExecution(t.Context(), e); err != nil {
				t.Fatal(err)
			}
			if _, err = pg.AddCTFCandidate(t.Context(), row.ID, e.ID, "flag{local}"); err != nil {
				t.Fatal(err)
			}
			ctfTask, ctfIntent = task, intent
			if !engine.ctfSubmissionWaiting(t.Context(), task) || engine.claimNext(t.Context(), task, "worker") != nil {
				t.Fatal("CTF claimed while waiting")
			}
		} else if engine.ctfSubmissionWaiting(t.Context(), task) || engine.claimNext(t.Context(), task, "worker") == nil {
			t.Fatal("generic task admission changed")
		}
	}
	var taskID int64
	if _, err := fmt.Sscan(ctfTask.ID, &taskID); err != nil {
		t.Fatal(err)
	}
	pending, err := pg.PendingCTFSubmission(t.Context(), taskID)
	if err != nil || pending == nil {
		t.Fatal(pending, err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), taskID, pending.ID, pending.Revision, "rejected", "incorrect"); err != nil {
		t.Fatal(err)
	}
	if engine.ctfSubmissionWaiting(t.Context(), ctfTask) || engine.claimNext(t.Context(), ctfTask, "worker") == nil {
		t.Fatal("rejection did not release intent")
	}
	if err = parkCTFSubmissionIntent(ctfTask.Store, ctfIntent); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, taskID); err != nil {
		t.Fatal(err)
	}
	if engine.claimNext(t.Context(), ctfTask, "worker") != nil {
		t.Fatal("manual pause was overridden")
	}
}
