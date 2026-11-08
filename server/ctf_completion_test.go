package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/ctf"
	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestCTFConfirmationUpdatesLiveTaskStatusWithoutModel(t *testing.T) {
	pg := privateVerificationDB(t)
	root := t.TempDir()
	row, err := pg.CreateTaskWithOptions("local", "recover flag", db.TaskCreateOptions{Mode: "ctf"})
	if err != nil {
		t.Fatal(err)
	}
	if err = ctf.New(root, pg).Sync(t.Context(), row.ID); err != nil {
		t.Fatal(err)
	}
	row, _ = pg.GetTask(row.ID)
	var hash string
	if err = pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, row.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	e := &db.CTFExecution{ID: uuid.NewString(), TaskID: row.ID, InputHash: hash, StartedAt: time.Now()}
	if err = pg.SaveCTFExecution(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	id, err := pg.AddCTFCandidate(t.Context(), row.ID, e.ID, "flag{api_finish}")
	if err != nil {
		t.Fatal(err)
	}
	candidates, _ := pg.CTFCandidates(t.Context(), row.ID)
	c := candidates[0]
	task := &Task{ID: fmt.Sprint(row.ID), Mode: "ctf", Status: row.Status, Store: pg.Exploration(row.ExplorationID)}
	m := &Manager{pg: pg, dir: root, tasks: map[string]*Task{task.ID: task}}
	s := &Server{m: m, engine: NewEngine(m), ctx: t.Context()}
	call := func(state string, finish bool) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/local", strings.NewReader(fmt.Sprintf(`{"state":%q,"revision":%d,"complete_task":%t}`, state, c.Revision, finish)))
		r.SetPathValue("id", task.ID)
		r.SetPathValue("candidateID", fmt.Sprint(id))
		s.decideCTFFlag(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if err = json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
	}
	call("accepted", true)
	if state := task.lifecycleSnapshot(); state.Status != "done" || state.CompletedAt == 0 || state.Paused {
		t.Fatal("live task mirror stale", state)
	}
	call("rejected", false)
	if state := task.lifecycleSnapshot(); state.Status == "done" || state.CompletedAt != 0 || !state.Paused || !s.engine.IsPaused(task.ID) {
		t.Fatal("revocation mirror stale", state)
	}
}
