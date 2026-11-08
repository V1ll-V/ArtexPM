package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTaskReportsUnavailableExecutionModelAndOptionalSwitchDoesNotBlockResume(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // no background planner/provider calls in this admission test
	var available atomic.Bool
	s := newAdmissionTestServer(m, func(*Task) bool { return available.Load() })
	s.ctx = ctx
	s.engine.lifecycleReady = func() bool { return false }
	w := httptest.NewRecorder()
	s.createTask(w, httptest.NewRequest("POST", "/api/tasks", strings.NewReader(`{"description":"local gate fixture","goal":"save a local marker without external traffic"}`)))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var dto TaskDTO
	if err = json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dto.ExecutionBlockedReason, "执行模型") {
		t.Fatal("created response concealed unavailable execution model", w.Body)
	}
	task, ok := m.Task(dto.ID)
	if !ok {
		t.Fatal("saved task missing")
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s.createGoals(t.Context(), task, nil)
	goals, err := task.Store.HasOpenGoal()
	if err != nil || !goals {
		t.Fatal("original goal lost", goals, err)
	}
	if _, err = s.applyTaskControl(task, "pause"); err != nil {
		t.Fatal(err)
	}
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil || !stored.Paused {
		t.Fatal("pause did not persist", stored, err)
	}
	available.Store(true)
	if reason := s.taskExecutionBlockReason(task); reason != "" {
		t.Fatal("optional switch still blocks task", reason)
	}
	if _, err = s.applyTaskControl(task, "resume"); err != nil {
		t.Fatal("optional switch prevented resume", err)
	}
	stored, err = m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil || stored.Paused {
		t.Fatal("resume did not commit", stored, err)
	}
}
