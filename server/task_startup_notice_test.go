package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateTaskReportsDisabledGateAndResumePreservesPause(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := newAdmissionTestServer(m, nil)
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
	if !strings.Contains(dto.ExecutionBlockedReason, "未启用") {
		t.Fatal("created response concealed disabled gate", w.Body)
	}
	task, ok := m.Task(dto.ID)
	if !ok {
		t.Fatal("saved task missing")
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	goals, err := task.Store.HasOpenGoal()
	if err != nil || !goals {
		t.Fatal("original goal lost", goals, err)
	}
	if _, err = s.applyTaskControl(task, "pause"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.applyTaskControl(task, "resume"); err == nil || !strings.Contains(err.Error(), "候选验收") {
		t.Fatal("resume did not explain block", err)
	}
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil || !stored.Paused {
		t.Fatal("blocked resume mutated persisted pause", stored, err)
	}
	s.engine.lifecycleReady = func() bool { return true }
	if reason := s.taskExecutionBlockReason(); reason != "" {
		t.Fatal("stale block after enabling", reason)
	}
}
