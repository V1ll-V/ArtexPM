package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type taskInputProbeProvider struct {
	captureUsageProvider
	requests []llm.CompletionRequest
}

func (p *taskInputProbeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.requests = append(p.requests, req)
	return p.captureUsageProvider.Stream(ctx, req)
}

func TestWorkerTaskInputsReachModelAndRemainPinnedOnResume(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTaskWithOptions("source analysis", "explain checker", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	root := t.TempDir()
	store := artifacts.Store{Root: root}
	a, err := store.Add("task", fmt.Sprint(task.ID), "checker.c", "source", strings.NewReader("int main(){}"))
	if err != nil {
		t.Fatal(err)
	}
	p := &taskInputProbeProvider{captureUsageProvider: captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "Recorded fixture analysis."}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}}}
	w := NewWorker(p, "test-model", root, nil, 0, 2)
	ts := d.Exploration(task.ExplorationID)
	run := func(intentID int64) string {
		t.Helper()
		intent, err := ts.GetNode(intentID)
		if err != nil {
			t.Fatal(err)
		}
		p.requests = nil
		if _, _, err = w.Execute(t.Context(), "worker", task.ID, nil, ts, intent, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if len(p.requests) == 0 {
			t.Fatal("worker did not call model")
		}
		raw, err := json.Marshal(p.requests[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	first, err := ts.AddIntent(map[string]any{"summary": "inspect attached source"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	initial := run(first)
	for _, required := range []string{"CTF", a.ID, a.SHA256, "checker.c", "reverse"} {
		if !strings.Contains(initial, required) {
			t.Fatalf("model input missing %q", required)
		}
	}
	if _, err = store.Add("task", fmt.Sprint(task.ID), "NEW_ATTACHMENT_SENTINEL.c", "source", strings.NewReader("new input")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(run(first), "NEW_ATTACHMENT_SENTINEL") {
		t.Fatal("resumed intent silently changed inputs")
	}
	second, err := ts.AddIntent(map[string]any{"summary": "inspect additional source"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(run(second), "NEW_ATTACHMENT_SENTINEL") {
		t.Fatal("new intent did not receive latest inputs")
	}
}
