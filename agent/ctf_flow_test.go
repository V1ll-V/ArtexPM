package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/ctf"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/google/uuid"
)

func ctfHandoffFixture(t *testing.T) (*db.DB, *db.Task, string, *db.CTFExecution) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	task, err := pg.CreateTaskWithOptions("local handoff fixture", "recover local flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.DeleteTask(task.ID) })
	root := t.TempDir()
	if err = ctf.New(root, pg).Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, task.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	path := filepath.ToSlash(filepath.Join("ctf", "executions", id, "stdout.log"))
	stderr := filepath.ToSlash(filepath.Join("ctf", "executions", id, "stderr.log"))
	data := []byte("flag{local_handoff_fixture}\n")
	for name, content := range map[string][]byte{path: data, stderr: {}} {
		full := filepath.Join(root, "tasks", fmt.Sprint(task.ID), name)
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(full, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := &db.CTFExecution{ID: id, TaskID: task.ID, InputHash: hash, Command: "local fixture only", StdoutPath: path, StderrPath: stderr, StdoutSHA: ctf.SHA(data), StderrSHA: ctf.SHA(nil), StartedAt: time.Now()}
	if err = pg.SaveCTFExecution(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	return pg, task, root, e
}

// The only provider call submits a candidate from saved local output. A second
// provider call would waste tokens; both stream modes must hand off without it.
func TestCTFWorkerHandsOffWithoutAnotherModelCallAndResumesAfterRejection(t *testing.T) {
	for _, nonStreaming := range []bool{false, true} {
		t.Run(fmt.Sprint(nonStreaming), func(t *testing.T) {
			pg, task, root, execution := ctfHandoffFixture(t)
			store := pg.Exploration(task.ExplorationID)
			intentID, err := store.AddIntent(map[string]any{"summary": "local flag fixture"}, 5, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			intent, _ := store.GetNode(intentID)
			calls := 0
			provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
				calls++
				if calls == 1 {
					input, _ := json.Marshal(map[string]any{"execution_id": execution.ID, "value": "flag{local_handoff_fixture}"})
					for _, event := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "submit-local", ToolName: "ctf_submit_flag"}, {Type: llm.SEToolInputJSON, Text: string(input)}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
						if !y(event, nil) {
							return
						}
					}
				} else {
					if y(llm.StreamEvent{Type: llm.SETextDelta, Text: "continue after rejection"}, nil) {
						y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
					}
				}
			}}
			worker := NewWorker(provider, "local", root, nil, 0, 6)
			worker.SetNonStreaming(func() bool { return nonStreaming })
			var records []db.Activity
			reason, _, err := worker.Execute(t.Context(), "work", task.ID, nil, store, intent, nil, func(a db.Activity) { records = append(records, a) }, nil, nil)
			if err != nil || reason != ReasonCTFSubmission || calls != 1 {
				t.Fatalf("reason=%s calls=%d err=%v", reason, calls, err)
			}
			var results, toolResults int
			for _, a := range records {
				if a.Kind == "result" && strings.Contains(a.Detail, "系统自动交接") {
					results++
				}
				if a.Kind == "tool_result" && a.Tool == "ctf_submit_flag" && !a.IsError {
					toolResults++
				}
			}
			if results != 1 || toolResults != 1 {
				t.Fatal("handoff or paired evidence missing", records)
			}
			planner := NewPlanner(provider, "local", root, nil, 0, 4)
			for i := 0; i < 3; i++ {
				met, _, err := planner.Plan(t.Context(), task.ID, nil, store, "recover flag", nil, nil)
				if err != nil || met || calls != 1 {
					t.Fatal("waiting planner called model", calls, err)
				}
			}
			if _, err = ctf.New(root, pg).Execute(t.Context(), task.ID, intentID, "must not reach runner", 1); err == nil || !strings.Contains(err.Error(), "等待用户") {
				t.Fatal("waiting execution reached runner", err)
			}
			candidate, err := pg.PendingCTFSubmission(t.Context(), task.ID)
			if err != nil || candidate == nil {
				t.Fatal(candidate, err)
			}
			if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, candidate.ID, candidate.Revision, "rejected", "local test feedback"); err != nil {
				t.Fatal(err)
			}
			reason, _, err = worker.Execute(t.Context(), "work", task.ID, nil, store, intent, nil, nil, nil, nil)
			if err != nil || reason != harness.ReasonCompleted || calls != 2 {
				t.Fatal("rejection did not release worker", reason, calls, err)
			}
		})
	}
}

func TestCTFHumanChatCanDiscussAnExistingCandidate(t *testing.T) {
	pg, task, root, execution := ctfHandoffFixture(t)
	if _, err := pg.AddCTFCandidate(t.Context(), task.ID, execution.ID, "flag{local_handoff_fixture}"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		calls++
		if y(llm.StreamEvent{Type: llm.SETextDelta, Text: "explanation from existing evidence"}, nil) {
			y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
		}
	}}
	main := NewMainAgent(provider, "local", root, nil, 0, 4)
	text, err := main.Chat(t.Context(), task.ID, 0, nil, pg.Exploration(task.ExplorationID), "recover flag", "explain the solution", nil, nil, nil, nil, nil)
	if err != nil || calls != 1 || !strings.Contains(text, "explanation") {
		t.Fatal(text, calls, err)
	}
}

func TestCTFHumanChatHandsOffNewFlagWithoutAnotherModelCall(t *testing.T) {
	pg, task, root, execution := ctfHandoffFixture(t)
	calls := 0
	provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		calls++
		input, _ := json.Marshal(map[string]any{"execution_id": execution.ID, "value": "flag{local_handoff_fixture}"})
		for _, event := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "submit-chat", ToolName: "ctf_submit_flag"}, {Type: llm.SEToolInputJSON, Text: string(input)}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
			if !y(event, nil) {
				return
			}
		}
	}}
	main := NewMainAgent(provider, "local", root, nil, 0, 4)
	text, err := main.Chat(t.Context(), task.ID, 0, nil, pg.Exploration(task.ExplorationID), "recover flag", "solve local fixture", nil, nil, nil, nil, nil)
	if err != nil || calls != 1 || !strings.Contains(text, "系统自动交接") || !strings.Contains(text, execution.ID) {
		t.Fatal("chat continued after discovering flag", text, calls, err)
	}
}

func TestCTFReportToolsStaySeparateFromGenericTasks(t *testing.T) {
	pg, task, root, _ := ctfHandoffFixture(t)
	base := NewToolSet(pg.Exploration(task.ExplorationID), "worker").WorkerTools()
	containsReport := func(tools []actool.CoreTool) bool {
		for _, tool := range tools {
			if tool.Name() == "report_finding" {
				return true
			}
		}
		return false
	}
	if !containsReport(base) {
		t.Fatal("generic report tool missing from fixture")
	}
	ctx, tools := ctfBase(t.Context(), root, pg.Exploration(task.ExplorationID), task.ID, 1, base)
	if !isCTFContext(ctx) || containsReport(tools) {
		t.Fatal("CTF attached generic vulnerability reporting")
	}
	if _, err := pg.Exec(`UPDATE tasks SET mode='pentest' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	ctx, tools = ctfBase(t.Context(), root, pg.Exploration(task.ExplorationID), task.ID, 1, base)
	if isCTFContext(ctx) || !containsReport(tools) {
		t.Fatal("generic report flow was changed")
	}
}

func TestCTFWorkerExploitProofHandsOffWithoutAnotherModelCallAndResumesAfterRejection(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	task, err := pg.CreateTaskWithOptions("persist exploit", "无需提交 flag，完成持久化漏洞利用并验证", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	if task.CTFVerifyMode != db.CTFVerifyExploitProof {
		t.Fatalf("expected auto verify mode exploit_proof, got %q", task.CTFVerifyMode)
	}
	root := t.TempDir()
	if err = ctf.New(root, pg).Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = pg.QueryRow(`SELECT ctf_input_hash FROM tasks WHERE id=$1`, task.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	execID := uuid.NewString()
	stdoutRel := filepath.ToSlash(filepath.Join("ctf", "executions", execID, "stdout.log"))
	stderrRel := filepath.ToSlash(filepath.Join("ctf", "executions", execID, "stderr.log"))
	stdoutData := []byte("HTTP 200 OK persisted=/data/pwned_proof.txt\n")
	for rel, content := range map[string][]byte{stdoutRel: stdoutData, stderrRel: {}} {
		full := filepath.Join(root, "tasks", fmt.Sprint(task.ID), rel)
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(full, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ex := &db.CTFExecution{ID: execID, TaskID: task.ID, InputHash: hash, Command: "curl verify", StdoutPath: stdoutRel, StderrPath: stderrRel, StdoutSHA: ctf.SHA(stdoutData), StderrSHA: ctf.SHA(nil), StartedAt: time.Now()}
	if err = pg.SaveCTFExecution(t.Context(), ex); err != nil {
		t.Fatal(err)
	}

	// Verify ctfBase exposes ctf_submit_exploit_proof and hides ctf_submit_flag.
	store := pg.Exploration(task.ExplorationID)
	_, mounted := ctfBase(t.Context(), root, store, task.ID, 1, nil)
	var hasProofTool, hasFlagTool bool
	for _, tl := range mounted {
		if tl.Name() == "ctf_submit_exploit_proof" {
			hasProofTool = true
		}
		if tl.Name() == "ctf_submit_flag" {
			hasFlagTool = true
		}
	}
	if !hasProofTool || hasFlagTool {
		t.Fatalf("unexpected tool mounting: hasProof=%v hasFlag=%v", hasProofTool, hasFlagTool)
	}

	intentID, err := store.AddIntent(map[string]any{"summary": "verify persistent exploit"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, _ := store.GetNode(intentID)
	calls := 0
	provider := captureUsageProvider{stream: func(_ context.Context, y func(llm.StreamEvent, error) bool) {
		calls++
		if calls == 1 {
			input, _ := json.Marshal(map[string]any{"execution_id": ex.ID, "proof_summary": "写入持久化文件成功", "target_effect": "GET 验证存在"})
			for _, event := range []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "submit-proof", ToolName: "ctf_submit_exploit_proof"}, {Type: llm.SEToolInputJSON, Text: string(input)}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}} {
				if !y(event, nil) {
					return
				}
			}
		} else {
			if y(llm.StreamEvent{Type: llm.SETextDelta, Text: "retry after rejection"}, nil) {
				y(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
			}
		}
	}}
	worker := NewWorker(provider, "local", root, nil, 0, 6)
	var records []db.Activity
	reason, _, err := worker.Execute(t.Context(), "work", task.ID, nil, store, intent, nil, func(a db.Activity) { records = append(records, a) }, nil, nil)
	if err != nil || reason != ReasonCTFSubmission || calls != 1 {
		t.Fatalf("reason=%s calls=%d err=%v", reason, calls, err)
	}
	planner := NewPlanner(provider, "local", root, nil, 0, 4)
	met, planReason, err := planner.Plan(t.Context(), task.ID, nil, store, "persist exploit", nil, nil)
	if err != nil || met || calls != 1 || !strings.Contains(planReason, "漏洞利用证明") {
		t.Fatalf("unexpected planner result: met=%v calls=%d reason=%q err=%v", met, calls, planReason, err)
	}
	if _, err = ctf.New(root, pg).Execute(t.Context(), task.ID, intentID, "blocked", 1); err == nil || !strings.Contains(err.Error(), "等待用户") {
		t.Fatalf("expected wait error, got %v", err)
	}
	cand, err := pg.PendingCTFSubmission(t.Context(), task.ID)
	if err != nil || cand == nil || cand.Kind != db.CTFCandidateExploitProof {
		t.Fatalf("expected pending exploit_proof candidate, got %+v %v", cand, err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, cand.ID, cand.Revision, "rejected", "platform verify failed"); err != nil {
		t.Fatal(err)
	}
	reason, _, err = worker.Execute(t.Context(), "work", task.ID, nil, store, intent, nil, nil, nil, nil)
	if err != nil || reason != harness.ReasonCompleted || calls != 2 {
		t.Fatalf("rejection did not release worker: reason=%s calls=%d err=%v", reason, calls, err)
	}
}
