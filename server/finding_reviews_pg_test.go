package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func newReviewServer(t *testing.T) (*Server, int64) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, m: &Manager{pg: pg, dir: td, tasks: map[string]*Task{}},
		chatBusy: map[string]bool{}, chatCancel: map[string]context.CancelCauseFunc{}}
	if err := s.seedFindingReviewer(); err != nil {
		t.Fatal(err)
	}
	fid, err := pg.AddFinding(0, 0, "triage-server", "复核测试", "high", "summary", "original proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldAugment, oldResolve, oldPrompt := agent.ToolAugment, agent.ToolResolve, agent.PromptOverride
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return s.findingReviewTools(), agent.DeferredInfo{}, func() {}
	}
	agent.ToolResolve = nil
	agent.PromptOverride = func(string) (string, bool) { return agent.ReviewerDefaultPrompt, true }
	t.Cleanup(func() {
		cancel()
		waitRetestIdle(t, s)
		agent.ToolAugment, agent.ToolResolve, agent.PromptOverride = oldAugment, oldResolve, oldPrompt
		_, _ = pg.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
		_, _ = pg.DeleteFinding(fid)
		pg.Close()
	})
	return s, fid
}

func TestReviewHTTPThroughConversationAndTools(t *testing.T) {
	s, fid := newReviewServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	setRetestProvider(s, retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return llm.Message{}, "", llm.Usage{}, ctx.Err()
			}
		}
		name, input := "get_finding_review_context", `{}`
		if n == 2 {
			serialized, _ := json.Marshal(req.Messages)
			if !bytes.Contains(serialized, []byte("original proof")) {
				t.Error("agent did not receive source evidence")
			}
			name = "record_finding_review_result"
			input = `{"verdict":"false_positive","confidence":"high","summary":"原证据把静态 200 回显误判为注入成功","evidence":"原证据中的响应是固定 HTML，无参数回显；请求实际未改变服务端状态。","recommended_status":"false_positive"}`
		}
		if n > 2 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("复核结论已保存")}}, "end_turn", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
			Type: llm.BlockToolUse, ID: strconv.Itoa(int(n)), Name: name, Input: json.RawMessage(input),
		}}}, "tool_use", llm.Usage{}, nil
	}})

	w := retestRequest(s.startFindingReview, "POST", fid, `{"feedback":"返回 200 但无回显，怀疑误报","scope":{"mode":"evidence_only","focus":["evidence"]}}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider not called")
	}
	dup := retestRequest(s.startFindingReview, "POST", fid, `{}`)
	if dup.Code != http.StatusOK || !strings.Contains(dup.Body.String(), `"created":false`) {
		t.Fatalf("duplicate %d %s", dup.Code, dup.Body)
	}
	close(release)
	waitRetestIdle(t, s)

	rows, err := s.m.pg.ListFindingRetests(fid)
	if err != nil {
		t.Fatal(err)
	}
	var run *db.FindingRetest
	for _, r := range rows {
		if r.Kind == db.FindingRunTriage {
			run = r
		}
	}
	if run == nil || run.Status != "completed" || run.Verdict != "false_positive" || run.Confidence != "high" {
		t.Fatalf("review run = %+v", run)
	}
	if run.Feedback != "返回 200 但无回显，怀疑误报" {
		t.Fatalf("feedback = %q", run.Feedback)
	}

	// The agent's verdict is a recommendation only: no status/decision change yet.
	f, err := s.m.pg.GetFinding(fid)
	if err != nil || f.Status != db.FindingPending || f.ReviewDecision != "" {
		t.Fatalf("triage must not auto-change the finding: %+v err=%v", f, err)
	}

	body := fmt.Sprintf(`{"decision":"false_positive","note":"人工确认：静态回显误判","apply_status":true,"run_id":%d}`, run.ID)
	w = retestRequest(s.decideFindingReview, "PATCH", fid, body)
	if w.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", w.Code, w.Body)
	}
	f, err = s.m.pg.GetFinding(fid)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != db.FindingFalsePositive || f.ReviewDecision != db.FindingReviewFalsePositive || f.ReviewNote == "" {
		t.Fatalf("decision not applied: %+v", f)
	}
	if f.ReviewRunID == nil || *f.ReviewRunID != run.ID {
		t.Fatalf("review run id = %v, want %d", f.ReviewRunID, run.ID)
	}

	md := report.FindingsMarkdown([]*db.DBFinding{f}, time.Now())
	if !strings.Contains(md, "人工复核结论") || !strings.Contains(md, "误报") {
		t.Fatalf("export missing review section:\n%s", md)
	}
	// The export query scans a wider column list than GetFinding; assert the new
	// review columns line up there too.
	exported, err := s.m.pg.ListFindingsForExport(db.FindingFilter{}, []int64{fid})
	if err != nil || len(exported) != 1 || exported[0].ReviewDecision != db.FindingReviewFalsePositive {
		t.Fatalf("export rows: %+v err=%v", exported, err)
	}
	if csv := string(report.FindingsCSV(exported)); !strings.Contains(csv, "误报") {
		t.Fatalf("csv missing review decision: %s", csv)
	}
}

func TestReviewDecisionValidation(t *testing.T) {
	s, fid := newReviewServer(t)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"bad decision", `{"decision":"fixed"}`, 400},
		{"apply status not supported", `{"decision":"exaggerated","apply_status":true}`, 400},
		{"bad severity", `{"decision":"exaggerated","severity":"urgent"}`, 400},
		{"unknown finding", `{"decision":"false_positive"}`, 404},
	}
	for _, tc := range cases {
		target := fid
		if tc.name == "unknown finding" {
			target = 999999999
		}
		w := retestRequest(s.decideFindingReview, "PATCH", target, tc.body)
		if w.Code != tc.code {
			t.Fatalf("%s: code=%d want=%d %s", tc.name, w.Code, tc.code, w.Body)
		}
	}

	// A human can annotate without running an agent at all, then clear it.
	w := retestRequest(s.decideFindingReview, "PATCH", fid, `{"decision":"false_positive","note":"手工标注"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("manual decision: %d %s", w.Code, w.Body)
	}
	f, _ := s.m.pg.GetFinding(fid)
	if f.ReviewDecision != db.FindingReviewFalsePositive || f.ReviewNote != "手工标注" {
		t.Fatalf("manual decision not saved: %+v", f)
	}
	if f.Status != db.FindingPending {
		t.Fatalf("manual decision must not change status without apply_status: %s", f.Status)
	}
	w = retestRequest(s.decideFindingReview, "PATCH", fid, `{"decision":"","note":"ignored"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", w.Code, w.Body)
	}
	f, _ = s.m.pg.GetFinding(fid)
	if f.ReviewDecision != "" || f.ReviewNote != "" || f.ReviewedAt != nil {
		t.Fatalf("clear left stale fields: %+v", f)
	}
}

func TestReviewStartValidation(t *testing.T) {
	s, fid := newReviewServer(t)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"bad scope mode", `{"scope":{"mode":"auto"}}`, 400},
		{"feedback too long", `{"feedback":"` + strings.Repeat("文", 4001) + `"}`, 400},
		{"bad json", `{`, 400},
	}
	for _, tc := range cases {
		w := retestRequest(s.startFindingReview, "POST", fid, tc.body)
		if w.Code != tc.code {
			t.Fatalf("%s: code=%d want=%d %s", tc.name, w.Code, tc.code, w.Body)
		}
	}
	if w := retestRequest(s.startFindingReview, "POST", 999999999, `{}`); w.Code != http.StatusNotFound {
		t.Fatalf("unknown finding: %d %s", w.Code, w.Body)
	}
}
