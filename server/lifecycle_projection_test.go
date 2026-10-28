package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/report"
	actool "github.com/Autumn-27/norma/tool"
)

func TestLifecycleProjectionListDetailTaskAndExportUseAcceptedScope(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, store := acceptedHTTPReportFixture(t, d)
	if err := processReportJobWith(t.Context(), d, callbackReportWriter(func(_ context.Context, in *db.ReportExecutionInput) (string, error) { return "# limited report", nil }), job, "local", store.LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	f, err := d.GetFinding(rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	dto := findingFromDB(f, nil)
	if !dto.Effective || dto.DisplayClaim != "ACCEPTED_LIMITED_SCOPE" || dto.ReportStale {
		t.Fatalf("detail: %+v", dto)
	}
	page, _, err := d.ListFindingsPage(db.FindingFilter{TaskID: i64s(*f.TaskID)}, 1, 50)
	if err != nil || len(page) != 1 {
		t.Fatal(page, err)
	}
	if got := findingFromDB(page[0], nil); !got.Effective || got.DisplayClaim != dto.DisplayClaim || got.ReportStale {
		t.Fatal("list projection differs", got)
	}
	var expID int64
	if err = d.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, *f.TaskID).Scan(&expID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exploration(expID).RecordFinding(t.Context(), db.RecordFindingInput{TaskID: *f.TaskID, Summary: "UNACCEPTED_RCE", Evidence: "only a candidate"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{ctx: t.Context(), m: &Manager{pg: d, dir: t.TempDir(), tasks: map[string]*Task{i64s(*f.TaskID): {ID: i64s(*f.TaskID), Description: "fixture", Store: d.Exploration(expID)}}}}
	w := httptest.NewRecorder()
	s.getReport(w, httptest.NewRequest("GET", "/api/report?task="+i64s(*f.TaskID), nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "UNACCEPTED_RCE") || !strings.Contains(w.Body.String(), "ACCEPTED_LIMITED_SCOPE") {
		t.Fatal("task report promoted candidate", w.Code, w.Body)
	}
	meta, err := d.FindingMetaByNodeID(*f.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	var exp int64
	if err = d.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, *f.TaskID).Scan(&exp); err != nil {
		t.Fatal(err)
	}
	nodes, err := d.Exploration(exp).ListByKind(db.KindFinding, 100)
	if err != nil {
		t.Fatal(err)
	}
	items := findingDTOsForOwner(i64s(*f.TaskID), "fixture", nodes, meta, nil)
	found := false
	for _, item := range items {
		if item.FindingID == dto.FindingID {
			found = item.DisplayClaim == dto.DisplayClaim && item.Effective
		}
	}
	if !found {
		t.Fatal("task projection differs", items)
	}
	if _, _, _, err = d.SetFindingStatusWithNotify(t.Context(), f.ID, db.FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	if err = store.StageFindingsExport(t.Context(), []*db.DBFinding{f}, "", false); err != nil {
		t.Fatal(err)
	}
	if f.Status != db.FindingFalsePositive || f.Projection().Effective || !f.ReportIsStale() {
		t.Fatal("export kept stale source/decision from initial selection", f)
	}
	f, err = d.GetFinding(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	dto = findingFromDB(f, nil)
	if dto.Effective || !dto.ReportStale || dto.AcceptedClaim != "" {
		t.Fatal("human rejection retained effective report", dto)
	}
	md := report.SingleFindingMarkdown(f, time.Now())
	csv := string(report.FindingsCSV([]*db.DBFinding{f}))
	if !strings.Contains(md, "历史报告（已失效）") || !strings.Contains(csv, "refuted") {
		t.Fatal(md, csv)
	}
	raw, err := json.Marshal(dto)
	if err != nil || !strings.Contains(string(raw), `"report_stale":true`) {
		t.Fatal(string(raw), err)
	}
}

func TestLifecycleNeedsReviewFeedbackReachesPlanner(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, store := verificationHTTPFixture(t, d)
	v := &fakeVerifier{result: db.VerdictResult{Decision: db.VerdictNeedsReview, MissingEvidence: []string{"missing independent account baseline"}, UnsupportedClaims: []string{"full compromise"}}}
	if err := processVerificationJobWith(t.Context(), d, v, job, store.LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	var task, exp int64
	if err := d.QueryRow(`SELECT task_id,exploration_id FROM findings JOIN tasks ON tasks.id=findings.task_id WHERE findings.id=$1`, rec.FindingID).Scan(&task, &exp); err != nil {
		t.Fatal(err)
	}
	ts := agent.NewToolSet(d.Exploration(exp), "planner")
	ts.SetTaskID(task)
	for _, tool := range []actool.CoreTool{ts.ListFindingsTool(), ts.GraphOverviewTool(), ts.NodeDetailTool()} {
		input := json.RawMessage(`{}`)
		if tool.Name() == "node_detail" {
			input = json.RawMessage(fmt.Sprintf(`{"id":%d}`, rec.NodeID))
		}
		result, err := tool.Call(t.Context(), input, nil)
		if err != nil || result.IsError || !strings.Contains(result.Flatten(), "missing independent account baseline") || !strings.Contains(result.Flatten(), `"effective":false`) {
			t.Fatal("feedback absent", tool.Name(), result.Flatten(), err)
		}
	}
}
