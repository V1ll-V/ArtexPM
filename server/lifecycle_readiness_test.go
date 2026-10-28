package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestLifecycleReadinessDefaultEnableDriftAndDisable(t *testing.T) {
	s, plan := lifecycleConfigServer(t)
	s.SetVerifier(&fakeVerifier{})
	s.SetReportWriter(callbackReportWriter(func(context.Context, *db.ReportExecutionInput) (string, error) { return "fixture", nil }))
	if _, err := s.m.pg.MigrateVerificationConfig(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	status := s.lifecycleStatus(t.Context())
	if status.Enabled || status.ReadyForProduction || !status.ReadyForEnable || s.lifecycleRunnable() {
		t.Fatalf("default/readiness: %+v", status)
	}
	call := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.setLifecycleEnabled(w, httptest.NewRequest("POST", "/api/verification/lifecycle", strings.NewReader(body)))
		return w
	}
	if w := call(`{"enabled":true}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !s.lifecycleRunnable() || !s.lifecycleStatus(t.Context()).ReadyForProduction {
		t.Fatal("ready switch did not enable both")
	}
	tool, err := s.m.pg.GetTool("report_finding")
	if err != nil {
		t.Fatal(err)
	}
	agents, _ := json.Marshal(tool.Agents)
	if err = s.m.pg.UpdateTool(tool.Key, "changed after enable", tool.Schema, agents, tool.Enabled); err != nil {
		t.Fatal(err)
	}
	if s.lifecycleRunnable() || s.lifecycleStatus(t.Context()).ReadyForProduction {
		t.Fatal("configuration drift kept execution enabled")
	}
	if w := call(`{"enabled":true}`); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(`{"enabled":false}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if s.lifecycleStatus(t.Context()).Enabled {
		t.Fatal("disable requires readiness or was not persisted")
	}
	if w := call(`{}`); w.Code != 400 {
		t.Fatal("missing boolean accepted", w.Code)
	}
}

func TestLifecycleReadinessMissingConsumersSchemaAndStorage(t *testing.T) {
	s, plan := lifecycleConfigServer(t)
	if _, err := s.m.pg.MigrateVerificationConfig(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	status := s.lifecycleStatus(t.Context())
	if status.ReadyForEnable {
		t.Fatal("missing consumers passed")
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	s.m.dir = path
	if _, err := s.m.pg.Exec(`ALTER TABLE report_runs RENAME TO report_runs_missing`); err != nil {
		t.Fatal(err)
	}
	status = s.lifecycleStatus(t.Context())
	seen := map[string]bool{}
	for _, c := range status.Checks {
		seen[c.Key] = c.Ready
	}
	if seen["schema"] || seen["evidence_storage"] || seen["verifier"] || seen["reporter"] || status.ReadyForProduction {
		t.Fatal(status)
	}
}

func TestLifecycleEngineAndSchedulerShareFailClosedSwitch(t *testing.T) {
	s, plan := lifecycleConfigServer(t)
	if _, err := s.m.pg.MigrateVerificationConfig(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	s.SetVerifier(&fakeVerifier{})
	s.SetReportWriter(callbackReportWriter(func(context.Context, *db.ReportExecutionInput) (string, error) { return "fixture", nil }))
	s.engine = NewEngine(s.m)
	s.engine.lifecycleReady = s.lifecycleRunnable
	s.engine.SetReadiness(func() bool { return true })
	pl, wk := &agent.Planner{}, &agent.Worker{}
	resolverCalls := 0
	s.engine.SetAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { resolverCalls++; return pl, wk })
	if p, w := s.engine.snapshotFor(&Task{ID: "fixture"}); p != nil || w != nil || resolverCalls != 0 {
		t.Fatal("execution bypassed disabled switch")
	}
	task, err := s.m.pg.CreateTask("disabled", "keep jobs queued", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.m.pg.Exploration(task.ExplorationID).RecordFinding(t.Context(), db.RecordFindingInput{TaskID: task.ID, Summary: "candidate", Evidence: "local", ExplorationID: task.ExplorationID})
	if err != nil {
		t.Fatal(err)
	}
	if s.engine.Ready() {
		t.Fatal("V0 ready with joint switch disabled")
	}
	sc := newScheduler(s)
	sc.fireVerdictWorkflow()
	var state string
	if err = s.m.pg.QueryRow(`SELECT state FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1`, f.FindingID).Scan(&state); err != nil || state != db.JobQueued {
		t.Fatal("disabled consumer claimed work", state, err)
	}
	v := &fakeVerifier{result: db.VerdictResult{Decision: db.VerdictSupported, AcceptedClaim: "only local fixture", AcceptedSeverity: db.SeverityLow}}
	s.SetVerifier(v)
	w := httptest.NewRecorder()
	s.setLifecycleEnabled(w, httptest.NewRequest("POST", "/api/verification/lifecycle", strings.NewReader(`{"enabled":true}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !s.engine.Ready() {
		t.Fatal("V0 not ready after joint enable")
	}
	if p, w := s.engine.snapshotFor(&Task{ID: "fixture"}); p != pl || w != wk {
		t.Fatal("ready engine cannot resolve its execution agents")
	}
	sc.fireVerdictWorkflow()
	sc.verifyWG.Wait()
	sc.fireVerdictWorkflow()
	sc.reportWG.Wait()
	row, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || row == nil || !row.Projection().Effective || row.Report != "fixture" || row.ReportIsStale() || v.calls != 1 {
		t.Fatal("enabled pipeline did not commit exact report", row, err, v.calls)
	}
}

func TestLifecycleRunnableRejectsHalfUpgradeAndDisabledCriticalTool(t *testing.T) {
	s, plan := lifecycleConfigServer(t)
	s.SetVerifier(&fakeVerifier{})
	s.SetReportWriter(callbackReportWriter(func(context.Context, *db.ReportExecutionInput) (string, error) { return "", nil }))
	if _, err := s.m.pg.MigrateVerificationConfig(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.SetSetting(lifecycleEnabledSetting, "true"); err != nil {
		t.Fatal(err)
	}
	if !s.lifecycleRunnable() {
		t.Fatal("fixture not ready")
	}
	if _, err := s.m.pg.Exec(`UPDATE tools SET enabled=false WHERE key='prove_goal'`); err != nil {
		t.Fatal(err)
	}
	if s.lifecycleRunnable() {
		t.Fatal("disabled critical tool bypassed readiness")
	}
	if _, err := s.m.pg.Exec(`UPDATE tools SET enabled=true WHERE key='prove_goal';ALTER TABLE report_runs RENAME TO report_runs_missing`); err != nil {
		t.Fatal(err)
	}
	if s.lifecycleRunnable() {
		t.Fatal("half upgrade bypassed readiness")
	}
}
