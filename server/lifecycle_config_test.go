package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func lifecycleConfigServer(t *testing.T) (*Server, db.VerificationConfigPlan) {
	t.Helper()
	d := privateVerificationDB(t)
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: t.Context()}
	plan, err := s.verificationConfigPlan()
	if err != nil {
		t.Fatal(err)
	}
	seedPrompts(d)
	for _, change := range plan.Tools {
		if err = d.SeedTool(change.Key, change.Description, change.Schema, json.RawMessage(`["custom-reader"]`)); err != nil {
			t.Fatal(err)
		}
	}
	if err = d.SeedVerificationReporter(t.Context(), agent.ReporterDefaultPrompt, nil); err != nil {
		t.Fatal(err)
	}
	return s, plan
}

func TestLifecycleConfigMigratesActualLegacyDefaultsAndPreservesCustom(t *testing.T) {
	s, plan := lifecycleConfigServer(t)
	d := s.m.pg
	for _, change := range plan.Prompts {
		a, err := d.GetAgentByKey(change.Key)
		if err != nil || a == nil {
			t.Fatal(a, err)
		}
		if len(change.Legacy) != 1 {
			t.Fatal("missing immutable legacy prompt", change.Key)
		}
		if _, err = d.SavePrompt(a.ID, change.Legacy[0], "内置默认", "system"); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range plan.Tools {
		if len(change.Legacy) != 1 {
			t.Fatal("missing immutable legacy tool", change.Key)
		}
		old := change.Legacy[0]
		if err := d.UpdateTool(change.Key, old.Description, old.Schema, json.RawMessage(`["custom-reader"]`), false); err != nil {
			t.Fatal(err)
		}
	}
	worker, err := d.GetAgentByKey("worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.SavePrompt(worker.ID, "custom organization policy {{.Now}}", "custom", "ui"); err != nil {
		t.Fatal(err)
	}
	tr, err := d.CreateTrigger(&db.AgentTrigger{AgentKey: "reporter", Enabled: true, OnToolCall: true, ToolNames: []string{"report_finding"}, ToolCallMessage: reporterToolCallMessage})
	if err != nil {
		t.Fatal(err)
	}
	// The old loose migration flag cannot bypass the new audited migration.
	if err = d.SetSetting("reporter_event_trigger_v1", "done"); err != nil {
		t.Fatal(err)
	}
	r, err := s.migrateVerificationConfig(t.Context())
	if err != nil || r.State != "needs_review" {
		t.Fatal(r, err)
	}
	for _, change := range plan.Tools {
		row, e := d.GetTool(change.Key)
		if e != nil || row.Description != change.Description || row.Enabled || len(row.Agents) != 1 || row.Agents[0] != "custom-reader" {
			t.Fatal("contract or user bindings lost", row, e)
		}
	}
	for _, change := range plan.Prompts {
		a, e := d.GetAgentByKey(change.Key)
		if e != nil {
			t.Fatal(e)
		}
		body, e := d.CurrentPrompt(a.ID)
		if e != nil {
			t.Fatal(e)
		}
		if change.Key == "worker" {
			if body != "custom organization policy {{.Now}}" {
				t.Fatal("custom prompt replaced")
			}
		} else if body != change.Template {
			t.Fatal("active prompt not migrated", change.Key)
		}
	}
	triggers, err := d.ListTriggersFor("reporter")
	if err != nil || len(triggers) != 1 || !triggers[0].Enabled || !triggers[0].OnToolCall {
		t.Fatal("unowned default-looking trigger retired", triggers, err)
	}
	tr.Enabled = false
	if err = d.UpdateTrigger(tr); err != nil {
		t.Fatal(err)
	}
	r, err = s.migrateVerificationConfig(t.Context())
	if err != nil || r.State != "ready" {
		t.Fatal(r, err)
	}
	prompt, err := s.reportSystemPrompt()
	if err != nil || strings.Contains(prompt, "刚刚被确认登记") || !strings.Contains(prompt, "accepted_claim") {
		t.Fatal("actual reporter still uses legacy contract", err)
	}
}

func TestLifecycleConfigAPIReportsDriftAndRetriesWithoutOverwriting(t *testing.T) {
	s, _ := lifecycleConfigServer(t)
	call := func(retry bool) map[string]any {
		t.Helper()
		method := "GET"
		if retry {
			method = "POST"
		}
		r := httptest.NewRequest(method, "/api/verification/config-migration", nil)
		w := httptest.NewRecorder()
		if retry {
			s.retryVerificationConfigMigration(w, r)
		} else {
			s.getVerificationConfigMigration(w, r)
		}
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["ready_for_production"] != false {
			t.Fatal("config completion enabled production")
		}
		return out
	}
	if call(false)["state"] != "not_run" {
		t.Fatal("unrun migration reported complete")
	}
	if call(true)["migration"].(map[string]any)["state"] != "ready" {
		t.Fatal("new default migration not ready")
	}
	if _, err := s.m.pg.Exec(`UPDATE tools SET description='user customization' WHERE key='report_finding'`); err != nil {
		t.Fatal(err)
	}
	if call(false)["migration"].(map[string]any)["state"] != "needs_review" {
		t.Fatal("cached ready hid drift")
	}
	if call(true)["migration"].(map[string]any)["state"] != "needs_review" {
		t.Fatal("custom contract silently accepted")
	}
	row, err := s.m.pg.GetTool("report_finding")
	if err != nil || row.Description != "user customization" {
		t.Fatal(row, err)
	}
}

func TestLifecycleConfigStartupPreservesPromptAndCriticalBindings(t *testing.T) {
	s, plan := lifecycleConfigServer(t)
	d := s.m.pg
	worker, err := d.GetAgentByKey("worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.SavePrompt(worker.ID, "startup custom policy", "custom", "ui"); err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Tools {
		if err = d.UpdateTool(change.Key, change.Description, change.Schema, json.RawMessage(`["custom-reader","planner"]`), false); err != nil {
			t.Fatal(err)
		}
	}
	var schema string
	if err = d.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := uri.Query()
	q.Set("search_path", schema)
	uri.RawQuery = q.Encode()
	t.Setenv("ARTEX_PG_DSN", uri.String())
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Initialization is bounded and atomic even if the execution context was
	// cancelled; background workers must still inherit that cancellation.
	cancel()
	server := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	server.archiveWG.Wait()
	<-server.side.done
	for _, change := range plan.Tools {
		row, e := d.GetTool(change.Key)
		if e != nil || row.Enabled || len(row.Agents) != 2 || row.Agents[0] != "custom-reader" || row.Agents[1] != "planner" {
			t.Fatal("startup changed critical binding", row, e)
		}
	}
	body, err := d.CurrentPrompt(worker.ID)
	if err != nil || body != "startup custom policy" {
		t.Fatal(body, err)
	}
	status, err := d.VerificationConfigMigration(t.Context())
	if err != nil || status == nil || status.State != "ready" {
		t.Fatal("startup did not run migration", status, err)
	}
	token, err := signJWT(server.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/api/verification/config-migration", bytes.NewReader(nil))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		want := 401
		if authenticated {
			want = 200
		}
		if w.Code != want {
			t.Fatal("migration route auth", w.Code, w.Body.String())
		}
	}
	for _, endpoint := range []struct{ method, path string }{{"GET", "/api/verification/readiness"}, {"POST", "/api/verification/lifecycle"}} {
		for _, authenticated := range []bool{false, true} {
			r := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(`{"enabled":true}`))
			if authenticated {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			want := 401
			if authenticated {
				want = 200
				if endpoint.method == "POST" {
					want = 409
				}
			}
			if w.Code != want {
				t.Fatal("readiness/switch auth or blocker", endpoint.path, w.Code, w.Body)
			}
		}
	}
	if d.GetBool(lifecycleEnabledSetting, false) {
		t.Fatal("blocked or unauthenticated request enabled execution")
	}
}
