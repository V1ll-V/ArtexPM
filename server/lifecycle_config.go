package server

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// Immutable complete baseline defaults, extracted from the recorded source
// revision. They are comparison data, never instructions to execute.
//
//go:embed lifecycle_legacy_defaults.json
var lifecycleLegacyDefaults []byte

func (s *Server) verificationConfigPlan() (db.VerificationConfigPlan, error) {
	var legacy struct {
		Prompts map[string]string `json:"prompts"`
		Tools   []struct {
			Key, Desc string
			Schema    json.RawMessage
		} `json:"tools"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(lifecycleLegacyDefaults, []byte{0xef, 0xbb, 0xbf}), &legacy); err != nil {
		return db.VerificationConfigPlan{}, err
	}
	plan := db.VerificationConfigPlan{}
	seeds := agent.BuiltinPromptSeeds()
	seeds["reporter"] = agent.ReporterDefaultPrompt
	keys := make([]string, 0, len(seeds))
	for key := range seeds {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		change := db.PromptConfigChange{Key: key, Template: seeds[key]}
		if text := legacy.Prompts[key]; text != "" {
			change.Legacy = []string{text}
		}
		plan.Prompts = append(plan.Prompts, change)
	}
	wanted := map[string]bool{"report_finding": true, "prove_goal": true, "goal_met": true}
	for _, seed := range agent.BuiltinToolSeeds() {
		if !wanted[seed.Key] {
			continue
		}
		raw, err := json.Marshal(seed.Schema)
		if err != nil {
			return plan, err
		}
		plan.Tools = append(plan.Tools, db.ToolConfigChange{Key: seed.Key, ToolConfigContract: db.ToolConfigContract{Description: seed.Desc, Schema: raw}})
	}
	report := s.toolUpdateFindingReport()
	raw, err := json.Marshal(report.InputSchema())
	if err != nil {
		return plan, err
	}
	plan.Tools = append(plan.Tools, db.ToolConfigChange{Key: report.Name(), ToolConfigContract: db.ToolConfigContract{Description: report.Description(), Schema: raw}})
	for i := range plan.Tools {
		for _, old := range legacy.Tools {
			if old.Key == plan.Tools[i].Key {
				plan.Tools[i].Legacy = append(plan.Tools[i].Legacy, db.ToolConfigContract{Description: old.Desc, Schema: old.Schema})
			}
		}
	}
	sort.Slice(plan.Tools, func(i, j int) bool { return plan.Tools[i].Key < plan.Tools[j].Key })
	return plan, nil
}
func (s *Server) migrateVerificationConfig(ctx context.Context) (*db.VerificationConfigResult, error) {
	plan, err := s.verificationConfigPlan()
	if err != nil {
		return nil, err
	}
	return s.m.pg.MigrateVerificationConfig(ctx, plan)
}
func (s *Server) getVerificationConfigMigration(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	result, err := pg.VerificationConfigMigration(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if result == nil {
		writeJSON(w, 200, map[string]any{"version": db.VerificationConfigVersion, "state": "not_run", "ready_for_production": false})
		return
	}
	writeJSON(w, 200, map[string]any{"migration": result, "ready_for_production": s.lifecycleStatus(r.Context()).ReadyForProduction, "readiness_url": "/api/verification/readiness"})
}
func (s *Server) retryVerificationConfigMigration(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	result, err := s.migrateVerificationConfig(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"migration": result, "ready_for_production": s.lifecycleStatus(r.Context()).ReadyForProduction, "readiness_url": "/api/verification/readiness"})
}
