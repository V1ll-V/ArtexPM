package db

import (
	"encoding/json"
	"fmt"
	"testing"
)

func lifecycleConfigFixture(t *testing.T) (*DB, VerificationConfigPlan, int64) {
	t.Helper()
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.GetAgentByKey("worker")
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	if err = d.SeedPromptIfEmpty(a.ID, "known old default"); err != nil {
		t.Fatal(err)
	}
	old := ToolConfigContract{Description: "known old tool", Schema: json.RawMessage(`{"type":"object","properties":{"proof":{"type":"string"}}}`)}
	if err = d.SeedTool("lifecycle_fixture", old.Description, old.Schema, json.RawMessage(`["custom-reader"]`)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE tools SET enabled=false,deferred=true WHERE key='lifecycle_fixture'`); err != nil {
		t.Fatal(err)
	}
	plan := VerificationConfigPlan{Prompts: []PromptConfigChange{{Key: "worker", Template: "new candidate lifecycle", Legacy: []string{"known old default"}}}, Tools: []ToolConfigChange{{Key: "lifecycle_fixture", ToolConfigContract: ToolConfigContract{Description: "candidate only", Schema: json.RawMessage(`{"type":"object","properties":{"proof":{"type":"string"},"finding_id":{"type":"integer"}}}`)}, Legacy: []ToolConfigContract{old}}}}
	return d, plan, a.ID
}
func configItem(t *testing.T, r *VerificationConfigResult, kind, key string) ConfigMigrationItem {
	t.Helper()
	for _, i := range r.Items {
		if i.Kind == kind && i.Key == key {
			return i
		}
	}
	t.Fatalf("missing %s/%s", kind, key)
	return ConfigMigrationItem{}
}
func assertLifecycleVersion(t *testing.T, d *DB, id int64, want int) {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1`, id).Scan(&n); err != nil || n != want {
		t.Fatal(n, err)
	}
}

func TestConfigMigrationOwnedDefaultsVersionedAndIdempotent(t *testing.T) {
	d, plan, id := lifecycleConfigFixture(t)
	result, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || result.State != "ready" {
		t.Fatal(result, err)
	}
	if configItem(t, result, "prompt", "worker").State != "migrated" || configItem(t, result, "tool", "lifecycle_fixture").State != "migrated" {
		t.Fatal(result)
	}
	assertLifecycleVersion(t, d, id, 2)
	var old string
	if err = d.QueryRow(`SELECT template_text FROM agent_prompts WHERE agent_id=$1 AND version=1`, id).Scan(&old); err != nil || old != "known old default" {
		t.Fatal(old, err)
	}
	var enabled, deferred bool
	var agents []byte
	if err = d.QueryRow(`SELECT enabled,deferred,agents FROM tools WHERE key='lifecycle_fixture'`).Scan(&enabled, &deferred, &agents); err != nil {
		t.Fatal(err)
	}
	if enabled || !deferred || string(agents) != `["custom-reader"]` {
		t.Fatal("user switches/bindings changed", enabled, deferred, string(agents))
	}
	result, err = d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || configItem(t, result, "prompt", "worker").State != "unchanged" {
		t.Fatal(result, err)
	}
	assertLifecycleVersion(t, d, id, 2)
}

func TestConfigMigrationLegacyRequiresFullDefaultAndSystemHistory(t *testing.T) {
	d, plan, id := lifecycleConfigFixture(t)
	if _, err := d.Exec(`DELETE FROM managed_config`); err != nil {
		t.Fatal(err)
	}
	result, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || result.State != "ready" {
		t.Fatal(result, err)
	}
	assertLifecycleVersion(t, d, id, 2)
	// A user-saved old-looking prompt is still a custom decision, not a seed.
	if _, err = d.SavePrompt(id, "known old default", "user copy", "ui"); err != nil {
		t.Fatal(err)
	}
	result, err = d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || configItem(t, result, "prompt", "worker").State != "custom_preserved" {
		t.Fatal(result, err)
	}
	assertLifecycleVersion(t, d, id, 3)
}

func TestConfigMigrationPreservesCustomPromptAndTool(t *testing.T) {
	d, plan, id := lifecycleConfigFixture(t)
	if _, err := d.SavePrompt(id, "custom organization prompt", "custom", "ui"); err != nil {
		t.Fatal(err)
	}
	custom := `{"type":"object","properties":{"proof":{"type":"string","default":"custom-default"}},"additionalProperties":false}`
	if _, err := d.Exec(`UPDATE tools SET description='custom description',schema=$1 WHERE key='lifecycle_fixture'`, custom); err != nil {
		t.Fatal(err)
	}
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || r.State != "needs_review" {
		t.Fatal(r, err)
	}
	if configItem(t, r, "prompt", "worker").State != "custom_preserved" || configItem(t, r, "tool", "lifecycle_fixture").State != "needs_review" {
		t.Fatal(r)
	}
	current, err := d.CurrentPrompt(id)
	if err != nil || current != "custom organization prompt" {
		t.Fatal(current, err)
	}
	var desc string
	var raw []byte
	if err = d.QueryRow(`SELECT description,schema FROM tools WHERE key='lifecycle_fixture'`).Scan(&desc, &raw); err != nil {
		t.Fatal(err)
	}
	h1, _ := ConfigFingerprint(json.RawMessage(custom))
	h2, _ := ConfigFingerprint(json.RawMessage(raw))
	if desc != "custom description" || h1 != h2 {
		t.Fatal("custom tool overwritten")
	}
	assertLifecycleVersion(t, d, id, 2)
}

func TestConfigMigrationDoesNotInferTriggerOwnershipFromToolName(t *testing.T) {
	d, plan, _ := lifecycleConfigFixture(t)
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "reporter", Enabled: true, OnToolCall: true, ToolNames: []string{"report_finding"}, ToolCallMessage: "custom user message"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := reporterTriggerFingerprint(tr)
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || r.State != "needs_review" {
		t.Fatal(r, err)
	}
	if configItem(t, r, "trigger", fmt.Sprint(tr.ID)).State != "needs_review" {
		t.Fatal(r)
	}
	rows, err := d.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := reporterTriggerFingerprint(rows[0])
	if before != after {
		t.Fatal("custom trigger changed")
	}
	tr.Enabled = false
	if err = d.UpdateTrigger(tr); err != nil {
		t.Fatal(err)
	}
	r, err = d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || r.State != "ready" {
		t.Fatal(r, err)
	}
}

func TestConfigMigrationOwnedTriggerRetiresOnlyDiscoveryCondition(t *testing.T) {
	d, plan, _ := lifecycleConfigFixture(t)
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "reporter", Enabled: true, IntervalSec: 60, OnToolCall: true, ToolNames: []string{"report_finding"}, ToolCallMessage: "known managed message", IntervalMessage: "custom interval"})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := reporterTriggerFingerprint(tr)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = recordManagedConfigTx(tx, "trigger", fmt.Sprint(tr.ID), hash); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = d.TouchTriggerFire(tr.ID); err != nil {
		t.Fatal(err)
	}
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || configItem(t, r, "trigger", fmt.Sprint(tr.ID)).State != "migrated" {
		t.Fatal(r, err)
	}
	rows, err := d.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].OnToolCall || !rows[0].Enabled || rows[0].IntervalSec != 60 || rows[0].IntervalMessage != "custom interval" || rows[0].LastFire == nil {
		t.Fatal("independent trigger settings lost", rows[0])
	}
}

func TestConfigMigrationSQLFailureRollsBackAndRetries(t *testing.T) {
	for _, table := range []string{"tools", "verification_config_migrations"} {
		t.Run(table, func(t *testing.T) {
			d, plan, id := lifecycleConfigFixture(t)
			if _, err := d.Exec(`CREATE FUNCTION reject_config_migration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected migration failure'; END $$; CREATE TRIGGER reject_config_migration BEFORE INSERT OR UPDATE ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_config_migration()`); err != nil {
				t.Fatal(err)
			}
			if _, err := d.MigrateVerificationConfig(t.Context(), plan); err == nil {
				t.Fatal("injected failure ignored")
			}
			assertLifecycleVersion(t, d, id, 1)
			current, err := d.CurrentPrompt(id)
			if err != nil || current != "known old default" {
				t.Fatal(current, err)
			}
			stored, err := d.VerificationConfigMigration(t.Context())
			if err != nil || stored != nil {
				t.Fatal("failed migration marked complete", stored, err)
			}
			if _, err = d.Exec(`DROP TRIGGER reject_config_migration ON ` + table); err != nil {
				t.Fatal(err)
			}
			r, err := d.MigrateVerificationConfig(t.Context(), plan)
			if err != nil || r.State != "ready" {
				t.Fatal(r, err)
			}
			assertLifecycleVersion(t, d, id, 2)
		})
	}
}

func TestConfigMigrationPromptConcurrentEditWins(t *testing.T) {
	d, plan, id := lifecycleConfigFixture(t)
	blocker, err := d.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	var pid int
	if err = blocker.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.Exec(`SELECT id FROM agents WHERE id=$1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	type result struct {
		r *VerificationConfigResult
		e error
	}
	done := make(chan result, 1)
	go func() { r, e := d.MigrateVerificationConfig(t.Context(), plan); done <- result{r, e} }()
	waitClosingBlock(t, d, pid)
	var promptID int64
	if err = blocker.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,2,'concurrent custom','edit','ui') RETURNING id`, id).Scan(&promptID); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.Exec(`UPDATE agents SET current_prompt_id=$2 WHERE id=$1`, id, promptID); err != nil {
		t.Fatal(err)
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.e != nil || configItem(t, r.r, "prompt", "worker").State != "custom_preserved" {
		t.Fatal(r.r, r.e)
	}
	current, err := d.CurrentPrompt(id)
	if err != nil || current != "concurrent custom" {
		t.Fatal(current, err)
	}
}

func TestConfigMigrationSchemaUpgradeAndRepeatedApply(t *testing.T) {
	d, plan, id := lifecycleConfigFixture(t)
	if _, err := d.Exec(`DROP TABLE verification_config_migrations; DROP TABLE managed_config`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := d.Exec(schemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || r.State != "ready" {
		t.Fatal(r, err)
	}
	assertLifecycleVersion(t, d, id, 2)
}

func TestConfigMigrationStatusDetectsEditsAndNewTriggers(t *testing.T) {
	d, plan, id := lifecycleConfigFixture(t)
	if _, err := d.MigrateVerificationConfig(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SavePrompt(id, "changed after migration", "custom", "ui"); err != nil {
		t.Fatal(err)
	}
	r, err := d.VerificationConfigMigration(t.Context())
	if err != nil || r.State != "needs_review" || configItem(t, r, "prompt", "worker").State != "changed_since_migration" {
		t.Fatal(r, err)
	}
	if _, err = d.MigrateVerificationConfig(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "reporter", Enabled: true, OnToolCall: true, ToolNames: []string{"report_finding"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err = d.VerificationConfigMigration(t.Context())
	if err != nil || r.State != "needs_review" || configItem(t, r, "trigger", fmt.Sprint(tr.ID)).State != "changed_since_migration" {
		t.Fatal(r, err)
	}
}

func TestConfigSeedNeverReclaimsEditedTool(t *testing.T) {
	d, plan, _ := lifecycleConfigFixture(t)
	if _, err := d.Exec(`UPDATE tools SET description='custom current' WHERE key='lifecycle_fixture'`); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedTool("lifecycle_fixture", "custom current", plan.Tools[0].Legacy[0].Schema, nil); err != nil {
		t.Fatal(err)
	}
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || configItem(t, r, "tool", "lifecycle_fixture").State != "needs_review" {
		t.Fatal("repeat seed claimed user edit", r, err)
	}
}

func TestConfigMigrationPreservesOccupiedReporterKey(t *testing.T) {
	d, plan, _ := lifecycleConfigFixture(t)
	a, err := d.CreateAgent("reporter", "custom reporter", "user-created role")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SeedPromptIfEmpty(a.ID, "custom assistant starter"); err != nil {
		t.Fatal(err)
	}
	if err = d.SeedVerificationReporter(t.Context(), "new report contract", nil); err != nil {
		t.Fatal(err)
	}
	plan.Prompts = append(plan.Prompts, PromptConfigChange{Key: "reporter", Template: "new report contract", Legacy: []string{"old report default"}})
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || configItem(t, r, "prompt", "reporter").State != "custom_preserved" {
		t.Fatal("custom occupied key adopted as builtin", r, err)
	}
	body, err := d.CurrentPrompt(a.ID)
	if err != nil || body != "custom assistant starter" {
		t.Fatal(body, err)
	}
}

func TestConfigMigrationPreservesOtherToolTriggers(t *testing.T) {
	d, plan, _ := lifecycleConfigFixture(t)
	if _, err := d.CreateTrigger(&AgentTrigger{AgentKey: "reporter", Enabled: true, OnToolCall: true, ToolNames: []string{"custom_tool"}, ToolCallMessage: "independent user workflow"}); err != nil {
		t.Fatal(err)
	}
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "reporter", Enabled: true, OnToolCall: true, ToolNames: []string{"report_finding", "another_tool"}, ToolCallMessage: "managed combined workflow"})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := reporterTriggerFingerprint(tr)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = recordManagedConfigTx(tx, "trigger", fmt.Sprint(tr.ID), hash); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r, err := d.MigrateVerificationConfig(t.Context(), plan)
	if err != nil || r.State != "ready" {
		t.Fatal(r, err)
	}
	rows, err := d.ListTriggersFor("reporter")
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	if !rows[0].Enabled || !rows[0].OnToolCall || rows[0].ToolNames[0] != "custom_tool" || !rows[1].Enabled || !rows[1].OnToolCall || len(rows[1].ToolNames) != 1 || rows[1].ToolNames[0] != "another_tool" {
		t.Fatal("other trigger conditions were retired", rows)
	}
}

func TestConfigReporterSeedAtomicFailureAndDeletion(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`CREATE FUNCTION reject_reporter_marker() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.key='reporter_agent_seed_v1' THEN RAISE EXCEPTION 'injected marker failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_reporter_marker BEFORE INSERT ON settings FOR EACH ROW EXECUTE FUNCTION reject_reporter_marker()`); err != nil {
		t.Fatal(err)
	}
	if err = d.SeedVerificationReporter(t.Context(), "new reporter", nil); err == nil {
		t.Fatal("seed marker failure ignored")
	}
	var n int
	if err = d.QueryRow(`SELECT count(*) FROM agents WHERE key='reporter'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("partial reporter committed", n, err)
	}
	if _, err = d.Exec(`DROP TRIGGER reject_reporter_marker ON settings`); err != nil {
		t.Fatal(err)
	}
	if err = d.SeedVerificationReporter(t.Context(), "new reporter", nil); err != nil {
		t.Fatal(err)
	}
	a, err := d.GetAgentByKey("reporter")
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	if _, err = d.Exec(`DELETE FROM agents WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.SeedVerificationReporter(t.Context(), "new reporter", nil); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM agents WHERE key='reporter'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("deleted reporter resurrected", n, err)
	}
}
