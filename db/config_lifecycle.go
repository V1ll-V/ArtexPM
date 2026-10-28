package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const VerificationConfigVersion = "verification-config-v1"
const verificationConfigLock int64 = 7337741060

type PromptConfigChange struct {
	Key, Template string
	Legacy        []string
}
type ToolConfigContract struct {
	Description string
	Schema      json.RawMessage
}
type ToolConfigChange struct {
	Key string
	ToolConfigContract
	Legacy []ToolConfigContract
}
type VerificationConfigPlan struct {
	Prompts []PromptConfigChange
	Tools   []ToolConfigChange
}
type ConfigMigrationItem struct {
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	State      string `json:"state"`
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
	Reason     string `json:"reason,omitempty"`
}
type VerificationConfigResult struct {
	Version string                `json:"version"`
	State   string                `json:"state"`
	Items   []ConfigMigrationItem `json:"items"`
}

// ConfigFingerprint normalizes JSON object keys/whitespace while retaining all
// semantic fields. Timestamps and runtime counters must be excluded by callers.
func ConfigFingerprint(value any) (string, error) { return canonicalReportHash(value) }

func managedConfigMatchesTx(tx *sql.Tx, kind, key, hash string) (bool, error) {
	var saved string
	err := tx.QueryRow(`SELECT fingerprint FROM managed_config WHERE kind=$1 AND resource_key=$2`, kind, key).Scan(&saved)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return saved == hash, err
}
func recordManagedConfigTx(tx *sql.Tx, kind, key, hash string) error {
	_, err := tx.Exec(`INSERT INTO managed_config(kind,resource_key,seed_key,fingerprint) VALUES($1,$2,$3,$4)
 ON CONFLICT(kind,resource_key) DO UPDATE SET seed_key=EXCLUDED.seed_key,fingerprint=EXCLUDED.fingerprint,updated_at=now()`, kind, key, "builtin."+kind+":"+key, hash)
	return err
}

// All configured changes, provenance and the completion record commit together.
// Unknown/custom content is preserved and exposed, never silently overwritten.
func (d *DB) MigrateVerificationConfig(ctx context.Context, plan VerificationConfigPlan) (out *VerificationConfigResult, err error) {
	if len(plan.Prompts) == 0 || len(plan.Tools) == 0 {
		return nil, errors.New("incomplete verification configuration plan")
	}
	for _, p := range plan.Prompts {
		if p.Key == "" || p.Template == "" {
			return nil, errors.New("empty prompt configuration")
		}
	}
	for _, tool := range plan.Tools {
		if tool.Key == "" || tool.Description == "" || !json.Valid(tool.Schema) {
			return nil, errors.New("invalid tool configuration")
		}
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, verificationConfigLock); err != nil {
		return nil, err
	}
	out = &VerificationConfigResult{Version: VerificationConfigVersion, State: "ready", Items: []ConfigMigrationItem{}}
	for _, change := range plan.Prompts {
		item, e := migratePromptConfigTx(tx, change)
		if e != nil {
			return nil, fmt.Errorf("prompt %s: %w", change.Key, e)
		}
		out.Items = append(out.Items, item)
	}
	for _, change := range plan.Tools {
		item, e := migrateToolConfigTx(tx, change)
		if e != nil {
			return nil, fmt.Errorf("tool %s: %w", change.Key, e)
		}
		out.Items = append(out.Items, item)
	}
	// Triggers have no historical ownership column. A matching tool name or
	// message is not proof; legacy unowned rows require explicit review.
	rows, e := tx.QueryContext(ctx, `SELECT `+triggerCols+` FROM agent_triggers WHERE agent_key='reporter' ORDER BY id FOR UPDATE`)
	if e != nil {
		return nil, e
	}
	var triggers []*AgentTrigger
	for rows.Next() {
		tr, e := scanTrigger(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		triggers = append(triggers, tr)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, tr := range triggers {
		item, e := migrateReporterTriggerTx(tx, tr)
		if e != nil {
			return nil, e
		}
		out.Items = append(out.Items, item)
	}
	for _, item := range out.Items {
		if item.State == "needs_review" || item.State == "missing" {
			out.State = "needs_review"
		}
	}
	raw, e := json.Marshal(out)
	if e != nil {
		return nil, e
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO verification_config_migrations(version,state,result) VALUES($1,$2,$3)
 ON CONFLICT(version) DO UPDATE SET state=EXCLUDED.state,result=EXCLUDED.result,updated_at=now()`, out.Version, out.State, string(raw)); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func migratePromptConfigTx(tx *sql.Tx, c PromptConfigChange) (item ConfigMigrationItem, err error) {
	item = ConfigMigrationItem{Kind: "prompt", Key: c.Key, State: "missing"}
	var id int64
	var pid sql.NullInt64
	var builtin bool
	err = tx.QueryRow(`SELECT id,current_prompt_id,builtin FROM agents WHERE key=$1 FOR UPDATE`, c.Key).Scan(&id, &pid, &builtin)
	if errors.Is(err, sql.ErrNoRows) {
		return item, nil
	}
	if err != nil {
		return item, err
	}
	var text, by, note string
	if pid.Valid {
		err = tx.QueryRow(`SELECT template_text,COALESCE(updated_by,''),COALESCE(note,'') FROM agent_prompts WHERE id=$1 AND agent_id=$2 FOR UPDATE`, pid.Int64, id).Scan(&text, &by, &note)
		if err != nil {
			return item, err
		}
	} else {
		item.Reason = "当前提示词未初始化"
		return item, nil
	}
	item.BeforeHash, err = ConfigFingerprint(text)
	if err != nil {
		return item, err
	}
	item.AfterHash = item.BeforeHash
	if text == c.Template {
		item.State = "unchanged"
		return item, nil
	}
	owned, e := managedConfigMatchesTx(tx, "prompt", strconv.FormatInt(id, 10), item.BeforeHash)
	if e != nil {
		return item, e
	}
	// Legacy built-in templates must match complete known text and system
	// provenance; a user-saved/custom template remains authoritative.
	if !owned && (builtin || c.Key == "reporter") && by == "system" && (note == "内置默认" || note == "恢复为内置默认") {
		for _, legacy := range c.Legacy {
			if text == legacy {
				owned = true
				break
			}
		}
	}
	if !owned {
		item.State = "custom_preserved"
		item.Reason = "保留自定义正文；运行时追加不可移除的验收合同"
		return item, nil
	}
	if c.Template == "" {
		return item, errors.New("empty target prompt")
	}
	var version int
	var newID int64
	if err = tx.QueryRow(`SELECT COALESCE(max(version),0)+1 FROM agent_prompts WHERE agent_id=$1`, id).Scan(&version); err != nil {
		return item, err
	}
	if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,$2,$3,$4,'system') RETURNING id`, id, version, c.Template, VerificationConfigVersion).Scan(&newID); err != nil {
		return item, err
	}
	if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$2 WHERE id=$1`, id, newID); err != nil {
		return item, err
	}
	item.AfterHash, err = ConfigFingerprint(c.Template)
	if err != nil {
		return item, err
	}
	err = recordManagedConfigTx(tx, "prompt", strconv.FormatInt(id, 10), item.AfterHash)
	item.State = "migrated"
	return item, err
}

func migrateToolConfigTx(tx *sql.Tx, c ToolConfigChange) (item ConfigMigrationItem, err error) {
	item = ConfigMigrationItem{Kind: "tool", Key: c.Key, State: "missing"}
	var desc, kind string
	var schema []byte
	var system bool
	err = tx.QueryRow(`SELECT description,schema,system,kind FROM tools WHERE key=$1 FOR UPDATE`, c.Key).Scan(&desc, &schema, &system, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return item, nil
	}
	if err != nil {
		return item, err
	}
	current := ToolConfigContract{Description: desc, Schema: schema}
	item.BeforeHash, err = ConfigFingerprint(current)
	if err != nil {
		return item, err
	}
	item.AfterHash = item.BeforeHash
	target, e := ConfigFingerprint(c.ToolConfigContract)
	if e != nil {
		return item, e
	}
	if system && kind == "builtin" && target == item.BeforeHash {
		item.State = "unchanged"
		return item, nil
	}
	owned, e := managedConfigMatchesTx(tx, "tool", c.Key, item.BeforeHash)
	if e != nil {
		return item, e
	}
	if !owned {
		for _, legacy := range c.Legacy {
			h, e := ConfigFingerprint(legacy)
			if e != nil {
				return item, e
			}
			if h == item.BeforeHash {
				owned = true
				break
			}
		}
	}
	if !system || kind != "builtin" || !owned {
		item.State = "needs_review"
		item.Reason = "自定义工具说明或 schema 保持原样；需要确认其符合当前候选/验收合同"
		return item, nil
	}
	if _, err = tx.Exec(`UPDATE tools SET description=$2,schema=$3 WHERE key=$1`, c.Key, c.Description, string(c.Schema)); err != nil {
		return item, err
	}
	item.AfterHash = target
	item.State = "migrated"
	err = recordManagedConfigTx(tx, "tool", c.Key, target)
	return item, err
}

func reporterTriggerFingerprint(tr *AgentTrigger) (string, error) {
	copy := *tr
	copy.LastFire = nil
	return ConfigFingerprint(copy)
}
func reporterDiscoveryTrigger(tr *AgentTrigger) bool {
	if !tr.Enabled {
		return false
	}
	if tr.OnFinding {
		return true
	}
	if tr.OnToolCall {
		for _, key := range tr.ToolNames {
			if key == "report_finding" {
				return true
			}
		}
	}
	return false
}
func migrateReporterTriggerTx(tx *sql.Tx, tr *AgentTrigger) (item ConfigMigrationItem, err error) {
	item = ConfigMigrationItem{Kind: "trigger", Key: strconv.FormatInt(tr.ID, 10), State: "unchanged"}
	item.BeforeHash, err = reporterTriggerFingerprint(tr)
	if err != nil {
		return item, err
	}
	item.AfterHash = item.BeforeHash
	if !reporterDiscoveryTrigger(tr) {
		return item, nil
	}
	owned, e := managedConfigMatchesTx(tx, "trigger", item.Key, item.BeforeHash)
	if e != nil {
		return item, e
	}
	if !owned {
		item.State = "needs_review"
		item.Reason = "缺少内置来源证明，保留触发器；旧入口不能保存正式报告，需人工确认保留或停用"
		return item, nil
	}
	// Retire only the old discovery trigger; preserve independent schedules.
	tr.OnFinding = false
	if tr.OnToolCall {
		var remaining []string
		for _, key := range tr.ToolNames {
			if key != "report_finding" {
				remaining = append(remaining, key)
			}
		}
		tr.ToolNames = remaining
		tr.OnToolCall = len(remaining) > 0
	}
	if tr.IntervalSec == 0 && !tr.OnToolCall && !tr.OnGoalMet && !tr.OnTaskTimeout && !tr.OnTaskCreate {
		tr.Enabled = false
	}
	if _, err = tx.Exec(`UPDATE agent_triggers SET enabled=$2,on_tool_call=$3,on_finding=false,tool_names=$4 WHERE id=$1`, tr.ID, tr.Enabled, tr.OnToolCall, marshalToolNames(tr.ToolNames)); err != nil {
		return item, err
	}
	item.AfterHash, err = reporterTriggerFingerprint(tr)
	if err != nil {
		return item, err
	}
	item.State = "migrated"
	return item, recordManagedConfigTx(tx, "trigger", item.Key, item.AfterHash)
}

func (d *DB) VerificationConfigMigration(ctx context.Context) (*VerificationConfigResult, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT result FROM verification_config_migrations WHERE version=$1`, VerificationConfigVersion).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out VerificationConfigResult
	err = json.Unmarshal(raw, &out)
	if err != nil {
		return nil, err
	}
	seenTriggers := map[string]bool{}
	for i := range out.Items {
		item := &out.Items[i]
		var hash string
		switch item.Kind {
		case "prompt":
			var body string
			err = tx.QueryRowContext(ctx, `SELECT p.template_text FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id AND p.agent_id=a.id WHERE a.key=$1`, item.Key).Scan(&body)
			if err == nil {
				hash, err = ConfigFingerprint(body)
			}
		case "tool":
			var c ToolConfigContract
			var system bool
			var kind string
			err = tx.QueryRowContext(ctx, `SELECT description,schema,system,kind FROM tools WHERE key=$1`, item.Key).Scan(&c.Description, &c.Schema, &system, &kind)
			if err == nil {
				hash, err = ConfigFingerprint(c)
			}
			if err == nil && (!system || kind != "builtin") {
				hash = ""
			}
		case "trigger":
			seenTriggers[item.Key] = true
			var tr *AgentTrigger
			tr, err = scanTrigger(tx.QueryRowContext(ctx, `SELECT `+triggerCols+` FROM agent_triggers WHERE id=$1 AND agent_key='reporter'`, item.Key))
			if err == nil {
				hash, err = reporterTriggerFingerprint(tr)
			}
		default:
			return nil, errors.New("unknown migration item")
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if errors.Is(err, sql.ErrNoRows) || hash != item.AfterHash {
			item.State = "changed_since_migration"
			item.Reason = "配置已在迁移后变化，请重试迁移检查"
			out.State = "needs_review"
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+triggerCols+` FROM agent_triggers WHERE agent_key='reporter' AND enabled AND (on_tool_call OR on_finding) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var tr *AgentTrigger
		if tr, err = scanTrigger(rows); err != nil {
			rows.Close()
			return nil, err
		}
		key := strconv.FormatInt(tr.ID, 10)
		if !seenTriggers[key] && reporterDiscoveryTrigger(tr) {
			out.State = "needs_review"
			out.Items = append(out.Items, ConfigMigrationItem{Kind: "trigger", Key: key, State: "changed_since_migration", Reason: "迁移后新增了未检查的 Reporter 触发器"})
		}
	}
	err = rows.Err()
	rows.Close()
	return &out, err
}

// SeedVerificationReporter is all-or-nothing and respects a previously occupied
// key or deliberate deletion. New installs never create discovery triggers.
func (d *DB) SeedVerificationReporter(ctx context.Context, prompt string, bindings []string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, verificationConfigLock); err != nil {
		return err
	}
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key='reporter_agent_seed_v1'`).Scan(&done)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if done == "true" {
		return nil
	}
	var id int64
	err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled,trigger_run_mode,trigger_merge_mode,trigger_max_parallel)
 VALUES('reporter','报告撰写','根据当前有效的验收范围与冻结证据生成报告。','assistant',false,true,'parallel','none',5)
 ON CONFLICT(key) DO NOTHING RETURNING id`).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if id > 0 {
		var pid int64
		if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,1,$2,'内置默认','system') RETURNING id`, id, prompt).Scan(&pid); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$2 WHERE id=$1`, id, pid); err != nil {
			return err
		}
		hash, e := ConfigFingerprint(prompt)
		if e != nil {
			return e
		}
		if err = recordManagedConfigTx(tx, "prompt", strconv.FormatInt(id, 10), hash); err != nil {
			return err
		}
		for _, key := range bindings {
			if _, err = tx.Exec(`UPDATE tools SET agents=agents||'"reporter"'::jsonb WHERE key=$1 AND system AND kind='builtin' AND NOT(agents ? 'reporter')`, key); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES('reporter_agent_seed_v1','true') ON CONFLICT(key) DO UPDATE SET value='true'`); err != nil {
		return err
	}
	return tx.Commit()
}
