package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
)

const lifecycleEnabledSetting = "verification_lifecycle_enabled"

type lifecycleCheck struct {
	Key    string `json:"key"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}
type lifecycleReadiness struct {
	Work               map[string]int               `json:"work,omitempty"`
	Scope              string                       `json:"scope"`
	Configuration      *db.VerificationConfigResult `json:"configuration,omitempty"`
	Enabled            bool                         `json:"enabled"`
	ReadyForEnable     bool                         `json:"ready_for_enable"`
	ReadyForProduction bool                         `json:"ready_for_production"`
	Checks             []lifecycleCheck             `json:"checks"`
	Version            string                       `json:"version"`
}

// Dynamic checks fail closed on errors and configuration drift. The switch
// controls V0 and both V1 consumers together; report/verdict guards always apply.
func (s *Server) lifecycleRunnable() bool {
	if s == nil || s.m == nil || s.m.pg == nil {
		return false
	}
	v, _, err := s.m.pg.GetSetting(lifecycleEnabledSetting)
	if err != nil || v != "true" || s.currentVerifier() == nil || s.currentReportWriter() == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m, err := s.m.pg.VerificationConfigMigration(ctx)
	if err != nil || m == nil || m.State != "ready" || s.ctx == nil || s.ctx.Err() != nil {
		return false
	}
	legacy, _, err := s.m.pg.GetSetting("findings_verdict_legacy_v1")
	return err == nil && legacy == "done" && s.lifecycleSchemaReady(ctx) && s.lifecycleToolsReady(ctx) && s.evidenceStorageReady(false)
}

func (s *Server) lifecycleToolsReady(ctx context.Context) bool {
	var count int
	err := s.m.pg.QueryRowContext(ctx, `SELECT count(*) FROM tools WHERE key IN ('report_finding','prove_goal') AND enabled AND system AND kind='builtin'`).Scan(&count)
	return err == nil && count == 2
}

func (s *Server) evidenceStorageReady(force bool) bool {
	s.cfgMu.Lock()
	checked, healthy := s.storageHealthAt, s.storageHealthy
	s.cfgMu.Unlock()
	if !force && !checked.IsZero() && time.Since(checked) < 5*time.Second {
		return healthy
	}
	healthy = s.evidenceStore().CheckStorage() == nil
	s.cfgMu.Lock()
	s.storageHealthAt, s.storageHealthy = time.Now(), healthy
	s.cfgMu.Unlock()
	return healthy
}

func (s *Server) lifecycleSchemaReady(ctx context.Context) bool {
	// Parse required columns as well as checking tables. A half-applied upgrade
	// must not become runnable through a previously saved enable setting.
	rows, err := s.m.pg.QueryContext(ctx, `SELECT f.proposed_claim,f.accepted_detail,f.input_revision,f.human_revision,f.report_run_id,
 t.run_epoch,t.closing_run_epoch,t.closing_reason,j.lease_generation,j.input_manifest,
 e.source_event_id,e.report_snapshot,r.execution_input,h.decision,c.evidence_refs,v.processed_at
 FROM findings f,tasks t,verification_jobs j,event_jobs e,report_runs r,finding_human_decisions h,finding_claims c,verdict_events v WHERE false`)
	if err != nil {
		return false
	}
	return rows.Close() == nil
}

func (s *Server) lifecycleStatus(ctx context.Context) lifecycleReadiness {
	out := lifecycleReadiness{Scope: "runtime_prerequisites", Version: db.VerificationConfigVersion, Checks: []lifecycleCheck{}}
	add := func(key string, ready bool, reason string) {
		if ready {
			reason = ""
		}
		out.Checks = append(out.Checks, lifecycleCheck{key, ready, reason})
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		add("database", false, "数据库未就绪")
		return out
	}
	pg := s.m.pg
	v, _, err := pg.GetSetting(lifecycleEnabledSetting)
	out.Enabled = err == nil && v == "true"
	add("schema", s.lifecycleSchemaReady(ctx), "生命周期表或版本列尚未就绪")
	legacy, _, err := pg.GetSetting("findings_verdict_legacy_v1")
	add("legacy_migration", err == nil && legacy == "done", "历史判定迁移未完成")
	m, err := pg.VerificationConfigMigration(ctx)
	out.Configuration = m
	add("configuration", err == nil && m != nil && m.State == "ready", "提示词、工具或旧触发器存在待复核项；检查配置迁移接口")
	add("critical_tools", s.lifecycleToolsReady(ctx), "候选登记或逐目标证明工具未启用；请核对工具设置")
	add("verifier", s.currentVerifier() != nil, "请配置可用的验收模型")
	add("reporter", s.currentReportWriter() != nil, "请配置可用的报告模型")
	add("evidence_storage", s.evidenceStorageReady(true), "证据目录无法完成写入、持久化与校验")
	add("runtime", s.ctx != nil && s.ctx.Err() == nil, "服务运行上下文不可用")
	out.ReadyForEnable = true
	for _, c := range out.Checks {
		out.ReadyForEnable = out.ReadyForEnable && c.Ready
	}
	out.ReadyForProduction = out.Enabled && out.ReadyForEnable
	if s.lifecycleSchemaReady(ctx) {
		var vq, vf, rq, rf int
		if err := pg.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM verification_jobs WHERE state='queued'),(SELECT count(*) FROM verification_jobs WHERE state='failed'),
 (SELECT count(*) FROM event_jobs WHERE job_kind='report_run' AND state='queued'),(SELECT count(*) FROM event_jobs WHERE job_kind='report_run' AND state='failed')`).Scan(&vq, &vf, &rq, &rf); err == nil {
			out.Work = map[string]int{"verification_queued": vq, "verification_failed": vf, "reports_queued": rq, "reports_failed": rf}
		}
	}
	return out
}

func (s *Server) getLifecycleReadiness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.lifecycleStatus(r.Context()))
}

func (s *Server) setLifecycleEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil || req.Enabled == nil {
		writeErr(w, 400, "必须提供 enabled 布尔值")
		return
	}
	if s.pg(w) == nil {
		return
	}
	if *req.Enabled {
		status := s.lifecycleStatus(r.Context())
		if !status.ReadyForEnable {
			writeJSON(w, http.StatusConflict, status)
			return
		}
	}
	if err := s.m.pg.SetSetting(lifecycleEnabledSetting, fmt.Sprint(*req.Enabled)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.lifecycleStatus(r.Context()))
}
