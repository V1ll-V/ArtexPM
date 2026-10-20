package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

// findingReviewScope is the normalized condition block stored in
// finding_retests.scope for a triage review. It is deliberately small: the
// reviewer must be able to explain exactly what it was allowed to do.
type findingReviewScope struct {
	Mode         string   `json:"mode"`
	Focus        []string `json:"focus,omitempty"`
	AllowNetwork bool     `json:"allow_network"`
	MaxRequests  int      `json:"max_requests"`
	Forbidden    string   `json:"forbidden,omitempty"`
	Assets       []int64  `json:"assets,omitempty"`
}

var reviewFocusValues = map[string]bool{
	"evidence": true, "impact": true, "exploitability": true,
	"environment": true, "scope": true,
}

func normalizeReviewScope(raw json.RawMessage) (json.RawMessage, error) {
	scope := findingReviewScope{Mode: agent.ReviewModeEvidenceOnly, MaxRequests: 5}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &scope); err != nil {
			return nil, errors.New("scope 不是合法 JSON")
		}
	}
	switch scope.Mode {
	case "", agent.ReviewModeEvidenceOnly:
		scope.Mode = agent.ReviewModeEvidenceOnly
	case agent.ReviewModeMinimal:
		scope.Mode = agent.ReviewModeMinimal
	default:
		return nil, errors.New("scope.mode 只能是 evidence_only 或 minimal_verification")
	}
	if scope.Mode == agent.ReviewModeEvidenceOnly {
		// 只读复核不允许联网，避免前端勾了 minimal 又切回只读时残留许可。
		scope.AllowNetwork = false
	}
	if scope.MaxRequests <= 0 {
		scope.MaxRequests = 5
	}
	if scope.MaxRequests > 50 {
		scope.MaxRequests = 50
	}
	focus := make([]string, 0, len(scope.Focus))
	for _, f := range scope.Focus {
		f = strings.TrimSpace(f)
		if reviewFocusValues[f] {
			focus = append(focus, f)
		}
	}
	scope.Focus = focus
	scope.Forbidden = strings.TrimSpace(scope.Forbidden)
	if utf8.RuneCountInString(scope.Forbidden) > 2000 {
		return nil, errors.New("scope.forbidden 最多 2000 个字符")
	}
	if len(scope.Assets) > 100 {
		scope.Assets = scope.Assets[:100]
	}
	b, err := json.Marshal(scope)
	return json.RawMessage(b), err
}

func (s *Server) startFindingReview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var req struct {
		Feedback string          `json:"feedback"`
		Scope    json.RawMessage `json:"scope"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	req.Feedback = strings.TrimSpace(req.Feedback)
	if utf8.RuneCountInString(req.Feedback) > 4000 {
		writeErr(w, 400, "复核意见最多 4000 个字符")
		return
	}
	scope, err := normalizeReviewScope(req.Scope)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	a, err := pg.GetAgentByKey(db.FindingReviewAgentKey)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if a == nil || !a.Enabled {
		writeErr(w, 409, "漏洞复核 Agent 不存在或未启用，请在 Agent 管理中配置 reviewer")
		return
	}
	for _, key := range []string{"get_finding_review_context", "record_finding_review_result"} {
		t, err := pg.GetTool(key)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if t == nil || !t.Enabled || !slices.Contains(t.Agents, a.Key) {
			writeErr(w, 409, "请为复核 Agent 启用并绑定工具："+key)
			return
		}
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: a.Key}) == nil {
		writeErr(w, 503, s.chatUnavailableReason())
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, 503, "服务正在停止")
		return
	}
	run, conv, created, err := pg.CreateFindingReview(r.Context(), id, req.Feedback, scope)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "finding not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if created {
		busyKey := s.convBusyKey(conv.ID)
		s.chatMu.Lock()
		s.chatBusy[busyKey] = true
		s.chatMu.Unlock()
		s.runConversation(conv, run.InitialMessage(), busyKey)
	}
	code := http.StatusOK
	if created {
		code = http.StatusAccepted
	}
	writeJSON(w, code, map[string]any{"review": run, "created": created})
}

func (s *Server) listFindingReviews(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	items, err := pg.ListFindingRetests(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]*db.FindingRetest, 0, len(items))
	for _, item := range items {
		if item.Kind == db.FindingRunTriage {
			out = append(out, item)
		}
	}
	writeJSON(w, 200, map[string]any{
		"reviews": out,
		"decision": map[string]any{
			"review_decision": f.ReviewDecision,
			"review_note":     f.ReviewNote,
			"review_run_id":   f.ReviewRunID,
			"reviewed_at":     f.ReviewedAt,
		},
	})
}

// decideFindingReview records the HUMAN verdict. The agent run's verdict is left
// untouched on purpose; adopting it is just a UI convenience that pre-fills this
// call. apply_status is the only path that changes findings.status, and it goes
// through the notification-aware SetFindingStatusTx inside the DB layer.
func (s *Server) decideFindingReview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var req struct {
		Decision    string `json:"decision"`
		Note        string `json:"note"`
		ApplyStatus bool   `json:"apply_status"`
		Severity    string `json:"severity"`
		RunID       *int64 `json:"run_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	req.Decision = strings.TrimSpace(req.Decision)
	req.Note = strings.TrimSpace(req.Note)
	req.Severity = strings.TrimSpace(req.Severity)
	if !db.ValidFindingReviewDecision(req.Decision) {
		writeErr(w, 400, "bad decision: "+req.Decision)
		return
	}
	if req.Severity != "" && !db.ValidSeverity(req.Severity) {
		writeErr(w, 400, "bad severity: "+req.Severity)
		return
	}
	var applyStatus *string
	if req.ApplyStatus && req.Decision != "" {
		var next string
		switch req.Decision {
		case db.FindingReviewFalsePositive:
			next = db.FindingFalsePositive
		case db.FindingReviewConfirmed:
			next = db.FindingConfirmed
		default:
			writeErr(w, 400, "该复核结论不支持自动更新处置状态，请改为手动选择状态")
			return
		}
		applyStatus = &next
	}
	var severity *string
	if req.Severity != "" {
		severity = &req.Severity
	}
	found, err := pg.SetFindingReviewDecision(r.Context(), id, req.Decision, req.Note, req.RunID, applyStatus, severity)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !found {
		writeErr(w, 404, "finding not found")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	writeJSON(w, 200, findingFromDB(f, s.resolveAssetIDs(f.AssetIDs)))
}

// Both review tools derive the finding from server-owned conversation context.
// Tool arguments cannot redirect a result into a different finding or
// conversation.
func (s *Server) findingReviewTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("get_finding_review_context", "读取当前复核会话关联的漏洞原文、摘要、证据/PoC、详细报告、资产、已绑定流量、原执行过程、历史复核记录、人工审查意见与本次复核条件。无参数，只能读取本会话。",
			objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
				run, err := s.m.pg.FindingRetestForConversation(ctx, intercept.ConvIDFromContext(ctx))
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if run == nil || run.Kind != db.FindingRunTriage {
					return actool.Errorf("当前会话未关联复核记录，请从漏洞详情发起复核"), nil
				}
				f, err := s.m.pg.GetFinding(run.FindingID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if f == nil {
					return actool.Errorf("漏洞不存在或已删除"), nil
				}
				var constraints []db.Constraint
				if f.TaskID != nil {
					if task, ok := s.m.Task(strconv.FormatInt(*f.TaskID, 10)); ok {
						constraints, _ = task.Store.ListConstraints()
					}
				}
				var snap struct {
					Assets      json.RawMessage `json:"assets"`
					Constraints json.RawMessage `json:"constraints"`
				}
				_ = json.Unmarshal(run.Snapshot, &snap)
				traffic, err := s.m.pg.GetFindingTraffic(ctx, f.ID)
				if err != nil {
					traffic = nil
				}
				previous, _ := s.m.pg.ListFindingRetests(f.ID)
				return jsonResult(map[string]any{
					"run": map[string]any{
						"id": run.ID, "kind": run.Kind, "feedback": run.Feedback,
						"scope": run.Scope, "notes": run.Notes, "status": run.Status,
					},
					"finding":              f,
					"snapshot_assets":      snap.Assets,
					"snapshot_constraints": snap.Constraints,
					"current_constraints":  constraints,
					"traffic_evidence":     traffic,
					"worker_trace":         s.reviewWorkerTrace(f, 40),
					"previous_runs":        previous,
				})
			}),
		wrTool("record_finding_review_result", "为当前复核会话保存唯一结论；结论只是建议，系统不会自动修改漏洞状态/严重等级/报告。必须提供本次实际核对的内容与证据，无法确认时写明阻塞原因。",
			objSchema(map[string]any{
				"verdict": map[string]any{"type": "string", "enum": []string{"confirmed", "false_positive", "exaggerated", "inconclusive"}},
				"confidence": map[string]any{"type": "string", "enum": []string{"low", "medium", "high"},
					"description": "结论置信度（可选）"},
				"summary":  strParam("本次复核结论摘要"),
				"evidence": strParam("Markdown：原证据的哪一条 → 本次核对了什么 → 为什么成立/不成立/夸大"),
				"recommended_severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", ""},
					"description": "结论为 exaggerated 时的建议严重等级（可选）"},
				"recommended_status": map[string]any{"type": "string", "enum": []string{"confirmed", "false_positive", ""},
					"description": "建议的处置状态（可选，仅供人工参考）"},
			}, "verdict", "summary", "evidence"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					Verdict             string `json:"verdict"`
					Confidence          string `json:"confidence"`
					Summary             string `json:"summary"`
					Evidence            string `json:"evidence"`
					RecommendedSeverity string `json:"recommended_severity"`
					RecommendedStatus   string `json:"recommended_status"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if err := s.m.pg.RecordFindingReviewResult(ctx, intercept.ConvIDFromContext(ctx),
					a.Verdict, a.Confidence, a.Summary, a.Evidence, a.RecommendedSeverity, a.RecommendedStatus); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"saved": true, "verdict": a.Verdict})
			}),
	}
}

// reviewWorkerTrace returns the source intent's execution steps (the same data
// get_worker_trace exposes to workers), so the reviewer can check whether the
// original PoC's output actually supports the finding. Best effort: a missing
// task/node just omits the trace.
func (s *Server) reviewWorkerTrace(f *db.DBFinding, limit int) map[string]any {
	if f == nil || f.NodeID == nil || f.TaskID == nil {
		return nil
	}
	t := s.m.ResolveTask(strconv.FormatInt(*f.TaskID, 10))
	if t == nil {
		return nil
	}
	nodes, edges, err := t.Store.FindingLineage(*f.NodeID)
	if err != nil {
		return nil
	}
	intentID := int64(0)
	for _, e := range edges {
		if e.To == *f.NodeID && (e.Rel == db.RelProves || e.Rel == db.RelDerivedFrom || e.Rel == db.RelYields) {
			intentID = e.From
		}
	}
	if intentID == 0 {
		for _, n := range nodes {
			if n.Kind == db.KindIntent {
				intentID = n.ID
			}
		}
	}
	if intentID == 0 {
		return nil
	}
	acts, err := t.Store.ActivityTrace(intentID, limit)
	if err != nil {
		return nil
	}
	steps := make([]map[string]any, 0, len(acts))
	for _, a := range acts {
		steps = append(steps, map[string]any{
			"step_id": a.ID, "worker": a.Worker, "kind": a.Kind,
			"tool": a.Tool, "summary": preview(a.Summary, 300), "is_error": a.IsError,
		})
	}
	return map[string]any{"intent_id": intentID, "steps": steps}
}

// Seed the editable agent atomically, without an automatic discovery trigger.
// Once seeded, user edits/deletion survive restarts; a pre-existing key is kept.
func (s *Server) seedFindingReviewer() error {
	for _, t := range s.findingReviewTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings, _ := json.Marshal([]string{db.FindingReviewAgentKey})
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			return err
		}
	}
	const flag = "finding_reviewer_seed_v1"
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Lock this migration, including concurrent server initialization.
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741011)`); err != nil {
		return err
	}
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, flag).Scan(&done)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if done == "true" {
		return nil
	}
	var id int64
	err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled)
	VALUES ($1,'漏洞复核','从漏洞详情手动启动，判断漏洞是否误报/夸大并保存独立复核结论；只给建议，人工拍板。','assistant',false,true)
	ON CONFLICT (key) DO NOTHING RETURNING id`, db.FindingReviewAgentKey).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if id > 0 {
		var pid int64
		if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
		VALUES ($1,1,$2,'内置默认','system') RETURNING id`, id, agent.ReviewerDefaultPrompt).Scan(&pid); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, pid, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, flag); err != nil {
		return err
	}
	return tx.Commit()
}

// reviewModeFromScope defaults to the safest mode when the stored scope is
// missing or malformed.
func reviewModeFromScope(raw json.RawMessage) string {
	var s struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal(raw, &s)
	if s.Mode == agent.ReviewModeMinimal {
		return agent.ReviewModeMinimal
	}
	return agent.ReviewModeEvidenceOnly
}
