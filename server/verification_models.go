package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/agent"
)

const verifierProfileSetting = "verification_model_profile_id"

type verificationModels struct {
	VerifierProfileID *int64 `json:"verifier_profile_id"`
	ReporterProfileID *int64 `json:"reporter_profile_id"`
	ReporterEnabled   bool   `json:"reporter_enabled"`
}

func (s *Server) verifierProfileID() (*int64, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil, nil
	}
	value, _, err := s.m.pg.GetSetting(verifierProfileSetting)
	if err != nil {
		return nil, err
	}
	if value == "" || value == "0" {
		return nil, nil
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return nil, fmt.Errorf("验收模型配置无效")
	}
	return &id, nil
}

func (s *Server) verificationModelBindings(ctx context.Context) (verificationModels, error) {
	result := verificationModels{ReporterEnabled: true}
	var err error
	result.VerifierProfileID, err = s.verifierProfileID()
	if err != nil {
		return result, err
	}
	row, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		return result, err
	}
	if row != nil {
		result.ReporterProfileID, result.ReporterEnabled = row.LLMProfileID, row.Enabled
	}
	return result, nil
}

// Store profile references only; API keys remain owned by the existing LLM
// configuration. Both role changes commit together and preserve Agent settings.
func (s *Server) setVerificationModels(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in struct {
		VerifierProfileID *int64 `json:"verifier_profile_id"`
		ReporterProfileID *int64 `json:"reporter_profile_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		writeErr(w, 400, "模型配置请求无效")
		return
	}
	for _, id := range []*int64{in.VerifierProfileID, in.ReporterProfileID} {
		if id != nil {
			if *id <= 0 {
				writeErr(w, 400, "模型 ID 无效")
				return
			}
			if _, ok := s.loadProfileConfig(*id); !ok {
				writeErr(w, 400, "所选模型不存在或未配置 API Key，请先前往模型配置保存")
				return
			}
		}
	}
	tx, err := pg.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 500, "无法保存模型分工")
		return
	}
	defer tx.Rollback()
	// Follow the existing Agent/profile lock order used by profile deletion.
	var reporterID int64
	if err = tx.QueryRowContext(r.Context(), `SELECT id FROM agents WHERE key='reporter' FOR UPDATE`).Scan(&reporterID); err != nil {
		writeErr(w, 409, "报告 Agent 不存在，请检查 Agent 配置")
		return
	}
	for _, id := range []*int64{in.VerifierProfileID, in.ReporterProfileID} {
		if id != nil {
			var lockedID int64
			if err = tx.QueryRowContext(r.Context(), `SELECT id FROM llm_profiles WHERE id=$1 FOR KEY SHARE`, *id).Scan(&lockedID); err != nil {
				writeErr(w, 409, "模型配置已变化，请刷新后重试")
				return
			}
		}
	}
	value := "0"
	if in.VerifierProfileID != nil {
		value = strconv.FormatInt(*in.VerifierProfileID, 10)
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES($1,$2)
 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()`, verifierProfileSetting, value); err == nil {
		_, err = tx.ExecContext(r.Context(), `UPDATE agents SET llm_profile_id=$1 WHERE id=$2`, in.ReporterProfileID, reporterID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeErr(w, 500, "保存模型分工失败")
		return
	}
	writeJSON(w, 200, s.lifecycleStatus(r.Context()))
}

// Goal evaluation follows the task's configured runtime unless a verifier was
// explicitly selected. Exhausted task chains must not fall through to global.
func (s *Server) verifierForTask(t *Task) agent.Verifier {
	s.cfgMu.Lock()
	injected := s.verifier
	s.cfgMu.Unlock()
	id, err := s.verifierProfileID()
	if injected != nil || id != nil || err != nil || t == nil {
		return s.currentVerifier()
	}
	if !s.taskRuntimeAvailable(t, "goals") {
		return nil
	}
	return &agent.LLMVerifier{Prov: &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "goals"}}
}
