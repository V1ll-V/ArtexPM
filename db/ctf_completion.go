package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// CompleteCTFSubmission is an explicit operator finish, independent of generic
// goal verification. It never claims unfinished goals were met.
func (d *DB) CompleteCTFSubmission(ctx context.Context, taskID, candidateID, revision int64) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		c, err := scanCTFCandidate(tx.QueryRowContext(ctx, `SELECT `+ctfCandidateCols+` FROM ctf_candidates WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, candidateID))
		if err != nil {
			return err
		}
		if c.Revision != revision {
			return errors.New("候选记录已变化，请刷新后重试")
		}
		return completeCTFSubmissionTx(ctx, tx, c)
	})
}

// CompleteCTFExploitProof lets an operator explicitly finish an exploit-proof or
// composite CTF task after confirming the target side-effect on the platform
// judge, even when no candidate row was registered beforehand.
func (d *DB) CompleteCTFExploitProof(ctx context.Context, taskID int64, executionID, proofSummary, notes string) (*CTFCandidate, error) {
	proofSummary = utf8Clean(strings.TrimSpace(proofSummary))
	notes = utf8Clean(strings.TrimSpace(notes))
	if len(proofSummary) > 4096 {
		return nil, errors.New("证明摘要过长")
	}
	if len(notes) > 8192 {
		return nil, errors.New("备注过长")
	}
	var out *CTFCandidate
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		var mode, hash, status, rawVerify, desc, goal string
		var expID int64
		if err := tx.QueryRowContext(ctx, `SELECT mode,ctf_input_hash,status,exploration_id,COALESCE(ctf_verify_mode,''),COALESCE(description,''),COALESCE(goal,'') FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&mode, &hash, &status, &expID, &rawVerify, &desc, &goal); err != nil {
			return err
		}
		if mode != "ctf" || hash == "" {
			return errors.New("完成 CTF 任务需要有效任务输入快照")
		}
		verifyMode := EffectiveCTFVerifyMode(rawVerify, desc, goal)
		if verifyMode != CTFVerifyExploitProof && verifyMode != CTFVerifyFlagAndExploit {
			return errors.New("当前任务验收方式为「提交 Flag」，请先切换验收方式或确认 Flag 候选")
		}
		if status == "done" {
			return nil
		}
		execID := strings.TrimSpace(executionID)
		var matchedExec string
		var execIntentID int64
		if execID != "" {
			err := tx.QueryRowContext(ctx, `SELECT id,intent_id FROM ctf_executions WHERE task_id=$1 AND id=$2 AND input_hash=$3`, taskID, execID, hash).Scan(&matchedExec, &execIntentID)
			if err != nil {
				return errors.New("指定的执行记录不存在或已过期")
			}
		} else {
			_ = tx.QueryRowContext(ctx, `SELECT id,intent_id FROM ctf_executions WHERE task_id=$1 AND input_hash=$2 ORDER BY started_at DESC,id DESC LIMIT 1`, taskID, hash).Scan(&matchedExec, &execIntentID)
		}
		if proofSummary == "" {
			proofSummary = "已在赛题平台完成漏洞利用验证"
		}
		if matchedExec != "" {
			c, err := scanCTFCandidate(tx.QueryRowContext(ctx, `INSERT INTO ctf_candidates(task_id,execution_id,input_hash,value,notes,kind,state)
 VALUES ($1,$2,$3,$4,$5,'exploit_proof','accepted')
 ON CONFLICT(task_id,execution_id,value) DO UPDATE SET kind='exploit_proof',state='accepted',notes=CASE WHEN excluded.notes<>'' THEN excluded.notes ELSE ctf_candidates.notes END,revision=ctf_candidates.revision+1,updated_at=now()
 RETURNING `+ctfCandidateCols, taskID, matchedExec, hash, proofSummary, notes))
			if err != nil {
				return err
			}
			out = &c
			factPayload, _ := json.Marshal(map[string]any{
				"summary":      "人工确认本题漏洞利用已在平台验证通过：" + c.Value,
				"detail":       notes,
				"subtype":      "ctf_answer",
				"kind":         CTFCandidateExploitProof,
				"candidate_id": c.ID,
				"execution_id": c.ExecutionID,
				"input_hash":   c.InputHash,
				"verification": "operator_confirmed",
			})
			var factID int64
			if err := tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) VALUES($1,'fact',$2::jsonb,'confirmed','human') RETURNING id`, expID, string(factPayload)).Scan(&factID); err == nil && factID > 0 {
				srcID := execIntentID
				if srcID <= 0 {
					_ = tx.QueryRowContext(ctx, `SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1`, expID).Scan(&srcID)
				}
				if srcID > 0 {
					_, _ = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES ($1,$2,$3,$4) ON CONFLICT (exploration_id,src_id,rel,dst_id) DO NOTHING`, expID, srcID, RelYields, factID)
				}
			}
			return completeCTFSubmissionTx(ctx, tx, c)
		}
		// Fallback when operator validated exploit manually before any container execution.
		var unfinished json.RawMessage
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'state',state) ORDER BY id),'[]'::jsonb) FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state NOT IN ('met','abandoned')`, expID).Scan(&unfinished); err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{
			"summary":          "用户确认漏洞利用已在平台验证通过并结束 CTF 任务：" + proofSummary,
			"detail":           notes,
			"subtype":          "ctf_completion",
			"kind":             CTFCandidateExploitProof,
			"candidate_id":     0,
			"execution_id":     "",
			"input_hash":       hash,
			"verification":     "operator_completed",
			"unfinished_goals": unfinished,
		})
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) VALUES($1,'fact',$2,'confirmed','human')`, expID, payload); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='abandoned',blocked_reason='用户已在赛题平台确认漏洞利用通过并完成任务' WHERE exploration_id=$1 AND kind='goal' AND state NOT IN ('met','abandoned')`, expID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='stopped' WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running','paused')`, expID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE verification_jobs SET state='superseded',lease_until=NULL,updated_at=now() WHERE subject_kind='goal' AND state IN ('queued','leased') AND subject_id IN (SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal')`, expID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE tasks SET status='done',completed_at=now(),paused=false,queued=false,queued_at=NULL,queue_mode='',run_epoch=run_epoch+1,closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis='' WHERE id=$1`, taskID)
		return err
	})
	return out, err
}

func completeCTFSubmissionTx(ctx context.Context, tx *sql.Tx, c CTFCandidate) error {
	var mode, hash, status string
	var expID int64
	if err := tx.QueryRowContext(ctx, `SELECT mode,ctf_input_hash,status,exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, c.TaskID).Scan(&mode, &hash, &status, &expID); err != nil {
		return err
	}
	if mode != "ctf" || hash == "" || hash != c.InputHash || c.State != "accepted" {
		return errors.New("完成 CTF 任务需要当前输入版本的已确认验收结果")
	}
	if status == "done" {
		return nil
	}
	var unfinished json.RawMessage
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'state',state) ORDER BY id),'[]'::jsonb) FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state NOT IN ('met','abandoned')`, expID).Scan(&unfinished); err != nil {
		return err
	}
	summary := "用户确认 Flag 并结束 CTF 任务"
	abandonReason := "用户以已确认 Flag 完成 CTF 任务，剩余目标未继续执行"
	if c.Kind == CTFCandidateExploitProof {
		summary = "用户确认漏洞利用通过并结束 CTF 任务"
		abandonReason = "用户以已确认漏洞利用证明完成 CTF 任务，剩余目标未继续执行"
	}
	payload, err := json.Marshal(map[string]any{"summary": summary, "subtype": "ctf_completion", "kind": c.Kind, "candidate_id": c.ID, "execution_id": c.ExecutionID, "input_hash": c.InputHash, "verification": "operator_completed", "unfinished_goals": unfinished})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) VALUES($1,'fact',$2,'confirmed','human')`, expID, payload); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='abandoned',blocked_reason=$2 WHERE exploration_id=$1 AND kind='goal' AND state NOT IN ('met','abandoned')`, expID, abandonReason); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='stopped' WHERE exploration_id=$1 AND kind='intent' AND state IN ('open','running','paused')`, expID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE verification_jobs SET state='superseded',lease_until=NULL,updated_at=now() WHERE subject_kind='goal' AND state IN ('queued','leased') AND subject_id IN (SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal')`, expID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tasks SET status='done',completed_at=now(),paused=false,queued=false,queued_at=NULL,queue_mode='',run_epoch=run_epoch+1,closing_reason='',closing_run_epoch=0,closing_since=NULL,closing_basis='' WHERE id=$1`, c.TaskID)
	return err
}

// Revocation invalidates an operator-completed result. Restore only the goals
// abandoned by that finish; pause so the user can choose how to continue.
func reopenRevokedCTFCompletionTx(ctx context.Context, tx *sql.Tx, taskID int64) error {
	var factID int64
	var payload json.RawMessage
	err := tx.QueryRowContext(ctx, `SELECT n.id,n.payload FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
 WHERE t.id=$1 AND t.mode='ctf' AND t.status='done' AND n.kind='fact' AND n.state='confirmed' AND n.origin='human' AND n.payload->>'subtype'='ctf_completion' AND n.payload->>'verification'='operator_completed'
 AND COALESCE(NULLIF(n.payload->>'candidate_id',''),'0')<>'0'
 AND NOT EXISTS(SELECT 1 FROM ctf_candidates c WHERE c.task_id=t.id AND c.id::text=n.payload->>'candidate_id' AND c.input_hash=t.ctf_input_hash AND c.state='accepted')
 ORDER BY n.id DESC LIMIT 1 FOR UPDATE OF n`, taskID).Scan(&factID, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		// Older CTF tasks may have finished through generic goal verification,
		// without an operator-completion fact. Do not leave that result terminal
		// after its accepted answer or input was revoked.
		_, err = tx.ExecContext(ctx, `UPDATE tasks t SET status='running',completed_at=NULL,paused=true,queued=false,queued_at=NULL,queue_mode='',run_epoch=run_epoch+1
 WHERE t.id=$1 AND t.mode='ctf' AND t.status='done' AND NOT EXISTS(SELECT 1 FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='fact' AND n.state='confirmed' AND n.origin='human' AND n.payload->>'subtype'='ctf_completion' AND n.payload->>'verification'='operator_completed')`, taskID)
		return err
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',blocked_reason=''
 WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$2) AND kind='goal' AND state='abandoned'
 AND id::text IN (SELECT value->>'id' FROM jsonb_array_elements($1::jsonb->'unfinished_goals'))`, payload, taskID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='dismissed' WHERE id=$1`, factID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tasks SET status='running',completed_at=NULL,paused=true,queued=false,queued_at=NULL,queue_mode='',run_epoch=run_epoch+1 WHERE id=$1 AND mode='ctf' AND status='done'`, taskID)
	return err
}
