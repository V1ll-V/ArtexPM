package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

func completeCTFSubmissionTx(ctx context.Context, tx *sql.Tx, c CTFCandidate) error {
	var mode, hash, status string
	var expID int64
	if err := tx.QueryRowContext(ctx, `SELECT mode,ctf_input_hash,status,exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, c.TaskID).Scan(&mode, &hash, &status, &expID); err != nil {
		return err
	}
	if mode != "ctf" || hash == "" || hash != c.InputHash || c.State != "accepted" {
		return errors.New("完成 CTF 任务需要当前输入版本的已确认 Flag")
	}
	if status == "done" {
		return nil
	}
	var unfinished json.RawMessage
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'state',state) ORDER BY id),'[]'::jsonb) FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state NOT IN ('met','abandoned')`, expID).Scan(&unfinished); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"summary": "用户确认 Flag 并结束 CTF 任务", "subtype": "ctf_completion", "candidate_id": c.ID, "execution_id": c.ExecutionID, "input_hash": c.InputHash, "verification": "operator_completed", "unfinished_goals": unfinished})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) VALUES($1,'fact',$2,'confirmed','human')`, expID, payload); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='abandoned',blocked_reason='用户以已确认 Flag 完成 CTF 任务，剩余目标未继续执行' WHERE exploration_id=$1 AND kind='goal' AND state NOT IN ('met','abandoned')`, expID); err != nil {
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
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',blocked_reason='CTF 答案确认已撤销，请重新验证'
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
