package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

type GoalEvaluation struct {
	JobID         int64  `json:"job_id"`
	GoalID        int64  `json:"goal_id"`
	State         string `json:"state"`
	InputRevision int64  `json:"input_revision"`
}

// Kept for source compatibility. A caller-supplied integer is not authoritative:
// the input revision is allocated from the actual, frozen goal proof manifest.
func EnqueueGoalEvaluationTx(tx *sql.Tx, goalID, inputRevision int64) (int64, error) {
	var expID int64
	if err := tx.QueryRow(`SELECT exploration_id FROM exploration_nodes WHERE id=$1 AND kind='goal'`, goalID).Scan(&expID); err != nil {
		return 0, err
	}
	return enqueueGoalEvaluationTx(context.Background(), tx, expID, goalID, "")
}

func (s *ExplorationStore) EnqueueGoalEvaluation(goalID, inputRevision int64) (id int64, err error) {
	err = s.db.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
		var e error
		id, e = enqueueGoalEvaluationTx(context.Background(), tx, s.expID, goalID, "")
		return e
	})
	return
}

// SubmitGoalEvidence atomically validates/links a proof node and freezes the
// complete goal input. Both fact and finding proofs require goal verification.
func (s *ExplorationStore) SubmitGoalEvidence(ctx context.Context, goalID, evidenceID int64, reason string) (id int64, err error) {
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		// Validate ownership before writing an edge, even when there are no old proofs.
		if _, e := buildGoalBundleTx(ctx, tx, s.expID, goalID, reason); e != nil {
			return e
		}
		var kind, state string
		var sourceExp int64
		if e := tx.QueryRowContext(ctx, `SELECT kind,state,exploration_id FROM exploration_nodes WHERE id=$1 FOR SHARE`, evidenceID).Scan(&kind, &state, &sourceExp); e != nil {
			return e
		}
		if kind != KindFact && kind != KindFinding {
			return fmt.Errorf("证明材料必须是事实或有效漏洞")
		}
		if sourceExp != s.expID {
			var allowed bool
			if e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks owner JOIN task_relations r ON r.task_id=owner.id
    JOIN tasks source ON source.id=r.source_task_id WHERE owner.exploration_id=$1 AND source.exploration_id=$2
    AND owner.deleted_at IS NULL AND source.deleted_at IS NULL)`, s.expID, sourceExp).Scan(&allowed); e != nil {
				return e
			}
			if !allowed {
				return fmt.Errorf("证明材料不属于本任务或直接关联任务")
			}
		}
		if kind == KindFact && state != "confirmed" && state != "origin" {
			return fmt.Errorf("已撤销的事实不能证明目标")
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'proves',$3)
   ON CONFLICT DO NOTHING`, s.expID, evidenceID, goalID); e != nil {
			return e
		}
		var e error
		id, e = enqueueGoalEvaluationTx(ctx, tx, s.expID, goalID, reason)
		return e
	})
	return
}

func enqueueGoalEvaluationTx(ctx context.Context, tx *sql.Tx, expID, goalID int64, reason string) (int64, error) {
	b, err := buildGoalBundleTx(ctx, tx, expID, goalID, reason)
	if err != nil {
		return 0, err
	}
	for _, r := range b.Refs {
		if !r.Effective {
			return 0, fmt.Errorf("证明材料 %s 已失效，不能提交验收", r.RefID)
		}
	}
	var oldHash string
	if err = tx.QueryRowContext(ctx, `SELECT evaluation_input_hash FROM exploration_nodes WHERE id=$1`, goalID).Scan(&oldHash); err != nil {
		return 0, err
	}
	if oldHash != b.InputHash {
		err = tx.QueryRowContext(ctx, `UPDATE exploration_nodes SET evaluation_revision=evaluation_revision+1,evaluation_input_hash=$2,
   state=CASE WHEN state='met' THEN 'open' ELSE state END WHERE id=$1 RETURNING evaluation_revision`, goalID, b.InputHash).Scan(&b.InputRevision)
		if err != nil {
			return 0, err
		}
	}
	id, err := EnqueueVerificationJobTx(tx, SubjectGoal, goalID, b.InputRevision, "")
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE verification_jobs SET input_manifest=COALESCE(input_manifest,$2::jsonb),
  input_hash=CASE WHEN input_hash='' THEN $3 ELSE input_hash END,request_reason=$4 WHERE id=$1`, id, string(raw), b.InputHash, reason)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE verification_jobs SET state='superseded',lease_until=NULL,last_error='目标输入已更新'
  WHERE subject_kind='goal' AND subject_id=$1 AND id<>$2 AND state IN ('queued','leased')`, goalID, id)
	return id, err
}

func (s *ExplorationStore) GoalEvaluationState(goalID int64) (out GoalEvaluation, pending bool, err error) {
	err = s.db.QueryRow(`SELECT j.id,j.subject_id,j.input_revision FROM verification_jobs j
 JOIN exploration_nodes g ON g.id=j.subject_id AND g.kind='goal' AND g.exploration_id=$3
 WHERE j.subject_kind=$1 AND j.subject_id=$2 AND j.state IN ('queued','leased') ORDER BY j.id DESC LIMIT 1`, SubjectGoal, goalID, s.expID).
		Scan(&out.JobID, &out.GoalID, &out.InputRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	out.State = "submitted"
	return out, true, nil
}

func (s *ExplorationStore) CountPendingGoalEvaluations() (n int, err error) {
	err = s.db.QueryRow(`SELECT count(*) FROM verification_jobs j JOIN exploration_nodes g ON g.id=j.subject_id AND g.kind='goal'
 WHERE j.subject_kind=$1 AND j.state IN ('queued','leased') AND g.exploration_id=$2`, SubjectGoal, s.expID).Scan(&n)
	return
}

func (s *ExplorationStore) CommitGoalEvaluation(ctx context.Context, id, generation int64, verdict string, results ...VerdictResult) (string, error) {
	if verdict != "met" && verdict != "not_met" && verdict != "inconclusive" {
		return "", fmt.Errorf("非法目标判定: %s", verdict)
	}
	conflict := CommitOK
	if len(results) > 1 {
		return "", fmt.Errorf("只能提交一次目标判定")
	}
	if len(results) == 1 && results[0].policy() != VerdictPolicyVersion {
		return CommitPolicyMismatch, nil
	}
	err := s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		j, e := readVerificationInputTx(ctx, tx, id, false)
		if errors.Is(e, ErrVerificationJobNotFound) {
			conflict = CommitStale
			return nil
		}
		if e != nil {
			return e
		}
		if j.kind != SubjectGoal {
			conflict = CommitSubjectMismatch
			return nil
		}
		var owner int64
		e = tx.QueryRowContext(ctx, `SELECT exploration_id FROM exploration_nodes WHERE id=$1 AND kind='goal'`, j.subject).Scan(&owner)
		if errors.Is(e, sql.ErrNoRows) {
			conflict = CommitStale
			return nil
		}
		if e != nil {
			return e
		}
		if owner != s.expID {
			conflict = CommitSubjectMismatch
			return nil
		}
		b, e := buildGoalBundleTx(ctx, tx, s.expID, j.subject, j.reason)
		if errors.Is(e, ErrGoalNotFound) || errors.Is(e, ErrVerificationInputStale) {
			conflict = CommitStale
			return nil
		}
		if e != nil {
			return e
		}
		j, e = readVerificationInputTx(ctx, tx, id, true)
		if e != nil {
			return e
		}
		if j.generation != generation || j.state != JobLeased || !j.valid {
			conflict = CommitLeaseLost
			return nil
		}
		if j.policy != VerdictPolicyVersion {
			conflict = CommitPolicyMismatch
			return nil
		}
		if len(j.manifest) == 0 || j.hash == "" || j.hash != b.InputHash || j.revision != b.InputRevision {
			conflict = CommitStale
			return nil
		}
		if verdict == "met" && !goalProofActive(b) {
			return fmt.Errorf("目标缺少当前有效的证明材料")
		}
		if verdict == "met" {
			if e = RequireCTFAcceptedFlag(b); e != nil {
				return e
			}
		}
		if verdict == "met" {
			if len(results) == 1 && len(results[0].MissingEvidence) > 0 {
				return fmt.Errorf("目标仍有必要证据缺口")
			}
			var execution []byte
			if e = tx.QueryRowContext(ctx, `SELECT execution_input FROM verification_jobs WHERE id=$1`, id).Scan(&execution); e != nil {
				return e
			}
			material := b
			if len(execution) > 0 {
				var saved EvidenceBundle
				if e = json.Unmarshal(execution, &saved); e != nil {
					return e
				}
				material = &saved
			}
			if !VerificationMaterialComplete(material) {
				return fmt.Errorf("必要正文缺失或未校验，不能验收目标")
			}
		}
		result := map[string]any{"verdict": verdict, "input_hash": j.hash, "input_revision": j.revision, "policy_version": j.policy}
		if len(results) == 1 {
			result["evaluation"] = results[0]
		}
		res, e := tx.ExecContext(ctx, `UPDATE verification_jobs SET state='committed',committed_verdict=$2,result=$3::jsonb,lease_until=NULL,updated_at=now(),
   attempt_log=jsonb_set(attempt_log,ARRAY[($4::bigint)::text],COALESCE(attempt_log->(($4::bigint)::text),'{}'::jsonb)
      ||jsonb_build_object('outcome',$2::text,'result',$3::jsonb,'finished_at',clock_timestamp()),true)
   WHERE id=$1 AND lease_generation=$4 AND state='leased' AND lease_until>clock_timestamp()`, id, verdict, mustJSON(result), generation)
		if e != nil {
			return e
		}
		if n, e := res.RowsAffected(); e != nil {
			return e
		} else if n != 1 {
			conflict = CommitLeaseLost
			return nil
		}
		if verdict == "met" {
			_, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='met',blocked_reason=NULL WHERE id=$1`, j.subject)
		} else {
			_, e = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',blocked_reason=$2 WHERE id=$1`, j.subject, "验收结论: "+verdict)
		}
		return e
	})
	return conflict, err
}
