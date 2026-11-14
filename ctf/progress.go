package ctf

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/db"
)

type Progress struct {
	Phase              string            `json:"phase"`
	VerifyMode         string            `json:"verify_mode,omitempty"`
	TaskStatus         string            `json:"task_status"`
	Paused             bool              `json:"paused"`
	InputHash          string            `json:"input_hash"`
	ExecutionCount     int               `json:"execution_count"`
	PendingCount       int               `json:"pending_count"`
	AcceptedCount      int               `json:"accepted_count"`
	AcceptedFlagCount  int               `json:"accepted_flag_count"`
	AcceptedProofCount int               `json:"accepted_proof_count"`
	GoalsTotal         int               `json:"goals_total"`
	GoalsMet           int               `json:"goals_met"`
	GoalsOpen          int               `json:"goals_open"`
	Candidates         []db.CTFCandidate `json:"candidates,omitempty"`
}

// Current input and operator decisions are authoritative; a candidate or a
// terminal task alone must never be presented as a verified solution.
func (s *Service) Progress(ctx context.Context, task int64) (Progress, error) {
	p := Progress{Candidates: []db.CTFCandidate{}}
	if err := s.Sync(ctx, task); err != nil {
		return p, err
	}
	var rawVerify, desc, goal string
	if err := s.DB.QueryRowContext(ctx, `SELECT status,paused,ctf_input_hash,COALESCE(ctf_verify_mode,''),COALESCE(description,''),COALESCE(goal,''),
 (SELECT count(*) FROM ctf_executions WHERE task_id=tasks.id),
 (SELECT count(*) FROM ctf_candidates WHERE task_id=tasks.id AND input_hash=tasks.ctf_input_hash AND state='candidate'),
 (SELECT count(*) FROM ctf_candidates WHERE task_id=tasks.id AND input_hash=tasks.ctf_input_hash AND state='accepted'),
 (SELECT count(*) FROM ctf_candidates WHERE task_id=tasks.id AND input_hash=tasks.ctf_input_hash AND state='accepted' AND kind<>'exploit_proof'),
 (SELECT count(*) FROM ctf_candidates WHERE task_id=tasks.id AND input_hash=tasks.ctf_input_hash AND state='accepted' AND kind='exploit_proof')
 FROM tasks WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`, task).Scan(&p.TaskStatus, &p.Paused, &p.InputHash, &rawVerify, &desc, &goal, &p.ExecutionCount, &p.PendingCount, &p.AcceptedCount, &p.AcceptedFlagCount, &p.AcceptedProofCount); err != nil {
		return p, fmt.Errorf("读取 CTF 解题状态：%w", err)
	}
	p.VerifyMode = db.EffectiveCTFVerifyMode(rawVerify, desc, goal)

	var goalsTotal, goalsMet, goalsOpen int
	_ = s.DB.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT count(*) FROM exploration_nodes WHERE exploration_id=tasks.exploration_id AND kind='goal' AND state<>'abandoned'), 0),
 COALESCE((SELECT count(*) FROM exploration_nodes WHERE exploration_id=tasks.exploration_id AND kind='goal' AND state='met'), 0),
 COALESCE((SELECT count(*) FROM exploration_nodes WHERE exploration_id=tasks.exploration_id AND kind='goal' AND state='open'), 0)
 FROM tasks WHERE id=$1`, task).Scan(&goalsTotal, &goalsMet, &goalsOpen)
	p.GoalsTotal = goalsTotal
	p.GoalsMet = goalsMet
	p.GoalsOpen = goalsOpen

	var err error
	p.Candidates, err = s.DB.CTFCandidates(ctx, task)
	if err != nil {
		return p, err
	}
	switch {
	case p.TaskStatus == "done" || p.TaskStatus == "failed" || p.TaskStatus == "timeout":
		p.Phase = "stopped"
	case p.PendingCount > 0:
		p.Phase = "awaiting_confirmation"
	case p.GoalsTotal > 0 && p.GoalsOpen == 0 && p.GoalsMet > 0:
		p.Phase = "confirmed"
	case p.GoalsTotal <= 1 && p.AcceptedCount > 0:
		p.Phase = "confirmed"
	case p.Paused:
		p.Phase = "paused"
	case p.ExecutionCount > 0 || p.AcceptedCount > 0:
		p.Phase = "solving"
	default:
		p.Phase = "not_started"
	}
	return p, nil
}
