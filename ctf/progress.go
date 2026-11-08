package ctf

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/db"
)

type Progress struct {
	Phase          string            `json:"phase"`
	TaskStatus     string            `json:"task_status"`
	Paused         bool              `json:"paused"`
	InputHash      string            `json:"input_hash"`
	ExecutionCount int               `json:"execution_count"`
	PendingCount   int               `json:"pending_count"`
	AcceptedCount  int               `json:"accepted_count"`
	Candidates     []db.CTFCandidate `json:"candidates,omitempty"`
}

// Current input and operator decisions are authoritative; a candidate or a
// terminal task alone must never be presented as a verified solution.
func (s *Service) Progress(ctx context.Context, task int64) (Progress, error) {
	p := Progress{Candidates: []db.CTFCandidate{}}
	if err := s.Sync(ctx, task); err != nil {
		return p, err
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT status,paused,ctf_input_hash,
 (SELECT count(*) FROM ctf_executions WHERE task_id=tasks.id),
 (SELECT count(*) FROM ctf_candidates WHERE task_id=tasks.id AND input_hash=tasks.ctf_input_hash AND state='candidate'),
 (SELECT count(*) FROM ctf_candidates WHERE task_id=tasks.id AND input_hash=tasks.ctf_input_hash AND state='accepted')
 FROM tasks WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`, task).Scan(&p.TaskStatus, &p.Paused, &p.InputHash, &p.ExecutionCount, &p.PendingCount, &p.AcceptedCount); err != nil {
		return p, fmt.Errorf("读取 CTF 解题状态：%w", err)
	}
	var err error
	p.Candidates, err = s.DB.CTFCandidates(ctx, task)
	if err != nil {
		return p, err
	}
	switch {
	case p.PendingCount > 0:
		p.Phase = "awaiting_confirmation"
	case p.AcceptedCount > 0:
		p.Phase = "confirmed"
	case p.TaskStatus == "done" || p.TaskStatus == "failed" || p.TaskStatus == "timeout":
		p.Phase = "stopped"
	case p.Paused:
		p.Phase = "paused"
	case p.ExecutionCount > 0:
		p.Phase = "solving"
	default:
		p.Phase = "not_started"
	}
	return p, nil
}
