package db

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
)

var ErrTaskModeInvalid = errors.New("任务模式或 CTF 题型无效")

func NormalizeTaskMode(mode, challenge string) (string, string, error) {
	mode = strings.TrimSpace(mode)
	challenge = strings.TrimSpace(challenge)
	if mode == "" {
		mode = "pentest"
	}
	if mode == "pentest" && challenge == "" {
		return mode, challenge, nil
	}
	if mode == "ctf" {
		if challenge == "" {
			challenge = "auto"
		}
		switch challenge {
		case "auto", "web", "pwn", "reverse", "crypto", "misc":
			return mode, challenge, nil
		}
	}
	return "", "", ErrTaskModeInvalid
}

func (s *ExplorationStore) TaskInputMetadata() (mode, challenge, batch string, err error) {
	err = s.db.QueryRow(`SELECT mode,challenge_type,attachment_batch_id FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.ID()).Scan(&mode, &challenge, &batch)
	return
}

// TaskChallengeType returns the normalized task mode and CTF challenge type for taskID.
func (d *DB) TaskChallengeType(ctx context.Context, taskID int64) (mode, challenge string, err error) {
	err = d.QueryRowContext(ctx, `SELECT mode,COALESCE(challenge_type,'') FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&mode, &challenge)
	return strings.ToLower(strings.TrimSpace(mode)), strings.ToLower(strings.TrimSpace(challenge)), err
}

func ValidAttachmentBatch(id string) bool {
	if id == "" {
		return true
	}
	u, err := uuid.Parse(id)
	return err == nil && u.String() == id
}
