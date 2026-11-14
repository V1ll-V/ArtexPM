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

// TaskCTFVPN returns the persisted WireGuard config, hash, and filename for an alive task.
func (d *DB) TaskCTFVPN(ctx context.Context, taskID int64) (config, hash, filename string, err error) {
	err = d.QueryRowContext(ctx,
		`SELECT COALESCE(ctf_vpn_config,''), COALESCE(ctf_vpn_hash,''), COALESCE(ctf_vpn_filename,'') FROM tasks WHERE id=$1 AND deleted_at IS NULL`,
		taskID,
	).Scan(&config, &hash, &filename)
	return config, hash, filename, err
}

// SetTaskCTFVPN persists or clears a CTF task's WireGuard config metadata.
func (d *DB) SetTaskCTFVPN(ctx context.Context, taskID int64, config, hash, filename string) error {
	res, err := d.ExecContext(ctx,
		`UPDATE tasks SET ctf_vpn_config=$2, ctf_vpn_hash=$3, ctf_vpn_filename=$4 WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`,
		taskID, config, hash, filename,
	)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		return nil
	}
	var mode string
	if err := d.QueryRowContext(ctx, `SELECT mode FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&mode); err != nil {
		return ErrTaskNotFound
	}
	return ErrTaskModeInvalid
}
