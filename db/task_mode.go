package db

import (
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
		case "auto", "web", "pwn", "reverse":
			return mode, challenge, nil
		}
	}
	return "", "", ErrTaskModeInvalid
}

func (s *ExplorationStore) TaskInputMetadata() (mode, challenge, batch string, err error) {
	err = s.db.QueryRow(`SELECT mode,challenge_type,attachment_batch_id FROM tasks WHERE exploration_id=$1 AND deleted_at IS NULL`, s.ID()).Scan(&mode, &challenge, &batch)
	return
}

func ValidAttachmentBatch(id string) bool {
	if id == "" {
		return true
	}
	u, err := uuid.Parse(id)
	return err == nil && u.String() == id
}
