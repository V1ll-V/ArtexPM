package db

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	CTFVerifyAuto           = "auto"
	CTFVerifyFlag           = "flag"
	CTFVerifyExploitProof   = "exploit_proof"
	CTFVerifyFlagAndExploit = "flag_and_exploit"
)

var (
	ErrTaskModeInvalid      = errors.New("任务模式或 CTF 题型无效")
	ErrCTFVerifyModeInvalid = errors.New("CTF 验收方式无效")

	ctfNegatedFlagRe        = regexp.MustCompile(`(?i)(?:无需|不需要|不用)\s*(?:提交)?\s*flag|无\s*flag(?:\s*可\s*提交)?|no\s+flag(?:\s+string)?(?:\s+to\s+submit)?`)
	ctfExploitProofSignalRe = regexp.MustCompile(`(?i)漏洞利用证明|验证漏洞利用|verify\s+exploit|trusted\s+judge|judge\s+sidecar|no\s+flag\s+(?:string\s+)?to\s+submit|(?:无需|不需要|不用)\s*(?:提交)?\s*flag`)
	ctfMultiStageExploitRe  = regexp.MustCompile(`(?i)先.{0,24}flag.{0,24}再.{0,24}(?:漏洞利用|提权|篡改|验证)|flag\s*(?:\+|和|与)\s*漏洞利用`)
	ctfPositiveFlagSignalRe = regexp.MustCompile(`(?i)flag\{|canonical\s+flag|\bdynamic\b|submit\s+(?:the\s+)?flag|提交\s*flag|获取\s*flag|找到\s*flag|读取\s*flag|recover\s+flag`)
)

// ResolveCTFVerifyMode infers the effective CTF verification mode when raw is
// empty or "auto". Explicit modes ("flag", "exploit_proof", "flag_and_exploit")
// are returned as-is.
func ResolveCTFVerifyMode(raw, description, goal string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case CTFVerifyFlag, CTFVerifyExploitProof, CTFVerifyFlagAndExploit:
		return raw
	}
	text := description + "\n" + goal
	if ctfMultiStageExploitRe.MatchString(text) {
		return CTFVerifyFlagAndExploit
	}
	if !ctfExploitProofSignalRe.MatchString(text) {
		return CTFVerifyFlag
	}
	stripped := ctfNegatedFlagRe.ReplaceAllString(text, " ")
	if ctfPositiveFlagSignalRe.MatchString(stripped) {
		return CTFVerifyFlagAndExploit
	}
	return CTFVerifyExploitProof
}

// NormalizeCTFVerifyMode validates raw verify mode for a task and resolves "auto"/"".
func NormalizeCTFVerifyMode(mode, raw, description, goal string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "ctf" {
		return "", nil
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", CTFVerifyAuto:
		return ResolveCTFVerifyMode(raw, description, goal), nil
	case CTFVerifyFlag, CTFVerifyExploitProof, CTFVerifyFlagAndExploit:
		return raw, nil
	default:
		return "", ErrCTFVerifyModeInvalid
	}
}

// EffectiveCTFVerifyMode resolves stored ctf_verify_mode with legacy fallback.
func EffectiveCTFVerifyMode(stored, description, goal string) string {
	return ResolveCTFVerifyMode(stored, description, goal)
}

// TaskCTFVerifyMode returns the effective CTF verify mode for taskID.
func (d *DB) TaskCTFVerifyMode(ctx context.Context, taskID int64) (string, error) {
	var mode, raw, desc, goal string
	if err := d.QueryRowContext(ctx,
		`SELECT mode,COALESCE(ctf_verify_mode,''),COALESCE(description,''),COALESCE(goal,'') FROM tasks WHERE id=$1 AND deleted_at IS NULL`,
		taskID,
	).Scan(&mode, &raw, &desc, &goal); err != nil {
		return "", err
	}
	if strings.ToLower(strings.TrimSpace(mode)) != "ctf" {
		return "", nil
	}
	return EffectiveCTFVerifyMode(raw, desc, goal), nil
}

// SetTaskCTFVerifyMode updates a CTF task's explicit verification mode.
func (d *DB) SetTaskCTFVerifyMode(ctx context.Context, taskID int64, raw string) (string, error) {
	normalized, err := NormalizeCTFVerifyMode("ctf", raw, "", "")
	if err != nil {
		var mode, desc, goal string
		if qErr := d.QueryRowContext(ctx, `SELECT mode,COALESCE(description,''),COALESCE(goal,'') FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&mode, &desc, &goal); qErr != nil {
			return "", ErrTaskNotFound
		}
		if strings.ToLower(strings.TrimSpace(mode)) != "ctf" {
			return "", ErrTaskModeInvalid
		}
		return "", err
	}
	if strings.ToLower(strings.TrimSpace(raw)) == "" || strings.ToLower(strings.TrimSpace(raw)) == CTFVerifyAuto {
		var desc, goal string
		if qErr := d.QueryRowContext(ctx, `SELECT COALESCE(description,''),COALESCE(goal,'') FROM tasks WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`, taskID).Scan(&desc, &goal); qErr == nil {
			normalized = ResolveCTFVerifyMode(CTFVerifyAuto, desc, goal)
		}
	}
	res, err := d.ExecContext(ctx,
		`UPDATE tasks SET ctf_verify_mode=$2 WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`,
		taskID, normalized,
	)
	if err != nil {
		return "", err
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		return normalized, nil
	}
	var mode string
	if err := d.QueryRowContext(ctx, `SELECT mode FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&mode); err != nil {
		return "", ErrTaskNotFound
	}
	return "", ErrTaskModeInvalid
}

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
