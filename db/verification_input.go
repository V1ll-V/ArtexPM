package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrGoalNotFound               = errors.New("目标不存在或不属于本任务")
	ErrVerificationInputStale     = errors.New("验收输入已变化")
	ErrVerificationLeaseLost      = errors.New("验收租约已失效")
	ErrVerificationPolicyMismatch = errors.New("验收策略已过期")
)

type verificationInputRow struct {
	kind, policy, state, hash, reason string
	subject, revision, generation     int64
	valid                             bool
	manifest                          []byte
}

func readVerificationInputTx(ctx context.Context, tx *sql.Tx, id int64, lock bool) (j verificationInputRow, err error) {
	query := `SELECT subject_kind,subject_id,input_revision,policy_version,state,lease_generation,
 COALESCE(lease_until>clock_timestamp(),false),input_manifest,input_hash,request_reason FROM verification_jobs WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	err = tx.QueryRowContext(ctx, query, id).Scan(&j.kind, &j.subject, &j.revision, &j.policy, &j.state, &j.generation, &j.valid, &j.manifest, &j.hash, &j.reason)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrVerificationJobNotFound
	}
	return
}

func validateVerificationLease(j verificationInputRow, generation int64) error {
	if j.state != JobLeased || j.generation != generation || !j.valid {
		return ErrVerificationLeaseLost
	}
	if j.policy != VerdictPolicyVersion {
		return ErrVerificationPolicyMismatch
	}
	return nil
}

func currentVerificationBundleTx(ctx context.Context, tx *sql.Tx, j verificationInputRow) (*EvidenceBundle, error) {
	switch j.kind {
	case SubjectFinding:
		return buildFindingBundleTx(ctx, tx, j.subject)
	case SubjectGoal:
		var expID int64
		err := tx.QueryRowContext(ctx, `SELECT exploration_id FROM exploration_nodes WHERE id=$1 AND kind='goal'`, j.subject).Scan(&expID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationInputStale
		}
		if err != nil {
			return nil, err
		}
		return buildGoalBundleTx(ctx, tx, expID, j.subject, j.reason)
	default:
		return nil, fmt.Errorf("未知验收主体")
	}
}

// PrepareVerificationInput freezes a finding's manifest at execution, or loads
// the goal manifest frozen atomically with submission. It never silently
// replaces an old goal request with current evidence.
func (d *DB) PrepareVerificationInput(ctx context.Context, id, generation int64) (out *EvidenceBundle, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		j, e := readVerificationInputTx(ctx, tx, id, false)
		if e != nil {
			return e
		}
		b, e := currentVerificationBundleTx(ctx, tx, j)
		if e != nil {
			return e
		}
		// Lock order: evidence/task/subject, then job. Re-read the leased row last.
		j, e = readVerificationInputTx(ctx, tx, id, true)
		if e != nil {
			return e
		}
		if e = validateVerificationLease(j, generation); e != nil {
			return e
		}
		if j.revision != b.InputRevision {
			return ErrVerificationInputStale
		}
		if len(j.manifest) == 0 {
			if j.kind == SubjectGoal {
				return ErrVerificationInputStale
			} // legacy unfrozen request
			raw, e := json.Marshal(b)
			if e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, `UPDATE verification_jobs SET input_manifest=$2,input_hash=$3 WHERE id=$1`, id, string(raw), b.InputHash)
			if e != nil {
				return e
			}
			out = b
			return nil
		}
		if j.hash == "" || j.hash != b.InputHash {
			return ErrVerificationInputStale
		}
		var frozen EvidenceBundle
		if e = json.Unmarshal(j.manifest, &frozen); e != nil {
			return e
		}
		hash, e := bundleHash(&frozen)
		if e != nil {
			return e
		}
		if hash != j.hash || frozen.InputHash != j.hash || frozen.InputRevision != j.revision {
			return ErrVerificationInputStale
		}
		out = &frozen
		return nil
	})
	return
}

// RecordVerificationExecutionInput persists the exact bounded model input.
// Retries reuse the first input; changed local availability cannot mutate an
// in-flight evaluation's meaning. Lease fencing also applies to this write.
func (d *DB) RecordVerificationExecutionInput(ctx context.Context, id, generation int64, b *EvidenceBundle) (out *EvidenceBundle, err error) {
	if b == nil {
		return nil, fmt.Errorf("验收输入为空")
	}
	manifestHash, e := bundleHash(b)
	if e != nil {
		return nil, e
	}
	if manifestHash != b.InputHash {
		return nil, ErrVerificationInputStale
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return nil, e
	}
	if len(raw) > 512*1024 {
		return nil, fmt.Errorf("验收输入超过 512 KiB，请收敛证据范围")
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		j, e := readVerificationInputTx(ctx, tx, id, true)
		if e != nil {
			return e
		}
		if e = validateVerificationLease(j, generation); e != nil {
			return e
		}
		if b.SubjectKind != j.kind || b.SubjectID != j.subject || b.InputRevision != j.revision || b.InputHash != j.hash || b.PolicyVersion != j.policy {
			return ErrVerificationInputStale
		}
		var saved []byte
		if e = tx.QueryRowContext(ctx, `SELECT execution_input FROM verification_jobs WHERE id=$1`, id).Scan(&saved); e != nil {
			return e
		}
		if len(saved) > 0 {
			var old EvidenceBundle
			if e = json.Unmarshal(saved, &old); e != nil {
				return e
			}
			out = &old
			var savedHash string
			if e = tx.QueryRowContext(ctx, `SELECT execution_hash FROM verification_jobs WHERE id=$1`, id).Scan(&savedHash); e != nil {
				return e
			}
			return recordVerificationAttemptInputTx(ctx, tx, id, generation, savedHash)
		}
		_, e = tx.ExecContext(ctx, `UPDATE verification_jobs SET execution_input=$2,execution_hash=$3 WHERE id=$1`, id, string(raw), hash)
		if e == nil {
			out = b
			e = recordVerificationAttemptInputTx(ctx, tx, id, generation, hash)
		}
		return e
	})
	return
}

func recordVerificationAttemptInputTx(ctx context.Context, tx *sql.Tx, id, generation int64, hash string) error {
	_, err := tx.ExecContext(ctx, `UPDATE verification_jobs SET attempt_log=jsonb_set(attempt_log,ARRAY[($2::bigint)::text],
 COALESCE(attempt_log->(($2::bigint)::text),'{}'::jsonb)||jsonb_build_object('input_hash',$3::text,'started_at',clock_timestamp()),true)
 WHERE id=$1`, id, generation, hash)
	return err
}

// Save even malformed model output before parsing it, scoped to this lease.
// Size/encoding flags keep raw NUL/binary or oversized responses safe for JSONB.
func (d *DB) RecordVerificationOutput(ctx context.Context, id, generation int64, raw string) error {
	truncated := len(raw) > 64*1024
	if truncated {
		raw = raw[:64*1024]
	}
	encoding := "utf-8"
	if !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		raw = base64.StdEncoding.EncodeToString([]byte(raw))
		encoding = "base64"
	}
	res, err := d.ExecContext(ctx, `UPDATE verification_jobs SET attempt_log=jsonb_set(attempt_log,ARRAY[($2::bigint)::text],
 COALESCE(attempt_log->(($2::bigint)::text),'{}'::jsonb)||jsonb_build_object('raw_output',$3::text,'encoding',$4::text,'truncated',$5::boolean),true)
 WHERE id=$1 AND lease_generation=$2 AND state='leased' AND lease_until>clock_timestamp()`, id, generation, raw, encoding, truncated)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrVerificationLeaseLost
	}
	return nil
}

// A supported goal must use active proof, not a dismissed fact, a stale finding
// or an empty list. The model still checks relevance and sufficiency separately.
func goalProofActive(b *EvidenceBundle) bool {
	if len(b.Refs) == 0 {
		return false
	}
	for _, r := range b.Refs {
		if !r.Effective {
			return false
		}
	}
	return true
}

// VerificationMaterialComplete checks availability/integrity, never semantic
// truth. A bounded nonempty excerpt may suffice; unseen bytes remain unknown.
func VerificationMaterialComplete(b *EvidenceBundle) bool {
	if b == nil {
		return false
	}
	for _, r := range b.Refs {
		if r.Kind == "http" {
			for _, body := range []*EvidenceBody{r.ReqBody, r.RespBody} {
				if body == nil || body.Missing || !body.Verified || (body.Truncated && body.IncludedBytes == 0) {
					return false
				}
			}
		}
		if r.Finding != nil && !VerificationMaterialComplete(r.Finding) {
			return false
		}
	}
	return true
}
