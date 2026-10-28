package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

var (
	ErrFindingReviewRequestInvalid = errors.New("必须提供不超过 128 字节的 review_request_id，重试复用原标识")
	ErrFindingHumanDecisionActive  = errors.New("人工决定仍生效；请先显式清除决定，再请求自动验收")
)

func normalizedClaimDetail(d ClaimDetail) ClaimDetail {
	d.VulnClass = strings.TrimSpace(d.VulnClass)
	d.Name = strings.TrimSpace(d.Name)
	d.Severity = strings.TrimSpace(d.Severity)
	d.Evidence = strings.TrimSpace(d.Evidence)
	d.EvidenceNote = strings.TrimSpace(d.EvidenceNote)
	set := map[string]bool{}
	for _, p := range d.Preconditions {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = true
		}
	}
	d.Preconditions = nil
	for p := range set {
		d.Preconditions = append(d.Preconditions, p)
	}
	sort.Strings(d.Preconditions)
	return d
}

// Semantic manifest excludes display order, history, timestamps and verdicts.
// Snapshot IDs bind the immutable request/response content hashes and metadata.
func findingManifestTx(tx *sql.Tx, id int64) (hash string, refs json.RawMessage, err error) {
	var claim, evidence string
	var raw []byte
	err = tx.QueryRow(`SELECT proposed_claim,proposed_detail,COALESCE(evidence,'') FROM findings WHERE id=$1`, id).Scan(&claim, &raw, &evidence)
	if err != nil {
		return
	}
	var detail ClaimDetail
	if err = json.Unmarshal(raw, &detail); err != nil {
		return
	}
	detail = normalizedClaimDetail(detail)
	err = tx.QueryRow(`SELECT COALESCE(jsonb_agg(jsonb_build_object('snapshot_id',b.snapshot_id,'role',b.role,'note',b.note,
 'request_hash',s.req_hash,'response_hash',s.resp_hash,'request_length',s.req_len,'response_length',s.resp_len)
 ORDER BY b.snapshot_id,b.role,b.note),'[]'::jsonb) FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1`, id).Scan(&refs)
	if err != nil {
		return
	}
	hash, err = canonicalReportHash(struct {
		Claim    string
		Detail   ClaimDetail
		Evidence string
		Refs     json.RawMessage
	}{strings.TrimSpace(claim), detail, strings.TrimSpace(evidence), refs})
	return
}
func refreshFindingInputTx(tx *sql.Tx, id int64, initial bool) (revision int64, changed bool, err error) {
	hash, _, err := findingManifestTx(tx, id)
	if err != nil {
		return 0, false, err
	}
	var previous string
	err = tx.QueryRow(`SELECT input_manifest_hash,input_revision FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&previous, &revision)
	if err != nil {
		return
	}
	if hash == previous {
		return revision, false, nil
	}
	if !initial {
		revision++
	}
	_, err = tx.Exec(`UPDATE findings SET input_manifest_hash=$2,input_revision=$3 WHERE id=$1`, id, hash, revision)
	return revision, true, err
}
func queueFindingInputTx(tx *sql.Tx, id, revision int64, request string) (int64, error) {
	job, created, err := enqueueVerificationJobTx(tx, SubjectFinding, id, revision, request)
	if err != nil {
		return 0, err
	}
	// Replaying an older request must never supersede a newer review.
	if !created {
		return job, nil
	}
	if _, err = tx.Exec(`UPDATE verification_jobs SET state='superseded',lease_until=NULL,last_error='证据输入或复核请求已更新'
 WHERE subject_kind='finding' AND subject_id=$1 AND id<>$2 AND state IN ('queued','leased')`, id, job); err != nil {
		return 0, err
	}
	if err = EnqueueVerdictEventTx(tx, id, EventCandidateCreated, revision, map[string]any{"job_id": job, "input_revision": revision, "review_request_id": request}); err != nil {
		return 0, err
	}
	return job, nil
}
func (d *DB) RequestFindingReview(ctx context.Context, id int64, request string) (job int64, err error) {
	request = strings.TrimSpace(request)
	if request == "" || len(request) > 128 {
		return 0, ErrFindingReviewRequestInvalid
	}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if e := LockFindingEvidenceTx(tx, id, nil); e != nil {
			return e
		}
		var decision string
		e := tx.QueryRowContext(ctx, `SELECT decision FROM finding_human_decisions WHERE finding_id=$1 ORDER BY human_revision DESC LIMIT 1`, id).Scan(&decision)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if decision != "" && decision != HumanDecisionClear {
			return ErrFindingHumanDecisionActive
		}
		var revision int64
		if e := tx.QueryRowContext(ctx, `SELECT input_revision FROM findings WHERE id=$1`, id).Scan(&revision); e != nil {
			return e
		}
		job, e = queueFindingInputTx(tx, id, revision, request)
		return e
	})
	return
}
