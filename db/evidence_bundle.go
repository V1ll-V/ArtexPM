package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// EvidenceBody is a bounded, hash-checked view of an immutable local blob.
type EvidenceBody struct {
	Text          string `json:"text,omitempty"`
	Encoding      string `json:"encoding,omitempty"`
	IncludedBytes int    `json:"included_bytes"`
	Verified      bool   `json:"verified"`
	Truncated     bool   `json:"truncated"`
	Missing       bool   `json:"missing"`
	Error         string `json:"error,omitempty"`
}

type EvidenceRef struct {
	Kind           string          `json:"kind"`
	RefID          string          `json:"ref_id,omitempty"`
	SourceTaskID   int64           `json:"source_task_id,omitempty"`
	Role           string          `json:"role,omitempty"`
	Note           string          `json:"note,omitempty"`
	Method         string          `json:"method,omitempty"`
	URL            string          `json:"url,omitempty"`
	Status         int             `json:"status,omitempty"`
	ReqHead        string          `json:"req_head,omitempty"`
	RespHead       string          `json:"resp_head,omitempty"`
	ReqHash        string          `json:"req_hash,omitempty"`
	RespHash       string          `json:"resp_hash,omitempty"`
	ReqLen         int64           `json:"req_len,omitempty"`
	RespLen        int64           `json:"resp_len,omitempty"`
	ReqBody        *EvidenceBody   `json:"req_body,omitempty"`
	RespBody       *EvidenceBody   `json:"resp_body,omitempty"`
	Summary        string          `json:"summary,omitempty"`
	Detail         json.RawMessage `json:"detail,omitempty"`
	State          string          `json:"state,omitempty"`
	ContentVersion int64           `json:"content_version,omitempty"`
	TrafficVer     int64           `json:"traffic_version,omitempty"`
	Finding        *EvidenceBundle `json:"finding,omitempty"`
	Effective      bool            `json:"effective,omitempty"`
}

// EvidenceBundle keeps proposed claims, original proof and historical decisions
// separate. InputHash identifies the frozen manifest, not a model's conclusion.
type EvidenceBundle struct {
	SubjectKind           string          `json:"subject_kind"`
	SubjectID             int64           `json:"subject_id"`
	TaskID                int64           `json:"task_id,omitempty"`
	Claim                 string          `json:"claim,omitempty"`
	Detail                json.RawMessage `json:"detail,omitempty"`
	Evidence              string          `json:"evidence,omitempty"`
	PreviousAcceptedClaim string          `json:"previous_accepted_claim,omitempty"`
	GoalText              string          `json:"goal_text,omitempty"`
	Reason                string          `json:"reason,omitempty"`
	RequirementVersion    int64           `json:"requirement_version,omitempty"`
	Refs                  []EvidenceRef   `json:"refs"`
	HumanDecision         string          `json:"human_decision,omitempty"`
	InputRevision         int64           `json:"input_revision"`
	VerdictRevision       int64           `json:"verdict_revision,omitempty"`
	HumanRevision         int64           `json:"human_revision,omitempty"`
	TechnicalVerdict      string          `json:"technical_verdict,omitempty"`
	VerdictInputRevision  int64           `json:"verdict_input_revision,omitempty"`
	VerdictPolicyVersion  string          `json:"verdict_policy_version,omitempty"`
	PolicyVersion         string          `json:"policy_version"`
	EvidenceVer           int64           `json:"evidence_version,omitempty"`
	InputHash             string          `json:"input_hash"`
}

func bundleHash(b *EvidenceBundle) (string, error) {
	copy := manifestView(b)
	copy.InputHash = ""
	if copy.SubjectKind == SubjectGoal {
		copy.InputRevision = 0
	}
	raw, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	// Normalize RawMessages: JSONB whitespace and key ordering are immaterial.
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		return "", err
	}
	raw, err = json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

// Hydration may add body views, but cannot change a frozen claim, identity,
// role, reference, or expected content hash. Clone before stripping views.
func manifestView(b *EvidenceBundle) EvidenceBundle {
	copy := *b
	copy.Refs = append([]EvidenceRef(nil), b.Refs...)
	for i := range copy.Refs {
		copy.Refs[i].ReqBody = nil
		copy.Refs[i].RespBody = nil
		if copy.Refs[i].Finding != nil {
			child := manifestView(copy.Refs[i].Finding)
			copy.Refs[i].Finding = &child
		}
	}
	return copy
}

func (d *DB) BuildFindingBundle(ctx context.Context, findingID int64) (b *EvidenceBundle, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; b, e = buildFindingBundleTx(ctx, tx, findingID); return e })
	return
}

func buildFindingBundleTx(ctx context.Context, tx *sql.Tx, id int64) (*EvidenceBundle, error) {
	if err := LockFindingEvidenceTx(tx, id, nil); err != nil {
		return nil, err
	}
	b := &EvidenceBundle{SubjectKind: SubjectFinding, SubjectID: id, Refs: []EvidenceRef{}, PolicyVersion: VerdictPolicyVersion}
	var taskID sql.NullInt64
	var detail []byte
	err := tx.QueryRowContext(ctx, `SELECT task_id,proposed_claim,COALESCE(proposed_detail,'{}'),
 COALESCE(accepted_claim,''),COALESCE(evidence,''),input_revision,evidence_version,
 verdict_revision,human_revision,technical_verdict,verdict_input_revision,verdict_policy_version
 FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&taskID, &b.Claim, &detail, &b.PreviousAcceptedClaim, &b.Evidence,
		&b.InputRevision, &b.EvidenceVer, &b.VerdictRevision, &b.HumanRevision, &b.TechnicalVerdict, &b.VerdictInputRevision, &b.VerdictPolicyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFindingNotFound
	}
	if err != nil {
		return nil, err
	}
	b.TaskID = taskID.Int64
	b.Detail = json.RawMessage(detail)
	rows, err := tx.QueryContext(ctx, `SELECT revision,kind,claim,detail FROM finding_claims
 WHERE finding_id=$1 ORDER BY revision DESC LIMIT 5`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rev int64
		var kind, claim string
		var detail []byte
		if err := rows.Scan(&rev, &kind, &claim, &detail); err != nil {
			rows.Close()
			return nil, err
		}
		b.Refs = append(b.Refs, EvidenceRef{Kind: "claim_history", RefID: fmt.Sprintf("claim#%d", rev), Summary: claim, Role: kind, Detail: json.RawMessage(detail)})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT b.role,b.note,s.method,s.url,s.status,s.req_head,s.resp_head,
 s.req_hash,s.resp_hash,s.req_len,s.resp_len,s.id
 FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id
 WHERE b.finding_id=$1 ORDER BY b.snapshot_id,b.role,b.note`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		r := EvidenceRef{Kind: "http", SourceTaskID: b.TaskID, TrafficVer: b.EvidenceVer}
		if err := rows.Scan(&r.Role, &r.Note, &r.Method, &r.URL, &r.Status, &r.ReqHead, &r.RespHead, &r.ReqHash, &r.RespHash, &r.ReqLen, &r.RespLen, &r.RefID); err != nil {
			rows.Close()
			return nil, err
		}
		b.Refs = append(b.Refs, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(b.Refs) > 69 {
		return nil, fmt.Errorf("流量证据超过 64 条，请收敛本次验收范围")
	}
	err = tx.QueryRowContext(ctx, `SELECT decision FROM finding_human_decisions WHERE finding_id=$1 ORDER BY human_revision DESC LIMIT 1`, id).Scan(&b.HumanDecision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	b.InputHash, err = bundleHash(b)
	return b, err
}

func (s *ExplorationStore) BuildGoalBundle(ctx context.Context, id int64) (b *EvidenceBundle, err error) {
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; b, e = buildGoalBundleTx(ctx, tx, s.expID, id, ""); return e })
	return
}

// Proof mutations share WithEvidenceTx. Row locks also fence direct payload
// edits/deletions; the task barrier serializes archive/deletion.
func buildGoalBundleTx(ctx context.Context, tx *sql.Tx, expID, id int64, reason string) (*EvidenceBundle, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT t.id FROM tasks t WHERE t.exploration_id=$1
 OR t.exploration_id IN (SELECT n.exploration_id FROM exploration_edges e JOIN exploration_nodes n ON n.id=e.src_id
 WHERE e.exploration_id=$1 AND e.dst_id=$2 AND e.rel='proves') ORDER BY t.id`, expID, id)
	if err != nil {
		return nil, err
	}
	var taskIDs []int64
	for rows.Next() {
		var tid int64
		if err := rows.Scan(&tid); err != nil {
			rows.Close()
			return nil, err
		}
		taskIDs = append(taskIDs, tid)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, tid := range taskIDs {
		if err := LockTaskEvidenceTx(tx, tid); err != nil {
			return nil, err
		}
	}
	b := &EvidenceBundle{SubjectKind: SubjectGoal, SubjectID: id, Reason: reason, Refs: []EvidenceRef{}, PolicyVersion: VerdictPolicyVersion}
	var payload []byte
	var goalState string
	err = tx.QueryRowContext(ctx, `SELECT n.payload,n.content_version,n.evaluation_revision,COALESCE(t.id,0),n.state
 FROM exploration_nodes n LEFT JOIN tasks t ON t.exploration_id=n.exploration_id
 WHERE n.id=$1 AND n.exploration_id=$2 AND n.kind='goal' FOR UPDATE OF n`, id, expID).
		Scan(&payload, &b.RequirementVersion, &b.InputRevision, &b.TaskID, &goalState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrGoalNotFound
	}
	if err != nil {
		return nil, err
	}
	if goalState == "abandoned" {
		return nil, ErrVerificationInputStale
	}
	b.Detail = json.RawMessage(payload)
	var p struct {
		Text string `json:"text"`
	}
	if err = json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	b.GoalText = p.Text
	rows, err = tx.QueryContext(ctx, `SELECT n.id,n.kind,n.payload,n.state,n.content_version,n.exploration_id,COALESCE(t.id,0)
 FROM exploration_edges e JOIN exploration_nodes n ON n.id=e.src_id LEFT JOIN tasks t ON t.exploration_id=n.exploration_id
 WHERE e.dst_id=$1 AND e.rel='proves' AND e.exploration_id=$2 ORDER BY n.id FOR UPDATE OF e,n`, id, expID)
	if err != nil {
		return nil, err
	}
	type proof struct {
		ref       EvidenceRef
		id, expID int64
	}
	var proofs []proof
	for rows.Next() {
		var x proof
		var pl []byte
		if err := rows.Scan(&x.id, &x.ref.Kind, &pl, &x.ref.State, &x.ref.ContentVersion, &x.expID, &x.ref.SourceTaskID); err != nil {
			rows.Close()
			return nil, err
		}
		x.ref.RefID = fmt.Sprint(x.id)
		x.ref.Role = "proves"
		x.ref.Detail = json.RawMessage(pl)
		var p struct {
			Summary string `json:"summary"`
		}
		if err = json.Unmarshal(pl, &p); err != nil {
			rows.Close()
			return nil, err
		}
		x.ref.Summary = p.Summary
		proofs = append(proofs, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(proofs) > 32 {
		return nil, fmt.Errorf("目标证据超过 32 条，请收敛本次验收范围")
	}
	for _, x := range proofs {
		if x.expID != expID {
			var allowed bool
			err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tasks owner JOIN task_relations r ON r.task_id=owner.id
    JOIN tasks source ON source.id=r.source_task_id WHERE owner.exploration_id=$1 AND source.exploration_id=$2
    AND owner.deleted_at IS NULL AND source.deleted_at IS NULL)`, expID, x.expID).Scan(&allowed)
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, fmt.Errorf("证明材料不属于本任务或直接关联任务")
			}
		}
		switch x.ref.Kind {
		case KindFact:
			x.ref.Effective = x.ref.State == "confirmed" || x.ref.State == "origin"
		case KindFinding:
			var fid int64
			if err = tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE node_id=$1`, x.id).Scan(&fid); err != nil {
				return nil, err
			}
			fb, e := buildFindingBundleTx(ctx, tx, fid)
			if e != nil {
				return nil, e
			}
			x.ref.Finding = fb
			x.ref.Effective = FindingVerdictEffective(VerdictState{TechnicalVerdict: fb.TechnicalVerdict, InputRevision: fb.InputRevision,
				VerdictRevision: fb.VerdictRevision, VerdictInputRevision: fb.VerdictInputRevision, VerdictPolicyVersion: fb.VerdictPolicyVersion})
		default:
			return nil, fmt.Errorf("只能用事实或有效漏洞证明目标")
		}
		b.Refs = append(b.Refs, x.ref)
	}
	b.InputHash, err = bundleHash(b)
	return b, err
}
