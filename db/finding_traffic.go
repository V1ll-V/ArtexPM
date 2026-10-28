package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/notify"
)

var (
	ErrEvidenceConflict = errors.New("流量证据已变更，请刷新后重试")
	ErrFindingNotFound  = errors.New("漏洞不存在")
	ErrEvidenceNotFound = errors.New("流量证据不存在")
)

// This lock covers the evidence filesystem as well as its SQL references. All
// processes sharing the database use it, including readers, exports and GC.
const findingEvidenceLockKey int64 = 7337741004

func (d *DB) WithEvidenceTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, findingEvidenceLockKey); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type TrafficRef struct {
	TrafficID string `json:"traffic_id"`
	Role      string `json:"role"`
	Note      string `json:"note"`
}

func NormalizeTrafficRefs(refs []TrafficRef) ([]TrafficRef, error) {
	out := make([]TrafficRef, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref.TrafficID = strings.TrimSpace(ref.TrafficID)
		if ref.TrafficID == "" {
			return nil, errors.New("traffic_id 不能为空")
		}
		if ref.Role == "" {
			ref.Role = "supporting"
		}
		if !ValidTrafficRole(ref.Role) {
			return nil, fmt.Errorf("无效的流量用途 %q", ref.Role)
		}
		if !seen[ref.TrafficID] {
			out = append(out, ref)
			seen[ref.TrafficID] = true
		}
	}
	return out, nil
}

func ValidTrafficRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

type TrafficEvidenceSnapshot struct {
	ID              string    `json:"id"`
	SourceTrafficID string    `json:"source_traffic_id"`
	CapturedAt      int64     `json:"captured_at"`
	URL             string    `json:"url"`
	Method          string    `json:"method"`
	Status          int       `json:"status"`
	ContentType     string    `json:"content_type"`
	ReqHead         string    `json:"req_head,omitempty"`
	RespHead        string    `json:"resp_head,omitempty"`
	ReqHash         string    `json:"req_hash"`
	RespHash        string    `json:"resp_hash"`
	ReqLen          int64     `json:"req_len"`
	RespLen         int64     `json:"resp_len"`
	CreatedAt       time.Time `json:"created_at"`
}

type FindingTrafficBinding struct {
	ID         int64                   `json:"id,string"`
	FindingID  int64                   `json:"finding_id,string"`
	SnapshotID string                  `json:"snapshot_id"`
	Role       string                  `json:"role"`
	Note       string                  `json:"note"`
	Position   int                     `json:"position"`
	CreatedAt  time.Time               `json:"created_at"`
	Snapshot   TrafficEvidenceSnapshot `json:"snapshot"`
}

type FindingTraffic struct {
	FindingID     int64                   `json:"finding_id,string"`
	Version       int64                   `json:"version"`
	ReportVersion int64                   `json:"report_version"`
	Bindings      []FindingTrafficBinding `json:"bindings"`
}

type PreparedTrafficEvidence struct {
	Ref      TrafficRef
	Snapshot TrafficEvidenceSnapshot
}

// Normalize makes the snapshot's text columns safe for PostgreSQL. URL and the
// head blocks come straight off the wire, so a target answering with a non-UTF-8
// header (a GBK `Content-Disposition: filename=…`, a NUL byte) would otherwise
// abort the INSERT and roll back the whole finding — losing a confirmed finding
// over a malformed response header. Applied before hashing so the ID always
// matches the bytes that actually land in the table.
func (s TrafficEvidenceSnapshot) Normalize() TrafficEvidenceSnapshot {
	s.SourceTrafficID = utf8Clean(s.SourceTrafficID)
	s.URL = utf8Clean(s.URL)
	s.Method = utf8Clean(s.Method)
	s.ContentType = utf8Clean(s.ContentType)
	s.ReqHead = utf8Clean(s.ReqHead)
	s.RespHead = utf8Clean(s.RespHead)
	return s
}

func TrafficSnapshotID(snapshot TrafficEvidenceSnapshot) string {
	snapshot = snapshot.Normalize()
	snapshot.ID = ""
	snapshot.CreatedAt = time.Time{}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// LockTaskEvidenceTx serializes writes with archive queueing (which locks the
// same task row). Once queued, its snapshot must not acquire new evidence.
func LockTaskEvidenceTx(tx *sql.Tx, taskID int64) error {
	if taskID == 0 {
		return nil
	}
	var deleted sql.NullTime
	if err := tx.QueryRow(`SELECT deleted_at FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&deleted); err != nil {
		return err
	}
	if deleted.Valid {
		return ErrTaskArchiveState
	}
	var state string
	err := tx.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1`, taskID).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && state != ArchiveFailed {
		return ErrTaskArchiveState
	}
	return nil
}

func LockFindingEvidenceTx(tx *sql.Tx, findingID int64, version *int64) error {
	var taskID sql.NullInt64
	if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, findingID).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFindingNotFound
		}
		return err
	}
	if version != nil && *version != current {
		return ErrEvidenceConflict
	}
	return nil
}

func InsertEvidenceSnapshotTx(tx *sql.Tx, s TrafficEvidenceSnapshot) error {
	if s.ID != TrafficSnapshotID(s) {
		return errors.New("证据快照元数据哈希不匹配")
	}
	// The ID was computed over the normalized form; store those same bytes.
	id := s.ID
	s = s.Normalize()
	s.ID = id
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO traffic_evidence_snapshots
(id,source_traffic_id,captured_at,url,method,status,content_type,req_head,resp_head,req_hash,resp_hash,req_len,resp_len,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.SourceTrafficID, s.CapturedAt, s.URL, s.Method, s.Status, s.ContentType, s.ReqHead, s.RespHead, s.ReqHash, s.RespHash, s.ReqLen, s.RespLen, s.CreatedAt)
	return err
}

func AddFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence) error {
	return addFindingTrafficTx(tx, findingID, prepared, true)
}

// S3 updates the claim and traffic together, then advances the input once.
func addFindingTrafficTx(tx *sql.Tx, findingID int64, prepared []PreparedTrafficEvidence, refresh bool) error {
	var position int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position)+1,0) FROM finding_traffic_bindings WHERE finding_id=$1`, findingID).Scan(&position); err != nil {
		return err
	}
	changed := false
	for _, item := range prepared {
		if err := InsertEvidenceSnapshotTx(tx, item.Snapshot); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots SET unreferenced_at=NULL WHERE id=$1`, item.Snapshot.ID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO UPDATE
SET role=EXCLUDED.role,note=EXCLUDED.note
WHERE (finding_traffic_bindings.role,finding_traffic_bindings.note) IS DISTINCT FROM (EXCLUDED.role,EXCLUDED.note)`, findingID, item.Snapshot.ID, item.Ref.Role, item.Ref.Note, position)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			changed = true
			position++
		}
	}
	if changed {
		if !refresh {
			_, err := tx.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, findingID)
			return err
		}
		return bumpEvidenceVersionTx(tx, findingID)
	}
	return nil
}

func bumpEvidenceVersionTx(tx *sql.Tx, findingID int64) error {
	// 证据引用属于验收输入清单的一部分:绑定变化必须同时推进 input_revision,
	// 否则旧判定会继续被当作"仍然适用"。
	_, err := tx.Exec(`UPDATE findings
SET evidence_version=evidence_version+1
WHERE id=$1`, findingID)
	if err != nil {
		return err
	}
	var claim string
	if err = tx.QueryRow(`SELECT proposed_claim FROM findings WHERE id=$1`, findingID).Scan(&claim); err != nil {
		return err
	}
	if strings.TrimSpace(claim) == "" {
		return nil
	}
	revision, changed, err := refreshFindingInputTx(tx, findingID, false)
	if err != nil {
		return err
	}
	if changed {
		_, err = queueFindingInputTx(tx, findingID, revision, "")
	}
	return err
}

func FindingTrafficTx(tx *sql.Tx, findingID int64) (*FindingTraffic, error) {
	out := &FindingTraffic{FindingID: findingID, Bindings: []FindingTrafficBinding{}}
	if err := tx.QueryRow(`SELECT evidence_version,report_evidence_version FROM findings WHERE id=$1`, findingID).Scan(&out.Version, &out.ReportVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	rows, err := tx.Query(`SELECT b.id,b.finding_id,b.snapshot_id,b.role,b.note,b.position,b.created_at,to_jsonb(s)
FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1 ORDER BY b.position,b.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b FindingTrafficBinding
		var raw []byte
		if err := rows.Scan(&b.ID, &b.FindingID, &b.SnapshotID, &b.Role, &b.Note, &b.Position, &b.CreatedAt, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.Snapshot); err != nil {
			return nil, err
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, rows.Err()
}

func (d *DB) GetFindingTraffic(ctx context.Context, findingID int64) (out *FindingTraffic, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = FindingTrafficTx(tx, findingID); return e })
	return
}

func (d *DB) EditFindingTraffic(ctx context.Context, findingID, bindingID, version int64, role, note *string, remove bool, order []int64) error {
	if role != nil && !ValidTrafficRole(*role) {
		return errors.New("无效的流量用途")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, findingID, &version); err != nil {
			return err
		}
		before, _, err := findingManifestTx(tx, findingID)
		if err != nil {
			return err
		}
		if order != nil {
			current, err := FindingTrafficTx(tx, findingID)
			if err != nil {
				return err
			}
			if len(order) != len(current.Bindings) {
				return ErrEvidenceConflict
			}
			ids := map[int64]bool{}
			for _, b := range current.Bindings {
				ids[b.ID] = true
			}
			for position, id := range order {
				if !ids[id] {
					return ErrEvidenceConflict
				}
				delete(ids, id)
				if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE finding_id=$2 AND id=$3`, position, findingID, id); err != nil {
					return err
				}
			}
		} else {
			var res sql.Result
			var err error
			if remove {
				res, err = tx.Exec(`DELETE FROM finding_traffic_bindings WHERE finding_id=$1 AND id=$2`, findingID, bindingID)
			} else {
				res, err = tx.Exec(`UPDATE finding_traffic_bindings SET role=COALESCE($3,role),note=COALESCE($4,note) WHERE finding_id=$1 AND id=$2`, findingID, bindingID, role, note)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrEvidenceNotFound
			}
		}
		after, _, err := findingManifestTx(tx, findingID)
		if err != nil {
			return err
		}
		if before == after {
			return nil
		}
		return bumpEvidenceVersionTx(tx, findingID)
	})
}

type RecordFindingInput struct {
	TaskID, ExplorationID, IntentID                      int64
	VulnClass, Name, Severity, Summary, Evidence, Worker string
	AssetIDs                                             []int64
	// V1 验收闭环:
	//   ExistingFindingID > 0 表示这是对既有漏洞的**追加验证**(S3),不新建 finding。
	//   SupersedesFindingID 只表达替代/纠正关系,不代替追加验证。
	ExistingFindingID   int64
	SupersedesFindingID int64
	Actor               string
	// Preconditions 是主张成立所需的适用前提(进入验收输入清单)。
	Preconditions []string
	EvidenceNote  string
}

// proposalClaim 返回候选主张文本。主张必须是非空的:没有主张就没有可验收对象。
func (in RecordFindingInput) proposalClaim() string {
	if s := strings.TrimSpace(in.Summary); s != "" {
		return s
	}
	return strings.TrimSpace(in.VulnClass + " " + in.Name)
}

// claimDetail 汇总迁移与验收都必须保留的主张要素。
func (in RecordFindingInput) claimDetail() ClaimDetail {
	return ClaimDetail{
		VulnClass:     in.VulnClass,
		Name:          in.Name,
		Severity:      in.Severity,
		Preconditions: in.Preconditions,
		EvidenceNote:  in.EvidenceNote,
		Evidence:      in.Evidence,
	}
}

// recordClaimAndEnqueueTx 写入候选主张、验收任务与候选事件。
//
// 三者与 finding 主记录在**同一事务**内提交:验收任务是候选进入闭环的必经
// 工作流,不是尽力投递的通知,任何一步失败都必须整笔回滚。
func recordClaimAndEnqueueTx(tx *sql.Tx, findingID int64, in RecordFindingInput, claimKind string) (jobID int64, err error) {
	claim := in.proposalClaim()
	if claim == "" {
		return 0, ErrFindingClaimEmpty
	}
	detail := normalizedClaimDetail(in.claimDetail())
	raw, err := json.Marshal(detail)
	if err != nil {
		return 0, err
	}
	var inputRev int64
	if err := tx.QueryRow(`UPDATE findings SET proposed_claim=$2, proposed_detail=$3
WHERE id=$1 RETURNING input_revision`, findingID, claim, string(raw)).Scan(&inputRev); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrFindingNotFound
		}
		return 0, err
	}
	inputRev, _, err = refreshFindingInputTx(tx, findingID, true)
	if err != nil {
		return 0, err
	}
	_, refs, err := findingManifestTx(tx, findingID)
	if err != nil {
		return 0, err
	}
	if err := insertClaimTx(tx, findingID, claimKind, claim, detail, refs, inputRev, in.Actor); err != nil {
		return 0, err
	}
	jobID, err = queueFindingInputTx(tx, findingID, inputRev, "")
	if err != nil {
		return 0, err
	}
	if err := EnqueueVerdictEventTx(tx, findingID, EventCandidateCreated, inputRev, map[string]any{
		"job_id":         jobID,
		"input_revision": inputRev,
	}); err != nil {
		return 0, err
	}
	return jobID, nil
}

// appendVerificationTx 把一次 S3 追加验证挂到**既有 finding_id** 上。
//
// 它不新建 finding(避免 #45/#46 那种"复现一次多一条成果"),而是:追加主张
// 修订、递增验收输入版本、重新入队验收。人工已作出决定时保持人工优先,
// 不把技术判定改回未验证。
func appendVerificationTx(tx *sql.Tx, in RecordFindingInput, existingID int64, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	var nodeID int64
	var humanRev int64
	var ownerTask sql.NullInt64
	var ownerExp int64
	// 归属检查:引用既有 finding_id 不等于获得写入授权。必须核对这条 finding
	// 实际属于哪个任务/探索——继承来的或无关任务的记录一律只读。
	if err := tx.QueryRow(`SELECT COALESCE(f.node_id,0),f.human_revision,f.task_id,n.exploration_id
FROM findings f LEFT JOIN exploration_nodes n ON n.id=f.node_id
WHERE f.id=$1`, existingID).Scan(&nodeID, &humanRev, &ownerTask, &ownerExp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("漏洞所属任务与探索记录不匹配")
		}
		// 既有 finding 必须属于同一个任务;跨任务追加写入一律拒绝。
		if !ownerTask.Valid || ownerTask.Int64 != in.TaskID {
			return nil, errors.New("该漏洞不属于当前任务，不能追加验证（继承或无关任务的记录只读）")
		}
	} else if ownerExp != in.ExplorationID {
		// 无任务上下文时至少要求同属一个探索。
		return nil, errors.New("该漏洞不属于当前探索，不能追加验证")
	}
	claim := in.proposalClaim()
	if claim == "" {
		return nil, ErrFindingClaimEmpty
	}
	detail := normalizedClaimDetail(in.claimDetail())
	raw, err := json.Marshal(detail)
	if err != nil {
		return nil, err
	}
	if err := LockFindingEvidenceTx(tx, existingID, nil); err != nil {
		return nil, err
	}
	// Freeze one semantic input after both claim and evidence have changed.
	if err := addFindingTrafficTx(tx, existingID, prepared, false); err != nil {
		return nil, err
	}
	var inputRev int64
	if err := tx.QueryRow(`UPDATE findings SET
       proposed_claim=CASE WHEN $2::text='' THEN proposed_claim ELSE $2::text END,
       proposed_detail=CASE WHEN $3::jsonb='{}'::jsonb THEN proposed_detail ELSE $3::jsonb END,
       supersedes_finding_id=CASE WHEN $4::bigint>0 THEN $4::bigint ELSE supersedes_finding_id END
WHERE id=$1 RETURNING input_revision`, existingID, claim, string(raw), in.SupersedesFindingID).Scan(&inputRev); err != nil {
		return nil, err
	}
	_, changed, err := refreshFindingInputTx(tx, existingID, false)
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRow(`SELECT input_revision FROM findings WHERE id=$1`, existingID).Scan(&inputRev); err != nil {
		return nil, err
	}
	// An identical retry must not append history or create a new verification job.
	if !changed {
		traffic, e := FindingTrafficTx(tx, existingID)
		return &RecordedFinding{FindingID: existingID, NodeID: nodeID, Traffic: traffic}, e
	}
	_, refs, err := findingManifestTx(tx, existingID)
	if err != nil {
		return nil, err
	}
	// An empty detail means "keep previous detail"; audit the effective input.
	if err = tx.QueryRow(`SELECT proposed_detail FROM findings WHERE id=$1`, existingID).Scan(&raw); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &detail); err != nil {
		return nil, err
	}
	// 新证据使自动判定过期;人工决定优先,不覆盖。
	if humanRev == 0 {
		if _, err := tx.Exec(`UPDATE findings SET technical_verdict=$2 WHERE id=$1 AND human_revision=0`, existingID, VerdictUnverified); err != nil {
			return nil, err
		}
	}
	if err := insertClaimTx(tx, existingID, "append_verification", claim, detail, refs, inputRev, in.Actor); err != nil {
		return nil, err
	}
	jobID, err := queueFindingInputTx(tx, existingID, inputRev, "")
	if err != nil {
		return nil, err
	}
	if err := EnqueueVerdictEventTx(tx, existingID, EventCandidateCreated, inputRev, map[string]any{
		"job_id":         jobID,
		"input_revision": inputRev,
		"append":         true,
	}); err != nil {
		return nil, err
	}
	traffic, err := FindingTrafficTx(tx, existingID)
	if err != nil {
		return nil, err
	}
	return &RecordedFinding{FindingID: existingID, NodeID: nodeID, Traffic: traffic}, nil
}

type RecordedFinding struct {
	FindingID int64           `json:"finding_id,string"`
	NodeID    int64           `json:"finding_node_id,string"`
	Traffic   *FindingTraffic `json:"traffic"`
}

// ctx 由调用方传入本次事务所用的上下文（而非在内部取 context.Background）：
// 事务内新加的推送事件写入同样应受调用方的取消与超时约束。
func RecordFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	// 归属/存活屏障必须在**任何**写入之前:包括 S3 追加分支。此前 append 分支
	// 提前 return,绕过了 LockTaskEvidenceTx,于是跨任务或归档中的追加写入不受
	// 约束。锁顺序统一为 task → finding。
	if err := LockTaskEvidenceTx(tx, in.TaskID); err != nil {
		return nil, err
	}
	// S3 追加验证:挂到既有 finding_id,不新建记录。
	if in.ExistingFindingID > 0 {
		return appendVerificationTx(tx, in, in.ExistingFindingID, prepared)
	}
	if in.TaskID > 0 {
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, in.TaskID).Scan(&expID); err != nil {
			return nil, err
		}
		if expID != in.ExplorationID {
			return nil, errors.New("漏洞所属任务与探索记录不匹配")
		}
	}
	if in.IntentID > 0 {
		var ok bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='intent')`, in.IntentID, in.ExplorationID).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("intent_id 必须是本任务的意图（关联任务意图只读）")
		}
	}
	payload, _ := json.Marshal(map[string]any{"vulnclass": in.VulnClass, "name": in.Name, "severity": in.Severity, "summary": in.Summary, "evidence": map[string]any{"by": in.Worker, "poc": in.Evidence}})
	out := &RecordedFinding{}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Worker).Scan(&out.NodeID); err != nil {
		return nil, err
	}
	for _, asset := range in.AssetIDs {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, out.NodeID, asset); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4)`, in.ExplorationID, in.IntentID, RelYields, out.NodeID); err != nil {
			return nil, err
		}
	}
	assets := in.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	raw, _ := json.Marshal(assets)
	if err := tx.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,asset_ids)
VALUES(NULLIF($1,0),$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, in.TaskID, out.NodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Worker, string(raw)).Scan(&out.FindingID); err != nil {
		return nil, err
	}
	// 在**同一事务**里登记一条推送事件：提交即保证「漏洞落库」与「推送任务存在」
	// 原子一致，不存在提交成功却没入队、消息永久丢失的窗口。
	// 这里的失败被隔离在保存点上、不影响漏洞写入（见函数注释），因此忽略返回值。
	RecordNotificationEventTx(ctx, tx, notify.EventFindingCreated, out.FindingID, notify.Snapshot{
		Kind:      notify.EventFindingCreated,
		FindingID: out.FindingID,
		TaskID:    in.TaskID,
		VulnClass: in.VulnClass,
		Name:      in.Name,
		Severity:  in.Severity,
		Summary:   in.Summary,
		AssetIDs:  assets,
	})
	if err := AddFindingTrafficTx(tx, out.FindingID, prepared); err != nil {
		return nil, err
	}
	var err error
	out.Traffic, err = FindingTrafficTx(tx, out.FindingID)
	if err != nil {
		return nil, err
	}
	// V1:候选主张 + 验收任务 + 候选事件在同一事务内提交。
	if _, err := recordClaimAndEnqueueTx(tx, out.FindingID, in, "candidate"); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordFinding is the atomic legacy/no-recorder path used by tools and tests.
func (s *ExplorationStore) RecordFinding(ctx context.Context, in RecordFindingInput) (out *RecordedFinding, err error) {
	in.ExplorationID = s.expID
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error { var e error; out, e = RecordFindingTx(ctx, tx, in, nil); return e })
	return
}

func (d *DB) FindingIDByNodeID(nodeID int64) (id int64, err error) {
	err = d.QueryRow(`SELECT id FROM findings WHERE node_id=$1`, nodeID).Scan(&id)
	return
}

// PopulateFindingTrafficIDs only enriches already-visible nodes. It performs no
// discovery or ID guessing, and leaves the legacy node ID unchanged.
func (s *ExplorationStore) PopulateFindingTrafficIDs(nodes []*Node) error {
	byID := map[int64]*Node{}
	var args []any
	var placeholders []string
	for _, n := range nodes {
		if n == nil || n.Kind != KindFinding || byID[n.ID] != nil {
			continue
		}
		byID[n.ID] = n
		args = append(args, n.ID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT f.id,f.node_id,(SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id) FROM findings f WHERE f.node_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var findingID, nodeID int64
		var count int
		if err := rows.Scan(&findingID, &nodeID, &count); err != nil {
			return err
		}
		n := byID[nodeID]
		n.FindingID, n.FindingNodeID, n.TrafficCount = findingID, nodeID, count
	}
	return rows.Err()
}

func (d *DB) SetFindingReportVersionByNodeID(ctx context.Context, nodeID int64, report string, version *int64) (int64, error) {
	return d.SetFindingReportGated(ctx, nodeID, report, version)
}
