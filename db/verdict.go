package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// 验收闭环(V1):技术判定、版本、验收任务、可靠事件。
//
// 三个互不替代的维度:
//   technical_verdict  技术真实性(supported/refuted/unverified/needs_review)
//   findings.status    处置状态(pending/fixed/ignored/...),既有枚举保持不变
//   evidence_version   证据绑定状态,既有语义保持不变
//
// 时间戳只用于审计;并发判定与优先级判定一律使用版本号。
// ============================================================================

// 技术判定取值。
const (
	VerdictUnverified  = "unverified"   // 尚未验收,或验收未得出结论
	VerdictSupported   = "supported"    // 证据支持该主张
	VerdictRefuted     = "refuted"      // 证据否定该主张
	VerdictNeedsReview = "needs_review" // 存在冲突意见,等待人工处置
)

// VerdictPolicyVersion 是当前验收规则的版本。修改验收规则时必须同步改这里,
// 否则无法区分"模型随机翻转"和"按新标准重新判断"。
const VerdictPolicyVersion = "verdict-policy-v1.1"

// 验收任务状态。
const (
	JobQueued     = "queued"
	JobLeased     = "leased"
	JobCommitted  = "committed"
	JobFailed     = "failed"
	JobSuperseded = "superseded"
)

// 验收主体类型。finding 与 goal 共用同一套领取/租约/重试/幂等底座,
// 但判断逻辑分开。
const (
	SubjectFinding = "finding"
	SubjectGoal    = "goal"
)

// 事件类型。
const (
	EventCandidateCreated   = "candidate_created"
	EventFindingSupported   = "finding_supported"
	EventFindingRefuted     = "finding_refuted"
	EventFindingNeedsReview = "finding_needs_review"
)

// 下游任务类型。
const EventJobReportRun = "report_run"

// 验收提交结果(不是 error,而是可判定的冲突类别)。
const (
	CommitOK              = ""
	CommitStale           = "stale"
	CommitSupersededHuman = "superseded_by_human"
	CommitLeaseLost       = "lease_lost"
	CommitPolicyMismatch  = "policy_mismatch"
	// CommitSubjectMismatch 表示租约所绑定的主体与提交目标不一致——调用方不能
	// 用主体 A 的租约去提交主体 B 的结果。
	CommitSubjectMismatch = "subject_mismatch"
)

var (
	ErrVerificationJobNotFound = errors.New("验收任务不存在")
	ErrFindingClaimEmpty       = errors.New("漏洞主张不能为空")
	ErrVerdictEventDrop        = errors.New("验收事件入队失败")
)

// 人工决定取值。clear = 人工显式清除决定,此后自动判定恢复权限。
const (
	HumanDecisionSupported   = "supported"
	HumanDecisionRefuted     = "refuted"
	HumanDecisionNeedsReview = "needs_review"
	HumanDecisionClear       = "clear"
)

// ClaimDetail 是候选主张的结构化部分。迁移时不得只保留 summary 而丢弃
// 名称/类别/等级/前提/证据来源。
type ClaimDetail struct {
	VulnClass     string   `json:"vulnclass,omitempty"`
	Name          string   `json:"name,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	Preconditions []string `json:"preconditions,omitempty"`
	EvidenceNote  string   `json:"evidence_note,omitempty"`
	Evidence      string   `json:"evidence,omitempty"`
}

// VerdictResult 是验收器的结构化输出。它回答的是"这份证据是否证明了
// 目标要求的安全属性或交付物",而不是"有没有抓到包"。
type VerdictResult struct {
	Decision          string   `json:"decision"` // supported | refuted | needs_review
	AcceptedClaim     string   `json:"accepted_claim"`
	AcceptedSeverity  string   `json:"accepted_severity,omitempty"`
	UnsupportedClaims []string `json:"unsupported_claims,omitempty"`
	MissingEvidence   []string `json:"missing_evidence,omitempty"`
	Preconditions     []string `json:"preconditions,omitempty"`
	SeverityRationale string   `json:"severity_rationale,omitempty"`
	PolicyVersion     string   `json:"policy_version,omitempty"`
	GoalVerdict       string   `json:"goal_verdict,omitempty"`
	Rationale         string   `json:"rationale,omitempty"`
}

// policy 返回该结果所依据的验收策略版本。
func (r VerdictResult) policy() string {
	if r.PolicyVersion != "" {
		return r.PolicyVersion
	}
	return VerdictPolicyVersion
}

// VerdictState 是一个 finding 当前的技术判定状态(读取用)。
type VerdictState struct {
	TechnicalVerdict     string `json:"technical_verdict"`
	InputRevision        int64  `json:"input_revision"`
	VerdictRevision      int64  `json:"verdict_revision"`
	HumanRevision        int64  `json:"human_revision"`
	VerdictInputRevision int64  `json:"verdict_input_revision"`
	VerdictPolicyVersion string `json:"verdict_policy_version"`
	LegacySource         string `json:"legacy_source,omitempty"`
}

// FindingVerdictEffective 是**唯一**的"当前有效判定"判据。
//
// 它同时要求:技术判定为 supported、判定所依据的输入版本与当前输入一致、
// 判定版本已提交、且判定策略版本仍是当前版本。任何一处不满足都说明
// 判定已过期或从未成立——过期判定不得参与计数、目标证明、继承或报告。
//
// SQL 侧的 EffectiveVerdictPredicate 必须与本函数保持同一组条件;
// 两者的一致性由 TestVerdictPredicateMatchesGoPredicate 锁定。
func FindingVerdictEffective(v VerdictState) bool {
	return v.TechnicalVerdict == VerdictSupported &&
		v.VerdictRevision > 0 &&
		v.VerdictInputRevision == v.InputRevision &&
		v.VerdictPolicyVersion == VerdictPolicyVersion
}

// EffectiveVerdictPredicate 返回与 FindingVerdictEffective 等价的 SQL 布尔表达式。
// alias 是 findings 表在该查询里的别名,必须是可信常量。policy 是编译期常量,
// 直接内联,避免把参数位置泄露给共享片段。
func EffectiveVerdictPredicate(alias string) string {
	return "((" + alias + ".technical_verdict = '" + VerdictSupported + "')" +
		" AND (" + alias + ".verdict_revision > 0)" +
		" AND (" + alias + ".verdict_input_revision = " + alias + ".input_revision)" +
		" AND (" + alias + ".verdict_policy_version = '" + VerdictPolicyVersion + "'))"
}

// FindingClaimInput 是一次候选提交或 S3 追加验证的主张内容。
type FindingClaimInput struct {
	Claim  string
	Detail ClaimDetail
	// ExistingFindingID > 0 表示这是对既有漏洞的**追加验证**(S3),不新建 finding。
	ExistingFindingID int64
	// SupersedesFindingID 只表达替代/纠正关系,不代替追加验证。
	SupersedesFindingID int64
	Actor               string
}

// FindingVerdictRow 是最小读取面,供验收器与守卫使用。
type FindingVerdictRow struct {
	FindingID             int64
	NodeID                int64
	TaskID                int64
	TechnicalVerdict      string
	ProposedClaim         string
	AcceptedClaim         string
	InputRevision         int64
	VerdictRevision       int64
	HumanRevision         int64
	VerdictInputRevision  int64
	VerdictPolicyVersion  string
	LegacySource          string
	Status                string
	ReportInputRevision   int64
	ReportVerdictRevision int64
}

// State 把行投影成判据所需的 VerdictState。
func (r FindingVerdictRow) State() VerdictState {
	return VerdictState{
		TechnicalVerdict:     r.TechnicalVerdict,
		InputRevision:        r.InputRevision,
		VerdictRevision:      r.VerdictRevision,
		HumanRevision:        r.HumanRevision,
		VerdictInputRevision: r.VerdictInputRevision,
		VerdictPolicyVersion: r.VerdictPolicyVersion,
		LegacySource:         r.LegacySource,
	}
}

// BumpFindingInputRevisionTx 在**验收输入清单**内容变化时递增 input_revision。
//
// 清单包含:主张、前提、证据引用及其内容哈希、身份对象、supports/refutes 关系。
// 不进入清单的展示性修改(排版、排序、纯 UI 字段)不调用本函数。
//
// 关键:只是递增版本就足以让既有判定失效(verdict_input_revision != input_revision),
// 因而无需改写 technical_verdict——过期判定会被 FindingVerdictEffective 直接排除。
func BumpFindingInputRevisionTx(tx *sql.Tx, findingID int64) (int64, error) {
	var rev int64
	err := tx.QueryRow(`UPDATE findings SET input_revision=input_revision+1 WHERE id=$1 RETURNING input_revision`, findingID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrFindingNotFound
	}
	return rev, err
}

// insertClaimTx 追加一条主张修订记录,revision 由该 finding 的既有记录数决定。
func insertClaimTx(tx *sql.Tx, findingID int64, kind, claim string, detail ClaimDetail, refs json.RawMessage, inputRev int64, actor string) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		refs = json.RawMessage("[]")
	}
	_, err = tx.Exec(`INSERT INTO finding_claims(finding_id,revision,kind,claim,detail,evidence_refs,input_revision,actor)
SELECT $1, COALESCE(MAX(revision),0)+1, $2, $3, $4, $5, $6, $7 FROM finding_claims WHERE finding_id=$1`,
		findingID, kind, claim, string(raw), string(refs), inputRev, actor)
	return err
}

// EnqueueVerificationJobTx 入队一个验收任务(幂等:同 key 复用同一任务)。
//
// 与通知的尽力投递不同,这个写入失败必须让调用方的事务回滚——验收任务是
// 候选进入闭环的必经工作流,不是便利功能。
func EnqueueVerificationJobTx(tx *sql.Tx, subjectKind string, subjectID, inputRevision int64, reviewRequestID string) (int64, error) {
	id, _, err := enqueueVerificationJobTx(tx, subjectKind, subjectID, inputRevision, reviewRequestID)
	return id, err
}

func enqueueVerificationJobTx(tx *sql.Tx, subjectKind string, subjectID, inputRevision int64, reviewRequestID string) (id int64, created bool, err error) {
	key := fmt.Sprintf("%s:%d:in%d:%s:%s", subjectKind, subjectID, inputRevision, VerdictPolicyVersion, reviewRequestID)
	err = tx.QueryRow(`
INSERT INTO verification_jobs(subject_kind,subject_id,idempotency_key,review_request_id,policy_version,input_revision,state)
VALUES($1,$2,$3,$4,$5,$6,'queued')
ON CONFLICT (subject_kind,subject_id,idempotency_key) DO NOTHING
RETURNING id`,
		subjectKind, subjectID, key, reviewRequestID, VerdictPolicyVersion, inputRevision).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind=$1 AND subject_id=$2 AND idempotency_key=$3`, subjectKind, subjectID, key).Scan(&id)
		return id, false, err
	}
	return id, err == nil, err
}

// EnqueueVerdictEventTx 在**同一事务**内登记一条可靠工作流事件。
// 返回错误时必须回滚,不能像通知那样静默丢弃。
func EnqueueVerdictEventTx(tx *sql.Tx, findingID int64, kind string, findingRevision int64, payload any) error {
	raw := []byte("{}")
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	if _, err := tx.Exec(`INSERT INTO verdict_events(finding_id,kind,finding_revision,payload)
VALUES($1,$2,$3,$4) ON CONFLICT (finding_id,kind,finding_revision) DO NOTHING`,
		findingID, kind, findingRevision, string(raw)); err != nil {
		return fmt.Errorf("%w: %v", ErrVerdictEventDrop, err)
	}
	return nil
}

// RecordHumanDecisionTx 记录一次人工决定,并把它提升为当前技术判定。
//
// 人工决定持续有效:只有显式 clear 才把权限交回自动判定。
// 时间用于审计,human_revision 用于并发检查与优先级。
func RecordHumanDecisionTx(tx *sql.Tx, findingID int64, decision, source, note, actor string) (int64, error) {
	switch decision {
	case HumanDecisionSupported, HumanDecisionRefuted, HumanDecisionNeedsReview, HumanDecisionClear:
	default:
		return 0, fmt.Errorf("未知人工决定: %s", decision)
	}
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return 0, err
	}
	var human, verdict, input int64
	var claim string
	if err := tx.QueryRow(`SELECT COALESCE(NULLIF(accepted_claim,''),NULLIF(proposed_claim,''),summary) FROM findings WHERE id=$1`, findingID).Scan(&claim); err != nil {
		return 0, err
	}
	if decision == HumanDecisionSupported && strings.TrimSpace(claim) == "" {
		return 0, ErrFindingClaimEmpty
	}
	technical, event := VerdictUnverified, "finding_unverified"
	switch decision {
	case HumanDecisionSupported:
		technical, event = VerdictSupported, EventFindingSupported
	case HumanDecisionRefuted:
		technical, event = VerdictRefuted, EventFindingRefuted
	case HumanDecisionNeedsReview:
		technical, event = VerdictNeedsReview, EventFindingNeedsReview
	}
	err := tx.QueryRow(`UPDATE findings SET human_revision=human_revision+1,verdict_revision=verdict_revision+1,
 technical_verdict=$2,accepted_claim=CASE WHEN $2='supported' THEN $3 ELSE '' END,
 accepted_detail=CASE WHEN $2='supported' AND accepted_claim<>'' THEN accepted_detail WHEN $2='supported' THEN proposed_detail ELSE '{}'::jsonb END,
 verdict_input_revision=input_revision,verdict_policy_version=$4 WHERE id=$1
 RETURNING human_revision,verdict_revision,input_revision`, findingID, technical, claim, VerdictPolicyVersion).Scan(&human, &verdict, &input)
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`INSERT INTO finding_human_decisions(finding_id,human_revision,decision,source,note,actor) VALUES($1,$2,$3,$4,$5,$6)`, findingID, human, decision, source, note, actor); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(`UPDATE verification_jobs SET state='superseded',lease_until=NULL,last_error='人工决定已更新' WHERE subject_kind='finding' AND subject_id=$1 AND state IN ('queued','leased')`, findingID); err != nil {
		return 0, err
	}
	if technical != VerdictSupported {
		claim = ""
	}
	if err = EnqueueVerdictEventTx(tx, findingID, event, verdict, map[string]any{"human_revision": human, "decision": decision, "source": source, "accepted_claim": claim}); err != nil {
		return 0, err
	}
	if decision == HumanDecisionClear {
		if _, err = EnqueueVerificationJobTx(tx, SubjectFinding, findingID, input, fmt.Sprintf("human-clear:%d", human)); err != nil {
			return 0, err
		}
	}
	return human, nil
}

// CommitFindingVerdictInput 是一次判定提交的完整预期版本组。
type CommitFindingVerdictInput struct {
	FindingID               int64
	JobID                   int64
	LeaseGeneration         int64
	ExpectedInputRevision   int64
	ExpectedVerdictRevision int64
	ExpectedHumanRevision   int64
	PolicyVersion           string
	Result                  VerdictResult
}

// CommitFindingVerdict 提交一次验收结果。
//
// 守卫(任一不满足即拒绝并返回对应类别,不做部分写入):
//   - 任务存活/未被归档(LockTaskEvidenceTx)     → 归档/删除屏障
//   - job.subject_kind/ subject_id 与 finding 一致 → 否则 subject_mismatch
//   - job 处于 leased、租约代次匹配、lease_until 未过期 → 否则 lease_lost
//   - job 记录的输入版本与当前一致               → 否则 stale
//   - job 记录的策略版本与当前一致               → 否则 policy_mismatch
//   - 输入/判定/人工版本未变                     → 否则 stale / superseded_by_human
//   - **最新有效人工决定**不是否定/确认(未 clear) → 否则 superseded_by_human
//
// 锁顺序统一为 task → finding → job(与绑定/归档路径一致),避免与
// SetFindingReportGated 形成相反锁序而互锁。
//
// 判定与对应事件在同一事务内提交;事件入队失败则整笔回滚。
func CommitFindingVerdict(ctx context.Context, d *DB, in CommitFindingVerdictInput) (string, error) {
	if in.Result.AcceptedSeverity != "" && !ValidSeverity(in.Result.AcceptedSeverity) {
		return "", fmt.Errorf("无效的验收等级")
	}
	verdict := in.Result.Decision
	switch verdict {
	case VerdictSupported, VerdictRefuted, VerdictNeedsReview:
	default:
		return "", fmt.Errorf("非法判定: %s", verdict)
	}
	policy := in.Result.policy()
	if in.PolicyVersion != "" && in.PolicyVersion != policy {
		return CommitPolicyMismatch, nil
	}
	if policy != VerdictPolicyVersion {
		return CommitPolicyMismatch, nil
	}
	if verdict == VerdictSupported && (strings.TrimSpace(in.Result.AcceptedClaim) == "" || len(in.Result.MissingEvidence) > 0) {
		return "", ErrFindingClaimEmpty
	}
	if in.JobID <= 0 {
		// 没有持久化验收任务就没有可信租约:拒绝无主体的提交。
		return CommitSubjectMismatch, nil
	}
	conflict := CommitOK
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		// ① 归属与存活:先解析 finding 所属任务,再按 task→finding→job 顺序加锁。
		var taskID sql.NullInt64
		if err := tx.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, in.FindingID).Scan(&taskID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrFindingNotFound
			}
			return err
		}
		if err := LockTaskEvidenceTx(tx, taskID.Int64); err != nil {
			return err // 归档/删除屏障
		}

		// ② finding 权威版本
		var (
			inputRev, verdictRev, humanRev int64
		)
		if err := tx.QueryRow(`SELECT input_revision,verdict_revision,human_revision
FROM findings WHERE id=$1 FOR UPDATE`, in.FindingID).
			Scan(&inputRev, &verdictRev, &humanRev); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrFindingNotFound
			}
			return err
		}

		// ③ 人工持续优先:human_revision 相等只证明"没有并发变化",并不授权
		// 自动结果覆盖一份已经存在的人工决定。只有显式 clear 才交回自动判定。
		var lastDecision string
		decErr := tx.QueryRow(`SELECT decision FROM finding_human_decisions
WHERE finding_id=$1 ORDER BY human_revision DESC LIMIT 1`, in.FindingID).Scan(&lastDecision)
		if decErr != nil && !errors.Is(decErr, sql.ErrNoRows) {
			return decErr
		}
		if decErr == nil && lastDecision != HumanDecisionClear && lastDecision != "" {
			conflict = CommitSupersededHuman
			return nil
		}
		if humanRev != in.ExpectedHumanRevision {
			conflict = CommitSupersededHuman
			return nil
		}
		if inputRev != in.ExpectedInputRevision || verdictRev != in.ExpectedVerdictRevision {
			conflict = CommitStale
			return nil
		}

		// ④ 租约与主体绑定:必须证明"这条租约就是针对这个主体的这个输入版本"。
		var (
			jobKind, jobPolicy, jobState string
			jobHash                      string
			manifest                     []byte
			execution                    []byte
			jobSubjectID, jobInputRev    int64
			jobGeneration                int64
			leaseValid                   bool
		)
		if err := tx.QueryRow(`SELECT subject_kind,subject_id,input_revision,policy_version,
       input_hash,input_manifest,execution_input,
       lease_generation,state,COALESCE(lease_until > clock_timestamp(), false)
FROM verification_jobs WHERE id=$1 FOR UPDATE`, in.JobID).
			Scan(&jobKind, &jobSubjectID, &jobInputRev, &jobPolicy, &jobHash, &manifest, &execution, &jobGeneration, &jobState, &leaseValid); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrVerificationJobNotFound
			}
			return err
		}
		if jobKind != SubjectFinding || jobSubjectID != in.FindingID {
			conflict = CommitSubjectMismatch
			return nil
		}
		if jobState != JobLeased || jobGeneration != in.LeaseGeneration || !leaseValid {
			conflict = CommitLeaseLost
			return nil
		}
		if jobInputRev != inputRev {
			conflict = CommitStale
			return nil
		}
		if jobPolicy != policy {
			conflict = CommitPolicyMismatch
			return nil
		}
		current, err := buildFindingBundleTx(ctx, tx, in.FindingID)
		if err != nil {
			return err
		}
		if len(manifest) == 0 || jobHash == "" || current.InputHash != jobHash {
			conflict = CommitStale
			return nil
		}

		if verdict == VerdictSupported {
			material := current
			if len(execution) > 0 {
				var saved EvidenceBundle
				if err := json.Unmarshal(execution, &saved); err != nil {
					return err
				}
				material = &saved
			}
			if !VerificationMaterialComplete(material) {
				return fmt.Errorf("必要正文缺失或未校验，不能确认漏洞")
			}
		}
		// ⑤ fencing 提交(再次带条件,防止并发双提交)
		res, err := tx.Exec(`UPDATE verification_jobs
SET state=$2, result=$3, committed_verdict=$4, lease_until=NULL, updated_at=now(),
    attempt_log=jsonb_set(attempt_log,ARRAY[($5::bigint)::text],COALESCE(attempt_log->(($5::bigint)::text),'{}'::jsonb)
       ||jsonb_build_object('outcome',$4::text,'result',$3::jsonb,'finished_at',clock_timestamp()),true)
WHERE id=$1 AND lease_generation=$5 AND state=$6 AND lease_until>clock_timestamp()`,
			in.JobID, JobCommitted, mustJSON(in.Result), verdict, in.LeaseGeneration, JobLeased)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			conflict = CommitLeaseLost
			return nil
		}
		nextRev := verdictRev + 1
		if _, err := tx.Exec(`UPDATE findings
SET technical_verdict=$2, accepted_claim=$3, accepted_detail=$4,
    verdict_revision=$5, verdict_input_revision=$6, verdict_policy_version=$7
WHERE id=$1`,
			in.FindingID, verdict, in.Result.AcceptedClaim, mustJSON(in.Result), nextRev, inputRev, policy); err != nil {
			return err
		}
		kind := EventFindingNeedsReview
		switch verdict {
		case VerdictSupported:
			kind = EventFindingSupported
		case VerdictRefuted:
			kind = EventFindingRefuted
		}
		return EnqueueVerdictEventTx(tx, in.FindingID, kind, nextRev, map[string]any{
			"accepted_claim": in.Result.AcceptedClaim,
			"policy_version": policy,
		})
	})
	if err != nil {
		return "", err
	}
	return conflict, nil
}

// mustJSON 序列化失败时退化为空对象,避免把守卫事务带崩。
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// VerificationJob 是一个已领取的验收任务。
type VerificationJob struct {
	ID               int64           `json:"id"`
	SubjectKind      string          `json:"subject_kind"`
	SubjectID        int64           `json:"subject_id"`
	InputRevision    int64           `json:"input_revision"`
	PolicyVersion    string          `json:"policy_version"`
	ReviewRequestID  string          `json:"review_request_id"`
	LeaseGeneration  int64           `json:"lease_generation"`
	Attempts         int             `json:"attempts"`
	Result           json.RawMessage `json:"result,omitempty"`
	CommittedVerdict string          `json:"committed_verdict,omitempty"`
}

// ClaimVerificationJob 以 FOR UPDATE SKIP LOCKED 领取一个到期任务,
// 同时递增 lease_generation(fencing token)并延长租约。
//
// 租约使用数据库时钟(now()),避免多机时钟漂移。
func (d *DB) ClaimVerificationJob(ctx context.Context, lease time.Duration) (*VerificationJob, error) {
	var out *VerificationJob
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRow(`
UPDATE verification_jobs SET
    state='leased',
    lease_generation=lease_generation+1,
    attempts=attempts+1,
    lease_until=now()+($1::double precision * interval '1 millisecond'),
    updated_at=now()
WHERE id = (
    SELECT id FROM verification_jobs
    WHERE (state='queued')
       OR (state='leased' AND (lease_until IS NULL OR lease_until < now()))
    ORDER BY id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id,subject_kind,subject_id,input_revision,policy_version,review_request_id,lease_generation,attempts`,
			lease.Milliseconds())
		var j VerificationJob
		if err := row.Scan(&j.ID, &j.SubjectKind, &j.SubjectID, &j.InputRevision, &j.PolicyVersion,
			&j.ReviewRequestID, &j.LeaseGeneration, &j.Attempts); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		out = &j
		return nil
	})
	return out, err
}

// FailVerificationJob 记录一次执行失败。任务回到队列等待重试,超过 maxAttempts
// 则落 failed 并保留可见错误——不能静默消失。
func (d *DB) FailVerificationJob(ctx context.Context, jobID, leaseGeneration int64, cause string, maxAttempts int) error {
	_, err := d.ExecContext(ctx, `
UPDATE verification_jobs SET
    state = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'queued' END,
    lease_until=NULL, last_error=$4, updated_at=now(),
    attempt_log=jsonb_set(attempt_log,ARRAY[($2::bigint)::text],COALESCE(attempt_log->(($2::bigint)::text),'{}'::jsonb)
       ||jsonb_build_object('error',$4::text,'outcome','error','finished_at',clock_timestamp()),true)
WHERE id=$1 AND lease_generation=$2 AND state='leased'`,
		jobID, leaseGeneration, maxAttempts, cause)
	return err
}

// ClaimVerificationJobByID 按 id 领取指定任务(测试与运维修复用)。
// 语义与 ClaimVerificationJob 相同:递增 lease_generation 并延长租约。
func (d *DB) ClaimVerificationJobByID(ctx context.Context, jobID int64, lease time.Duration) (*VerificationJob, error) {
	var out *VerificationJob
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRow(`
UPDATE verification_jobs SET
    state='leased', lease_generation=lease_generation+1, attempts=attempts+1,
    lease_until=now()+($2::double precision * interval '1 millisecond'), updated_at=now()
WHERE id = (SELECT id FROM verification_jobs
            WHERE id=$1 AND (state='queued' OR (state='leased' AND (lease_until IS NULL OR lease_until < now())))
            FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING id,subject_kind,subject_id,input_revision,policy_version,review_request_id,lease_generation,attempts`,
			jobID, lease.Milliseconds())
		var j VerificationJob
		if err := row.Scan(&j.ID, &j.SubjectKind, &j.SubjectID, &j.InputRevision, &j.PolicyVersion,
			&j.ReviewRequestID, &j.LeaseGeneration, &j.Attempts); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		out = &j
		return nil
	})
	return out, err
}

// SupersedeVerificationJob 把一条任务标记为失效(输入版本/主体/策略已变化,
// 或已有生效的人工决定)。它是**终态**,不会被重试,避免对作废输入反复调用模型。
func (d *DB) SupersedeVerificationJob(ctx context.Context, jobID, leaseGeneration int64, reason string) error {
	_, err := d.ExecContext(ctx, `UPDATE verification_jobs SET
    state=$3, lease_until=NULL, last_error=$4, updated_at=now(),
    attempt_log=jsonb_set(attempt_log,ARRAY[($2::bigint)::text],COALESCE(attempt_log->(($2::bigint)::text),'{}'::jsonb)
       ||jsonb_build_object('outcome','superseded','error',$4::text,'finished_at',clock_timestamp()),true)
WHERE id=$1 AND lease_generation=$2 AND state=$5`,
		jobID, leaseGeneration, JobSuperseded, reason, JobLeased)
	return err
}

// ReleaseExpiredVerificationLeases 回收已过期租约,供启动与周期对账使用。
func (d *DB) ReleaseExpiredVerificationLeases(ctx context.Context, maxAttempts int) (int64, error) {
	res, err := d.ExecContext(ctx, `
UPDATE verification_jobs SET
    state = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'queued' END,
    lease_until=NULL,
    last_error=CASE WHEN last_error='' THEN '租约过期,已回收' ELSE last_error END,
    updated_at=now(),
    attempt_log=jsonb_set(attempt_log,ARRAY[lease_generation::text],COALESCE(attempt_log->(lease_generation::text),'{}'::jsonb)
       ||jsonb_build_object('outcome','expired','finished_at',clock_timestamp()),true)
WHERE state='leased' AND lease_until IS NOT NULL AND lease_until < now()`, maxAttempts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FanOutVerdictEvents 是 verdict_events 的**唯一消费者**(持久化扇出器)。
//
// 它在同一事务内为事件创建各下游任务(event_jobs)并确认事件,因此下游任务
// 与事件确认原子一致;每个下游任务有自己的幂等键与处理状态,不会因为
// "第一位消费者处理完"而让其他消费者丢事件。
//
// 返回本轮扇出的事件数与新建下游任务数。
func (d *DB) FanOutVerdictEvents(ctx context.Context, max int) (events int, jobs int64, err error) {
	if max <= 0 {
		max = 20
	}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		rows, qerr := tx.Query(`
SELECT id,finding_id,kind,finding_revision
FROM verdict_events v
WHERE processed_at IS NULL AND EXISTS(SELECT 1 FROM findings f JOIN tasks t ON t.id=f.task_id
 WHERE f.id=v.finding_id AND t.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM task_archives a WHERE a.task_id=t.id AND a.state<>'archive_failed'))
ORDER BY id
FOR UPDATE SKIP LOCKED
LIMIT $1`, max)
		if qerr != nil {
			return qerr
		}
		type ev struct {
			id, findingID, revision int64
			kind                    string
		}
		var list []ev
		for rows.Next() {
			var e ev
			if scanErr := rows.Scan(&e.id, &e.findingID, &e.kind, &e.revision); scanErr != nil {
				rows.Close()
				return scanErr
			}
			list = append(list, e)
		}
		rows.Close()
		if rerr := rows.Err(); rerr != nil {
			return rerr
		}
		for _, e := range list {
			if e.kind == EventFindingSupported {
				// 只有"通过验收"才安排正式报告。幂等键含 finding_revision,
				// 因此 finding 更新后可以重新生成报告,而同版本重投不会重复。
				key := fmt.Sprintf("%s:%d:%d", EventJobReportRun, e.findingID, e.revision)
				res, jerr := tx.Exec(`INSERT INTO event_jobs(job_kind,dedup_key,source_event_id,payload,state)
VALUES($1,$2,$3,$4,'queued') ON CONFLICT (dedup_key) DO NOTHING`,
					EventJobReportRun, key, e.id, mustJSON(map[string]any{
						"finding_id":       e.findingID,
						"verdict_revision": e.revision,
					}))
				if jerr != nil {
					return jerr
				}
				if n, _ := res.RowsAffected(); n > 0 {
					jobs++
				}
			}
			if _, uerr := tx.Exec(`UPDATE verdict_events SET processed_at=now(), attempts=attempts+1 WHERE id=$1`, e.id); uerr != nil {
				return uerr
			}
			events++
		}
		return nil
	})
	return events, jobs, err
}

// ClaimEventJob 领取一个下游任务(report_run 等),与验收任务同样的 fencing 语义。
func (d *DB) ClaimEventJob(ctx context.Context, kind string, lease time.Duration, limits ...int) (*VerificationJob, error) {
	maxAttempts := 3
	if len(limits) > 0 {
		maxAttempts = limits[0]
	}
	if maxAttempts < 1 || lease <= 0 {
		return nil, fmt.Errorf("非法报告租约或重试上限")
	}
	var out *VerificationJob
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRow(`
UPDATE event_jobs SET state='leased', lease_generation=lease_generation+1,
    attempts=attempts+1, lease_until=now()+($2::double precision * interval '1 millisecond'), updated_at=now()
WHERE id = (SELECT id FROM event_jobs
            WHERE job_kind=$1 AND attempts<$3 AND ((state='queued') OR (state='leased' AND (lease_until IS NULL OR lease_until < clock_timestamp())))
            ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING id,payload,lease_generation,attempts`, kind, lease.Milliseconds(), maxAttempts)
		var j VerificationJob
		var payload []byte
		if err := row.Scan(&j.ID, &payload, &j.LeaseGeneration, &j.Attempts); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		j.Result = payload
		out = &j
		return nil
	})
	return out, err
}

// CompleteEventJob 标记下游任务完成。
func (d *DB) CompleteEventJob(ctx context.Context, jobID, leaseGeneration int64) error {
	var kind string
	if err := d.QueryRowContext(ctx, `SELECT job_kind FROM event_jobs WHERE id=$1`, jobID).Scan(&kind); err != nil {
		return err
	}
	if kind == EventJobReportRun {
		return ErrReportAtomicCommitRequired
	}
	_, err := d.ExecContext(ctx, `UPDATE event_jobs SET state='done', lease_until=NULL, updated_at=now()
WHERE id=$1 AND job_kind<>'report_run' AND lease_generation=$2 AND state='leased' AND lease_until>clock_timestamp()`, jobID, leaseGeneration)
	return err
}

// FailEventJob 记录下游任务失败并允许有限重试。
func (d *DB) FailEventJob(ctx context.Context, jobID, leaseGeneration int64, cause string, maxAttempts int) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE event_jobs SET
    state = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'queued' END,
    lease_until=NULL, last_error=$4, updated_at=now()
WHERE id=$1 AND lease_generation=$2 AND state='leased'`, jobID, leaseGeneration, maxAttempts, cause)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE report_runs SET state='failed',last_error=$3,finished_at=clock_timestamp()
	 WHERE job_id=$1 AND lease_generation=$2 AND state IN ('prepared','running')`, jobID, leaseGeneration, cause)
		return err
	})
}

// FindingVerdictRows 批量读取 finding 的判定状态(供统一读取路径使用)。
func (d *DB) FindingVerdictRows(ctx context.Context, findingIDs []int64) (map[int64]FindingVerdictRow, error) {
	out := map[int64]FindingVerdictRow{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(findingIDs))
	ph := ""
	for i, id := range findingIDs {
		args[i] = id
		if i > 0 {
			ph += ","
		}
		ph += fmt.Sprintf("$%d", i+1)
	}
	rows, err := d.QueryContext(ctx, `SELECT id,COALESCE(node_id,0),COALESCE(task_id,0),technical_verdict,proposed_claim,accepted_claim,
       input_revision,verdict_revision,human_revision,verdict_input_revision,verdict_policy_version,
       legacy_source,status,report_input_revision,report_verdict_revision
FROM findings WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r FindingVerdictRow
		if err := rows.Scan(&r.FindingID, &r.NodeID, &r.TaskID, &r.TechnicalVerdict, &r.ProposedClaim, &r.AcceptedClaim,
			&r.InputRevision, &r.VerdictRevision, &r.HumanRevision, &r.VerdictInputRevision, &r.VerdictPolicyVersion,
			&r.LegacySource, &r.Status, &r.ReportInputRevision, &r.ReportVerdictRevision); err != nil {
			return nil, err
		}
		out[r.FindingID] = r
	}
	return out, rows.Err()
}

// FindingVerdictByID 按独立 finding_id 读取判定状态。ok=false 表示该记录不存在。
func (d *DB) FindingVerdictByID(ctx context.Context, findingID int64) (FindingVerdictRow, bool, error) {
	var r FindingVerdictRow
	err := d.QueryRowContext(ctx, `SELECT id,COALESCE(node_id,0),COALESCE(task_id,0),technical_verdict,proposed_claim,accepted_claim,
       input_revision,verdict_revision,human_revision,verdict_input_revision,verdict_policy_version,
       legacy_source,status,report_input_revision,report_verdict_revision
FROM findings WHERE id=$1`, findingID).
		Scan(&r.FindingID, &r.NodeID, &r.TaskID, &r.TechnicalVerdict, &r.ProposedClaim, &r.AcceptedClaim,
			&r.InputRevision, &r.VerdictRevision, &r.HumanRevision, &r.VerdictInputRevision, &r.VerdictPolicyVersion,
			&r.LegacySource, &r.Status, &r.ReportInputRevision, &r.ReportVerdictRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	return r, true, nil
}

// FindingVerdictStates 按**探索节点 id** 读取 finding 的技术判定状态。
//
// 目标是唯一读取路径的一部分:任何想判断"这个漏洞发现能不能用于证明/计数"
// 的调用方都必须拿到 VerdictState 并交给 FindingVerdictEffective 判定,
// 不允许自己拼过滤条件。
func (s *ExplorationStore) FindingVerdictStates(nodeIDs []int64) (map[int64]VerdictState, error) {
	out := map[int64]VerdictState{}
	if len(nodeIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(nodeIDs))
	ph := ""
	for i, id := range nodeIDs {
		args[i] = id
		if i > 0 {
			ph += ","
		}
		ph += fmt.Sprintf("$%d", i+1)
	}
	rows, err := s.db.Query(`SELECT node_id,technical_verdict,input_revision,verdict_revision,human_revision,
       verdict_input_revision,verdict_policy_version,legacy_source
FROM findings WHERE node_id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID int64
		var st VerdictState
		if err := rows.Scan(&nodeID, &st.TechnicalVerdict, &st.InputRevision, &st.VerdictRevision, &st.HumanRevision,
			&st.VerdictInputRevision, &st.VerdictPolicyVersion, &st.LegacySource); err != nil {
			return nil, err
		}
		out[nodeID] = st
	}
	return out, rows.Err()
}

// migrateLegacyFindingVerdicts 是 V1 的一次性历史过渡。
//
// 规则:
//   - 升级前已存在的 finding 一律标 legacy_source='legacy_finding'(来源与
//     技术判定分开记录,不用 legacy_unverified 同时当结论)。
//   - 人工已标误报的,转为可追溯的人工否定(refuted),不再进入确认集合。
//   - 其余**不从历史 status 推导 supported**,保持未验证。
//
// 由 settings 守卫,只执行一次——不能放进 schema.sql,否则会把之后新建的
// 记录一并误标为 legacy。
func (d *DB) migrateLegacyFindingVerdicts() error {
	const flag = "findings_verdict_legacy_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`UPDATE findings SET legacy_source='legacy_finding'
WHERE legacy_source='' AND technical_verdict='unverified' AND human_revision=0 AND status<>'false_positive'`); err != nil {
		return fmt.Errorf("legacy finding 来源标记: %w", err)
	}
	// 人工已判定的误报 → 可追溯的人工否定。
	if _, err := d.Exec(`UPDATE findings SET
    legacy_source='legacy_finding',
    technical_verdict='refuted',
    human_revision=human_revision+1,
    verdict_policy_version='legacy-status-v1'
WHERE legacy_source='' AND status='false_positive' AND human_revision=0`); err != nil {
		return fmt.Errorf("legacy 误报转人工否定: %w", err)
	}
	// 为上面产生的人工否定补一条可追溯记录。
	if _, err := d.Exec(`INSERT INTO finding_human_decisions(finding_id,human_revision,decision,source,note,actor)
SELECT f.id, f.human_revision, 'refuted', 'legacy_status', '升级前已被人工标记为误报', 'migration'
FROM findings f
WHERE f.legacy_source='legacy_finding' AND f.status='false_positive' AND f.human_revision>0
  AND NOT EXISTS (SELECT 1 FROM finding_human_decisions h WHERE h.finding_id=f.id AND h.human_revision=f.human_revision)
ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("legacy 人工决定记录: %w", err)
	}
	return d.SetSetting(flag, "done")
}
