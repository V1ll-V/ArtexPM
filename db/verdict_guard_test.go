package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// ============================================================================
// R2/R6/R8 的回归测试:每一条都对应审查报告里给出的可推演反例。
// 需要 PostgreSQL;无库时 Skip(不算通过)。
// ============================================================================

// newGuardFixture 建一个任务 + 一个候选,返回 finding 与它的验收任务。
func newGuardFixture(t *testing.T, d *DB, label string) (*Task, *RecordedFinding, int64) {
	t.Helper()
	ctx := context.Background()
	tk, err := d.CreateTask(label, "确认漏洞", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	es := d.Exploration(tk.ExplorationID)
	rec, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, VulnClass: "sqli", Name: label, Severity: "high",
		Summary: label + " 候选主张", Evidence: "proof", Worker: "test",
	})
	if err != nil {
		t.Fatalf("RecordFinding: %v", err)
	}
	var jobID int64
	if err := d.QueryRow(`SELECT id FROM verification_jobs
WHERE subject_kind=$1 AND subject_id=$2 ORDER BY id DESC LIMIT 1`,
		SubjectFinding, rec.FindingID).Scan(&jobID); err != nil {
		t.Fatalf("找不到验收任务: %v", err)
	}
	return tk, rec, jobID
}

// TestCommitRejectsWrongSubject 复现 R6:用主体 A 的租约提交主体 B 的结果。
func TestCommitRejectsWrongSubject(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	_, recA, jobA := newGuardFixture(t, d, "主体A")
	_, recB, _ := newGuardFixture(t, d, "主体B")

	job, err := d.ClaimVerificationJobByID(ctx, jobA, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取 A 的任务失败: %v", err)
	}
	rowB, _, _ := d.FindingVerdictByID(ctx, recB.FindingID)

	conflict, cerr := CommitFindingVerdict(ctx, d, CommitFindingVerdictInput{
		FindingID: recB.FindingID, JobID: job.ID, LeaseGeneration: job.LeaseGeneration,
		ExpectedInputRevision: rowB.InputRevision, ExpectedVerdictRevision: rowB.VerdictRevision,
		ExpectedHumanRevision: rowB.HumanRevision,
		Result:                VerdictResult{Decision: VerdictSupported, AcceptedClaim: "越权提交"},
	})
	if cerr != nil {
		t.Fatalf("不应返回错误: %v", cerr)
	}
	if conflict != CommitSubjectMismatch {
		t.Fatalf("got %q, want %q —— 不能拿 A 的租约提交 B", conflict, CommitSubjectMismatch)
	}
	after, _, _ := d.FindingVerdictByID(ctx, recB.FindingID)
	if after.TechnicalVerdict != VerdictUnverified {
		t.Fatalf("被拒后 B 不应被改成 %q", after.TechnicalVerdict)
	}
	_ = recA
}

// TestCommitRejectsExpiredLease 复现 R6:租约已过期但仍可提交。
func TestCommitRejectsExpiredLease(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	_, rec, jobID := newGuardFixture(t, d, "过期租约")
	job, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取失败: %v", err)
	}
	// 确定性构造过期:直接把 lease_until 推到过去,不依赖 sleep。
	if _, err := d.Exec(`UPDATE verification_jobs SET lease_until=now()-interval '1 second' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	row, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	conflict, cerr := CommitFindingVerdict(ctx, d, CommitFindingVerdictInput{
		FindingID: rec.FindingID, JobID: job.ID, LeaseGeneration: job.LeaseGeneration,
		ExpectedInputRevision: row.InputRevision, ExpectedVerdictRevision: row.VerdictRevision,
		ExpectedHumanRevision: row.HumanRevision,
		Result:                VerdictResult{Decision: VerdictSupported, AcceptedClaim: "过期"},
	})
	if cerr != nil {
		t.Fatalf("不应返回错误: %v", cerr)
	}
	if conflict != CommitLeaseLost {
		t.Fatalf("got %q, want %q", conflict, CommitLeaseLost)
	}
}

// TestCommitRejectsOldGeneration 复现 R6:同一任务被重新领取后,旧执行者不能提交。
func TestCommitRejectsOldGeneration(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	_, rec, jobID := newGuardFixture(t, d, "旧代次")
	first, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || first == nil {
		t.Fatalf("首次领取失败: %v", err)
	}
	// 让租约立刻过期并重新领取 → 代次递增。
	if _, err := d.Exec(`UPDATE verification_jobs SET lease_until=now()-interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	second, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || second == nil {
		t.Fatalf("重新领取失败: %v", err)
	}
	if second.LeaseGeneration == first.LeaseGeneration {
		t.Fatal("重新领取必须递增 lease_generation")
	}
	row, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	conflict, cerr := CommitFindingVerdict(ctx, d, CommitFindingVerdictInput{
		FindingID: rec.FindingID, JobID: jobID, LeaseGeneration: first.LeaseGeneration,
		ExpectedInputRevision: row.InputRevision, ExpectedVerdictRevision: row.VerdictRevision,
		ExpectedHumanRevision: row.HumanRevision,
		Result:                VerdictResult{Decision: VerdictSupported, AcceptedClaim: "迟到的执行者"},
	})
	if cerr != nil {
		t.Fatalf("不应返回错误: %v", cerr)
	}
	if conflict != CommitLeaseLost {
		t.Fatalf("got %q, want %q —— 过期执行者不能提交", conflict, CommitLeaseLost)
	}
}

// TestCommitRejectsStaleInput 复现 R7/R6:同流量版本但主张/证据已变,旧判定不能提交。
func TestCommitRejectsStaleInput(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	tk, rec, jobID := newGuardFixture(t, d, "输入已变")
	job, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取失败: %v", err)
	}
	row, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	// 领取之后追加一次 S3 验证 → input_revision 前进。
	es := d.Exploration(tk.ExplorationID)
	if _, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, VulnClass: "sqli", Name: "输入已变", Severity: "high",
		Summary: "追加主张", Evidence: "proof2", Worker: "test",
		ExistingFindingID: rec.FindingID,
	}); err != nil {
		t.Fatalf("追加验证失败: %v", err)
	}
	conflict, cerr := CommitFindingVerdict(ctx, d, CommitFindingVerdictInput{
		FindingID: rec.FindingID, JobID: job.ID, LeaseGeneration: job.LeaseGeneration,
		ExpectedInputRevision: row.InputRevision, ExpectedVerdictRevision: row.VerdictRevision,
		ExpectedHumanRevision: row.HumanRevision,
		Result:                VerdictResult{Decision: VerdictSupported, AcceptedClaim: "旧输入"},
	})
	if cerr != nil {
		t.Fatalf("不应返回错误: %v", cerr)
	}
	if conflict != CommitStale {
		t.Fatalf("got %q, want %q", conflict, CommitStale)
	}
}

// TestHumanRefutedBlocksAutoSupported 复现 R2 的核心反例:
// 人工先否定(human_revision=1),自动任务用 ExpectedHumanRevision=1 提交,
// 旧实现会通过并把人工否定改成 supported。
func TestHumanRefutedBlocksAutoSupported(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	_, rec, jobID := newGuardFixture(t, d, "人工否定")
	// 人工标误报(走生产入口,同一事务转成人工否定)
	if _, _, _, err := d.SetFindingStatusWithNotify(ctx, rec.FindingID, FindingFalsePositive); err != nil {
		t.Fatalf("人工标误报失败: %v", err)
	}
	row, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	if row.TechnicalVerdict != VerdictRefuted || row.HumanRevision == 0 {
		t.Fatalf("人工否定未被记录: verdict=%q humanRev=%d", row.TechnicalVerdict, row.HumanRevision)
	}

	// 模拟一个"在人工决定之后才读到快照"的自动任务:它的期望值恰好等于当前值。
	// The queued job is now retired immediately; assert this first, then inject
	// a late request below the public API to exercise the commit guard as well.
	var oldState string
	if err := d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, jobID).Scan(&oldState); err != nil || oldState != JobSuperseded {
		t.Fatalf("human decision did not retire old work: %s %v", oldState, err)
	}
	if err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var e error
		jobID, e = EnqueueVerificationJobTx(tx, SubjectFinding, rec.FindingID, row.InputRevision, "injected-late-auto-request")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取失败: %v", err)
	}
	conflict, cerr := CommitFindingVerdict(ctx, d, CommitFindingVerdictInput{
		FindingID: rec.FindingID, JobID: job.ID, LeaseGeneration: job.LeaseGeneration,
		ExpectedInputRevision: row.InputRevision, ExpectedVerdictRevision: row.VerdictRevision,
		ExpectedHumanRevision: row.HumanRevision, // 相等!
		Result:                VerdictResult{Decision: VerdictSupported, AcceptedClaim: "自动覆盖人工"},
	})
	if cerr != nil {
		t.Fatalf("不应返回错误: %v", cerr)
	}
	if conflict != CommitSupersededHuman {
		t.Fatalf("got %q, want %q —— 人工否定必须持续优先", conflict, CommitSupersededHuman)
	}
	after, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	if after.TechnicalVerdict != VerdictRefuted {
		t.Fatalf("人工否定被覆盖成了 %q", after.TechnicalVerdict)
	}
}

// TestS3CrossTaskWriteRejected 复现 R8:用任务 B 去追加任务 A 的漏洞。
func TestS3CrossTaskWriteRejected(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	_, recA, _ := newGuardFixture(t, d, "任务A的漏洞")
	before, _, _ := d.FindingVerdictByID(ctx, recA.FindingID)
	tkB, err := d.CreateTask("任务B", "确认漏洞", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	esB := d.Exploration(tkB.ExplorationID)
	_, err = esB.RecordFinding(ctx, RecordFindingInput{
		TaskID: tkB.ID, VulnClass: "sqli", Name: "越权追加", Severity: "high",
		Summary: "跨任务追加", Evidence: "proof", Worker: "test",
		ExistingFindingID: recA.FindingID,
	})
	if err == nil {
		t.Fatal("跨任务追加验证必须被拒绝")
	}
	// 被拒的写入不得改动原始 finding 的输入版本。
	after, _, _ := d.FindingVerdictByID(ctx, recA.FindingID)
	if after.InputRevision != before.InputRevision {
		t.Fatalf("跨任务写入改动了原始输入版本: %d → %d", before.InputRevision, after.InputRevision)
	}
	if after.VerdictRevision != before.VerdictRevision {
		t.Fatalf("跨任务写入改动了判定版本: %d → %d", before.VerdictRevision, after.VerdictRevision)
	}
	_ = errors.Is
}
