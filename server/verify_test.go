package server

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// ============================================================================
// R1 端到端回归:验收执行者必须真的把候选/目标从 unverified 推到判定,
// 而不是只有定义没有调用方。测试注入假验收器,不触及真实模型网关。
// ============================================================================

// fakeVerifier 是可控的验收器实现。
type fakeVerifier struct {
	result db.VerdictResult
	err    error
	calls  int
	last   *db.EvidenceBundle
}

func (f *fakeVerifier) Verify(_ context.Context, b *db.EvidenceBundle) (db.VerdictResult, error) {
	f.calls++
	f.last = b
	return f.result, f.err
}

func openTestPG(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	return d
}

// TestVerifierDrivesCandidateToSupportedAndQueuesReport 证明 R1 闭环:
// 候选 → 领取 → 证据组装 → 验收 → 判定提交 → 事件 → 扇出出报告任务。
func TestVerifierDrivesCandidateToSupportedAndQueuesReport(t *testing.T) {
	d := openTestPG(t)
	defer d.Close()
	ctx := context.Background()
	// 测试隔离:先排空历史遗留的未处理事件,避免其它用例留下的积压影响本用例
	// 对"扇出是否产出报告任务"的断言。
	if _, _, err := d.FanOutVerdictEvents(ctx, 10000); err != nil {
		t.Fatalf("清理遗留事件失败: %v", err)
	}

	tk, err := d.CreateTask("R1 验收闭环", "确认漏洞", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	rec, err := es.RecordFinding(ctx, db.RecordFindingInput{
		TaskID: tk.ID, VulnClass: "sqli", Name: "R1", Severity: "high",
		Summary: "登录接口布尔注入可稳定复现", Evidence: "proof", Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 候选阶段绝不能已经算确认。
	row, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	if db.FindingVerdictEffective(row.State()) {
		t.Fatal("候选在接受验收前不应有效")
	}

	var jobID int64
	if err := d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind=$1 AND subject_id=$2`,
		db.SubjectFinding, rec.FindingID).Scan(&jobID); err != nil {
		t.Fatalf("候选必须入队验收任务: %v", err)
	}
	job, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取验收任务失败: %v", err)
	}

	fv := &fakeVerifier{result: db.VerdictResult{
		Decision: db.VerdictSupported, AcceptedClaim: "登录接口存在可复现的布尔注入",
		SeverityRationale: "可读取他人数据", PolicyVersion: db.VerdictPolicyVersion,
	}}
	if err := processVerificationJobWith(ctx, d, fv, job); err != nil {
		t.Fatalf("验收执行失败: %v", err)
	}
	if fv.calls != 1 {
		t.Fatalf("验收器应被调用一次, got %d", fv.calls)
	}
	// 证据包必须包含主张,而不是空清单。
	if fv.last == nil || fv.last.Claim == "" {
		t.Fatal("证据包缺少主张")
	}
	if len(fv.last.Refs) == 0 {
		t.Fatal("证据包缺少主张修订/证据引用")
	}

	after, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	if !db.FindingVerdictEffective(after.State()) {
		t.Fatalf("验收通过后应为有效确认: %+v", after.State())
	}
	if after.VerdictRevision != 1 {
		t.Fatalf("verdict_revision 应为 1, got %d", after.VerdictRevision)
	}
	if after.AcceptedClaim == "" {
		t.Fatal("accepted_claim 应被写入")
	}

	// 事件扇出后必须出现报告任务(证明"验收通过 → 报告"的入口真的接通)。
	if _, _, err := d.FanOutVerdictEvents(ctx, 20); err != nil {
		t.Fatalf("扇出失败: %v", err)
	}
	var reportJobs int
	if err := d.QueryRow(`SELECT count(*) FROM event_jobs WHERE job_kind=$1 AND payload->>'finding_id'=$2`,
		db.EventJobReportRun, itoa(rec.FindingID)).Scan(&reportJobs); err != nil {
		t.Fatal(err)
	}
	if reportJobs != 1 {
		t.Fatalf("验收通过后应恰好产生 1 个报告任务, got %d", reportJobs)
	}
	// 重复扇出不得产生第二个报告任务(幂等键含 finding_revision)。
	if _, _, err := d.FanOutVerdictEvents(ctx, 20); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM event_jobs WHERE job_kind=$1 AND payload->>'finding_id'=$2`,
		db.EventJobReportRun, itoa(rec.FindingID)).Scan(&reportJobs); err != nil {
		t.Fatal(err)
	}
	if reportJobs != 1 {
		t.Fatalf("重复扇出不应新增报告任务, got %d", reportJobs)
	}
}

// TestVerifierFailureKeepsUnverifiedAndRequeues 证明"验收器失败 ≠ 漏洞被否定"。
func TestVerifierFailureKeepsUnverifiedAndRequeues(t *testing.T) {
	d := openTestPG(t)
	defer d.Close()
	ctx := context.Background()

	tk, err := d.CreateTask("R1 失败恢复", "确认漏洞", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	rec, err := es.RecordFinding(ctx, db.RecordFindingInput{
		TaskID: tk.ID, VulnClass: "xss", Name: "R1b", Severity: "low",
		Summary: "候选主张", Evidence: "proof", Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind=$1 AND subject_id=$2`,
		db.SubjectFinding, rec.FindingID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取失败: %v", err)
	}
	fv := &fakeVerifier{err: errors.New("模型超时")}
	if err := processVerificationJobWith(ctx, d, fv, job); err == nil {
		t.Fatal("验收器失败时执行者应返回错误以便重试")
	}
	// 模拟调度器的失败处理。
	if err := d.FailVerificationJob(ctx, job.ID, job.LeaseGeneration, "模型超时", 3); err != nil {
		t.Fatal(err)
	}
	row, _, _ := d.FindingVerdictByID(ctx, rec.FindingID)
	if row.TechnicalVerdict != db.VerdictUnverified {
		t.Fatalf("验收器失败不得落成 %q(只能保持未验收)", row.TechnicalVerdict)
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, jobID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != db.JobQueued {
		t.Fatalf("失败后应回到队列等待重试, got %q", state)
	}
}

// TestVerifierDrivesGoalToMet 证明目标验收执行者也接通了。
func TestVerifierDrivesGoalToMet(t *testing.T) {
	d := openTestPG(t)
	defer d.Close()
	ctx := context.Background()

	tk, err := d.CreateTask("R1 目标验收", "产出攻击面清单", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	goalID, err := es.AddGoal(map[string]any{"text": "产出可核验的攻击面清单"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := es.AddNode(db.KindFact, map[string]any{"summary": "攻击面清单", "detail": "本地夹具：example.test /api，已核验服务与路径"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.SubmitGoalEvidence(ctx, goalID, factID, "清单包含要求的服务与路径"); err != nil {
		t.Fatal(err)
	}
	_, submitted, err := es.GoalEvaluationState(goalID)
	if err != nil || !submitted {
		t.Fatalf("目标应处于 submitted 等待状态: %v submitted=%v", err, submitted)
	}

	var jobID int64
	if err := d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind=$1 AND subject_id=$2`,
		db.SubjectGoal, goalID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimVerificationJobByID(ctx, jobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取目标验收任务失败: %v", err)
	}
	fv := &fakeVerifier{result: db.VerdictResult{
		Decision: db.VerdictSupported, AcceptedClaim: "清单完整可核验",
		PolicyVersion: db.VerdictPolicyVersion,
	}}
	if err := processVerificationJobWith(ctx, d, fv, job); err != nil {
		t.Fatalf("目标验收执行失败: %v", err)
	}
	if fv.last == nil || fv.last.GoalText == "" {
		t.Fatal("目标证据包缺少目标要求文本")
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, goalID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "met" {
		t.Fatalf("验收通过后目标应为 met, got %q", state)
	}
}

// itoa 是测试里的极小工具,避免为一行引入 strconv 依赖。
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var _ agent.Verifier = (*fakeVerifier)(nil)
