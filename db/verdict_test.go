package db

import (
	"context"
	"strings"
	"testing"
)

// --- 判据一致性:Go 判据与 SQL 判据必须表达同一组条件 ---------------------------

// TestVerdictPredicateMatchesGoPredicate 锁定 FindingVerdictEffective 与
// EffectiveVerdictPredicate 的一致性。
//
// 这是"单一读取路径"的机械保证:计数、目标证明、继承、列表、导出都依赖同一
// 判据,一旦两处实现漂移,某条读取路径就会重新把过期/被否定的判定算成确认。
func TestVerdictPredicateMatchesGoPredicate(t *testing.T) {
	pred := EffectiveVerdictPredicate("f")
	for _, want := range []string{
		"f.technical_verdict = 'supported'",
		"f.verdict_revision > 0",
		"f.verdict_input_revision = f.input_revision",
		"f.verdict_policy_version = '" + VerdictPolicyVersion + "'",
	} {
		if !strings.Contains(pred, want) {
			t.Fatalf("SQL 判据缺少条件 %q:\n%s", want, pred)
		}
	}
}

func TestFindingVerdictEffective(t *testing.T) {
	base := VerdictState{
		TechnicalVerdict:     VerdictSupported,
		InputRevision:        3,
		VerdictRevision:      2,
		VerdictInputRevision: 3,
		VerdictPolicyVersion: VerdictPolicyVersion,
	}
	if !FindingVerdictEffective(base) {
		t.Fatal("完整匹配的判定应当有效")
	}
	cases := []struct {
		name  string
		mut   func(*VerdictState)
		valid bool
	}{
		{"未验收", func(v *VerdictState) { v.TechnicalVerdict = VerdictUnverified }, false},
		{"已否定", func(v *VerdictState) { v.TechnicalVerdict = VerdictRefuted }, false},
		{"待重审", func(v *VerdictState) { v.TechnicalVerdict = VerdictNeedsReview }, false},
		{"从未提交", func(v *VerdictState) { v.VerdictRevision = 0 }, false},
		// 关键用例:技术判定仍是 supported,但输入(主张/证据)已经变化 →
		// 判定过期,必须排除。这对应 #47 "新反证写回后仍拿旧结论证明目标"。
		{"证据已变化", func(v *VerdictState) { v.InputRevision = 4 }, false},
		{"策略已升级", func(v *VerdictState) { v.VerdictPolicyVersion = "verdict-policy-v0" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := base
			c.mut(&v)
			if got := FindingVerdictEffective(v); got != c.valid {
				t.Fatalf("FindingVerdictEffective=%v, want %v (state=%+v)", got, c.valid, v)
			}
		})
	}
}

// --- 判定提交的入口守卫(不依赖数据库即可验证的部分) ---------------------------

func TestCommitFindingVerdictRejectsUnknownVerdict(t *testing.T) {
	_, err := CommitFindingVerdict(context.Background(), nil, CommitFindingVerdictInput{
		FindingID: 1,
		Result:    VerdictResult{Decision: "probably"},
	})
	if err == nil || !strings.Contains(err.Error(), "非法判定") {
		t.Fatalf("未知判定必须被拒绝,got %v", err)
	}
}

// TestCommitFindingVerdictPolicyMismatch 验证策略版本不匹配时**在触碰数据库之前**
// 就返回 policy_mismatch。这样修改验收规则后,旧规则下产出的结论不会被当成有效。
func TestCommitFindingVerdictPolicyMismatch(t *testing.T) {
	got, err := CommitFindingVerdict(context.Background(), nil, CommitFindingVerdictInput{
		FindingID:     1,
		PolicyVersion: "verdict-policy-v0",
		Result:        VerdictResult{Decision: VerdictSupported, PolicyVersion: "verdict-policy-v0"},
	})
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if got != CommitPolicyMismatch {
		t.Fatalf("got %q, want %q", got, CommitPolicyMismatch)
	}
}

// TestRecordFindingInputProposalClaim 验证主张为空时不会静默落库。
func TestRecordFindingInputProposalClaim(t *testing.T) {
	in := RecordFindingInput{Summary: "  ", Name: "XSS", VulnClass: "xss"}
	if got := in.proposalClaim(); got == "" {
		t.Fatal("名称/类别亦可构成主张,不应为空")
	}
	empty := RecordFindingInput{}
	if got := empty.proposalClaim(); got != "" {
		t.Fatalf("空输入不应产生主张, got %q", got)
	}
}

// TestClaimDetailKeepsAllFields 迁移不得只保留 summary 而丢弃名称/类别/等级/前提。
func TestClaimDetailKeepsAllFields(t *testing.T) {
	in := RecordFindingInput{
		VulnClass: "sqli", Name: "登录接口布尔注入", Severity: "high",
		Summary: "布尔差异可稳定复现", Preconditions: []string{"需要一个普通用户账号"}, EvidenceNote: "traffic#12",
	}
	d := in.claimDetail()
	if d.VulnClass != "sqli" || d.Name != "登录接口布尔注入" || d.Severity != "high" {
		t.Fatalf("主张要素丢失: %+v", d)
	}
	if len(d.Preconditions) != 1 || d.Preconditions[0] != "需要一个普通用户账号" {
		t.Fatalf("前提丢失: %+v", d)
	}
	if d.EvidenceNote != "traffic#12" {
		t.Fatalf("证据来源丢失: %+v", d)
	}
}

// --- 需要数据库的行为测试(无 DB 时跳过,不得宣称通过) -------------------------

func TestFindingCandidateIsNotEffectiveUntilVerdictCommits(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	tk, err := d.CreateTask("验收闭环测试", "确认漏洞", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	start, err := es.OriginFactID()
	if err != nil || start == 0 {
		t.Fatalf("无法取得起点 fact: %v", err)
	}
	recorded, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, IntentID: 0, VulnClass: "sqli", Name: "候选",
		Severity: "high", Summary: "候选主张", Evidence: "proof", Worker: "w",
	})
	if err != nil {
		t.Fatalf("登记候选失败: %v", err)
	}
	row, ok, err := d.FindingVerdictByID(ctx, recorded.FindingID)
	if err != nil || !ok {
		t.Fatalf("读取判定失败: %v ok=%v", err, ok)
	}
	if FindingVerdictEffective(row.State()) {
		t.Fatal("候选在验收提交前绝不能是有效确认")
	}
	if row.TechnicalVerdict != VerdictUnverified {
		t.Fatalf("候选判定应为 unverified, got %q", row.TechnicalVerdict)
	}
	// 候选写入必须同时产生验收任务与候选事件(同一事务)。
	var jobs, events int
	if err := d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE subject_kind=$1 AND subject_id=$2`,
		SubjectFinding, recorded.FindingID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("应恰好入队 1 个验收任务, got %d", jobs)
	}
	if err := d.QueryRow(`SELECT count(*) FROM verdict_events WHERE finding_id=$1 AND kind=$2`,
		recorded.FindingID, EventCandidateCreated).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("应恰好登记 1 条候选事件, got %d", events)
	}

	// 候选不得写入正式报告。
	if _, err := d.SetFindingReportGated(ctx, recorded.NodeID, "## report", nil); err != ErrVerdictNotSupported {
		t.Fatalf("候选必须被报告门禁拒绝, got %v", err)
	}

	// 提交判定后成为有效确认。
	// 必须按 id 领取:全局 ClaimVerificationJob 可能领到其它用例留下的任务。
	var ownJobID int64
	if err := d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind=$1 AND subject_id=$2`,
		SubjectFinding, recorded.FindingID).Scan(&ownJobID); err != nil {
		t.Fatalf("找不到本用例的验收任务: %v", err)
	}
	job, err := d.ClaimVerificationJobByID(ctx, ownJobID, 60_000_000_000)
	if err != nil || job == nil {
		t.Fatalf("领取验收任务失败: %v", err)
	}
	if _, err := d.PrepareVerificationInput(ctx, job.ID, job.LeaseGeneration); err != nil {
		t.Fatal(err)
	}
	conflict, err := CommitFindingVerdict(ctx, d, CommitFindingVerdictInput{
		FindingID: recorded.FindingID, JobID: job.ID, LeaseGeneration: job.LeaseGeneration,
		ExpectedInputRevision: row.InputRevision, ExpectedVerdictRevision: row.VerdictRevision,
		ExpectedHumanRevision: row.HumanRevision,
		Result:                VerdictResult{Decision: VerdictSupported, AcceptedClaim: "已证实"},
	})
	if err != nil || conflict != CommitOK {
		t.Fatalf("判定提交失败: conflict=%q err=%v", conflict, err)
	}
	row2, _, _ := d.FindingVerdictByID(ctx, recorded.FindingID)
	if !FindingVerdictEffective(row2.State()) {
		t.Fatalf("提交后应为有效确认: %+v", row2.State())
	}
	// Effective verdict grants a persistent report task, not an unbound write.
	if _, _, err := d.FanOutVerdictEvents(ctx, 100); err != nil {
		t.Fatal(err)
	}
	reportJob, err := d.ClaimEventJob(ctx, EventJobReportRun, 60_000_000_000)
	if err != nil || reportJob == nil {
		t.Fatalf("report claim: %v", err)
	}
	reportRun, err := d.PrepareReportRun(ctx, reportJob.ID, reportJob.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordReportExecutionInput(ctx, reportRun, &ReportExecutionInput{Snapshot: reportRun.Snapshot, SystemPrompt: "local test contract"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetFindingReportGated(WithReportRun(ctx, reportRun), recorded.NodeID, "## report", nil); err != nil {
		t.Fatalf("通过验收后应允许写报告: %v", err)
	}

	// 新增证据必须让判定过期 → 报告门禁重新关闭。
	es2 := d.Exploration(tk.ExplorationID)
	if _, err := es2.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, VulnClass: "sqli", Name: "候选", Severity: "high",
		Summary: "S3 追加验证", Evidence: "proof-2", Worker: "w",
		ExistingFindingID: recorded.FindingID,
	}); err != nil {
		t.Fatalf("追加验证失败: %v", err)
	}
	row3, _, _ := d.FindingVerdictByID(ctx, recorded.FindingID)
	if FindingVerdictEffective(row3.State()) {
		t.Fatal("新增证据后旧判定必须过期")
	}
	if _, err := d.SetFindingReportGated(ctx, recorded.NodeID, "## stale", nil); err != ErrVerdictNotSupported {
		t.Fatalf("证据变化后必须拒绝旧报告, got %v", err)
	}
}
