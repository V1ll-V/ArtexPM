package db

import (
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestTaskModeDefaultsAndValidation(t *testing.T) {
	for _, tc := range []struct {
		mode, challenge, wantMode, wantChallenge string
		valid                                    bool
	}{
		{"", "", "pentest", "", true}, {"ctf", "", "ctf", "auto", true},
		{"ctf", "pwn", "ctf", "pwn", true}, {"ctf", "reverse", "ctf", "reverse", true},
		{"ctf", "crypto", "ctf", "crypto", true}, {"ctf", "misc", "ctf", "misc", true},
		{"pentest", "pwn", "", "", false}, {"unknown", "", "", "", false}, {"ctf", "unknown", "", "", false},
	} {
		mode, challenge, err := NormalizeTaskMode(tc.mode, tc.challenge)
		if (err == nil) != tc.valid || mode != tc.wantMode || challenge != tc.wantChallenge {
			t.Fatalf("%+v => %q %q %v", tc, mode, challenge, err)
		}
	}
}

func TestCTFGoalRequiresConfirmationAndReopensOnRevocation(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	es, goal, fact, _ := goalInputFixture(t, d)
	var task int64
	if err = d.QueryRow(`UPDATE tasks SET mode='ctf',challenge_type='pwn' WHERE exploration_id=$1 RETURNING id`, es.ID()).Scan(&task); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	if err = d.SyncCTFInput(t.Context(), task, hash); err != nil {
		t.Fatal(err)
	}
	commit := func() (string, error) {
		t.Helper()
		id, err := es.SubmitGoalEvidence(t.Context(), goal, fact, "synthetic CTF proof")
		if err != nil {
			t.Fatal(err)
		}
		job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
		if err != nil || job == nil {
			t.Fatalf("claim: %+v %v", job, err)
		}
		if _, err = d.PrepareVerificationInput(t.Context(), job.ID, job.LeaseGeneration); err != nil {
			t.Fatal(err)
		}
		return es.CommitGoalEvaluation(t.Context(), job.ID, job.LeaseGeneration, "met")
	}
	if _, err = commit(); err == nil || !strings.Contains(err.Error(), "答案确认") {
		t.Fatalf("unconfirmed CTF goal accepted: %v", err)
	}
	e := &CTFExecution{ID: uuid.NewString(), TaskID: task, InputHash: hash, Command: "synthetic test", StartedAt: time.Now()}
	if err = d.SaveCTFExecution(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	id, err := d.AddCTFCandidate(t.Context(), task, e.ID, "flag{goal_gate}")
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := d.CTFCandidates(t.Context(), task)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates: %+v %v", candidates, err)
	}
	accepted, err := d.DecideCTFCandidate(t.Context(), task, id, candidates[0].Revision, "accepted", "test confirmation")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := commit(); err != nil || result != CommitOK {
		t.Fatalf("confirmed CTF goal: %s %v", result, err)
	}
	if _, err = d.DecideCTFCandidate(t.Context(), task, id, accepted.Revision, "rejected", "test revocation"); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, goal).Scan(&state); err != nil || state != "open" {
		t.Fatalf("revoked goal state: %s %v", state, err)
	}
}

func TestTaskModePersistsWithoutChangingPentestDefaults(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	for _, opts := range []TaskCreateOptions{{}, {Mode: "ctf", ChallengeType: "pwn"}, {Mode: "ctf", ChallengeType: "reverse"}} {
		task, err := d.CreateTaskWithOptions("mode test", "goal", opts)
		if err != nil {
			t.Fatal(err)
		}
		defer d.DeleteTask(task.ID)
		got, err := d.GetTask(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		if opts.Mode == "ctf" {
			if got.Mode != "ctf" || got.ChallengeType != opts.ChallengeType || got.CoverageEnabled {
				t.Fatalf("CTF metadata lost: %+v", got)
			}
		} else if got.Mode != "pentest" || !got.CoverageEnabled {
			t.Fatalf("legacy defaults changed: %+v", got)
		}
	}
}

func TestTaskModeArchiveRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	if err = d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	batch := uuid.NewString()
	task, err := d.CreateTaskWithOptions("CTF archive", "goal", TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn", AttachmentBatchID: batch})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) }()
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	a, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimTaskArchiveJob(t.Context())
	if err != nil || job == nil || job.ID != a.ID {
		t.Fatalf("claim: %+v %v", job, err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchive(a.ID, snapshot, "/tmp/ctf-test.tar.zst", "abc", 100, 50); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(a.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	restored, err := d.GetTask(task.ID)
	if err != nil || restored == nil || restored.Mode != "ctf" || restored.ChallengeType != "pwn" || restored.AttachmentBatchID != batch {
		t.Fatalf("CTF archive metadata: %+v %v", restored, err)
	}
}

func TestResolveCTFVerifyModeAutoDetection(t *testing.T) {
	cases := []struct {
		name, raw, desc, goal, want string
	}{
		{
			name: "explicit_flag",
			raw:  "flag", desc: "无需提交 flag", goal: "漏洞利用证明",
			want: CTFVerifyFlag,
		},
		{
			name: "persist_no_flag",
			raw:  "auto",
			desc: "Memo — Make your changes survive a reset.",
			goal: "本题无需提交 flag，完成持久化写入并由平台验证漏洞利用证明",
			want: CTFVerifyExploitProof,
		},
		{
			name: "deface_verify_exploit",
			raw:  "",
			desc: `Change the portal's home-page banner away from its default. There is no flag string to submit — press "Verify exploit" and the platform's trusted judge sidecar will confirm the defacement.`,
			goal: "无需提交 flag —— 平台会在沙箱里验证你的利用。",
			want: CTFVerifyExploitProof,
		},
		{
			name: "composite_flag_then_exploit_screenshot",
			raw:  "auto",
			desc: `flag DYNAMIC: The service token Opsboard leaks through its debug surface — the canonical FLAG{...} string. root 漏洞利用证明: Use what you recovered to grant a non-admin staff account operator rights. There is no flag string to submit for this step — the platform's trusted judge sidecar confirms the new operator.`,
			goal: "无需提交 flag —— 平台会在沙箱里验证你的利用。",
			want: CTFVerifyFlagAndExploit,
		},
		{
			name: "composite_chinese_phrase",
			raw:  "auto",
			desc: "先找到flag再进行漏洞利用",
			goal: "拿到 flag 后完成提权验证",
			want: CTFVerifyFlagAndExploit,
		},
		{
			name: "standard_exploit_to_get_flag",
			raw:  "auto",
			desc: "利用 SQL 注入漏洞读取管理员账号密码与 flag",
			goal: "获取 flag{...}",
			want: CTFVerifyFlag,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveCTFVerifyMode(tc.raw, tc.desc, tc.goal); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := NormalizeCTFVerifyMode("ctf", "bad_mode", "", ""); err == nil {
		t.Fatal("expected error for invalid verify mode")
	}
}

func TestExploitProofAndCompositeGoalGatingAndCompletion(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}

	// 1. exploit_proof task blocks unverified goal, then allows after proof confirmation.
	es, goal, fact, _ := goalInputFixture(t, d)
	var epTask int64
	if err = d.QueryRow(`UPDATE tasks SET mode='ctf',challenge_type='web',ctf_verify_mode='exploit_proof' WHERE exploration_id=$1 RETURNING id`, es.ID()).Scan(&epTask); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("b", 64)
	if err = d.SyncCTFInput(t.Context(), epTask, hash); err != nil {
		t.Fatal(err)
	}
	commitGoal := func(s *ExplorationStore, gID, fID int64) (string, error) {
		id, err := s.SubmitGoalEvidence(t.Context(), gID, fID, "proof test")
		if err != nil {
			t.Fatal(err)
		}
		job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
		if err != nil || job == nil {
			t.Fatalf("claim: %+v %v", job, err)
		}
		if _, err = d.PrepareVerificationInput(t.Context(), job.ID, job.LeaseGeneration); err != nil {
			t.Fatal(err)
		}
		return s.CommitGoalEvaluation(t.Context(), job.ID, job.LeaseGeneration, "met")
	}
	if _, err = commitGoal(es, goal, fact); err == nil || !strings.Contains(err.Error(), "漏洞利用证明") {
		t.Fatalf("expected exploit_proof gating error, got %v", err)
	}
	e1 := &CTFExecution{ID: uuid.NewString(), TaskID: epTask, InputHash: hash, Command: "curl -X POST ...", StartedAt: time.Now()}
	if err = d.SaveCTFExecution(t.Context(), e1); err != nil {
		t.Fatal(err)
	}
	proofID, err := d.AddCTFExploitProofCandidate(t.Context(), epTask, e1.ID, "写入持久化文件成功", "GET 读取确认存在")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := d.PendingCTFSubmission(t.Context(), epTask)
	if err != nil || pending == nil || pending.Kind != CTFCandidateExploitProof {
		t.Fatalf("expected pending exploit_proof candidate, got %+v %v", pending, err)
	}
	if _, err = d.DecideCTFCandidate(t.Context(), epTask, proofID, pending.Revision, "accepted", "平台验证通过"); err != nil {
		t.Fatal(err)
	}
	if res, err := commitGoal(es, goal, fact); err != nil || res != CommitOK {
		t.Fatalf("expected exploit_proof goal commit ok, got %s %v", res, err)
	}

	// 2. flag_and_exploit requires BOTH flag and exploit_proof before GoalMet.
	es2, goal2, fact2, _ := goalInputFixture(t, d)
	var compTask int64
	if err = d.QueryRow(`UPDATE tasks SET mode='ctf',challenge_type='web',ctf_verify_mode='flag_and_exploit' WHERE exploration_id=$1 RETURNING id`, es2.ID()).Scan(&compTask); err != nil {
		t.Fatal(err)
	}
	if err = d.SyncCTFInput(t.Context(), compTask, hash); err != nil {
		t.Fatal(err)
	}
	e2 := &CTFExecution{ID: uuid.NewString(), TaskID: compTask, InputHash: hash, Command: "curl debug", StartedAt: time.Now()}
	if err = d.SaveCTFExecution(t.Context(), e2); err != nil {
		t.Fatal(err)
	}
	fCandID, err := d.AddCTFCandidate(t.Context(), compTask, e2.ID, "FLAG{step1}")
	if err != nil {
		t.Fatal(err)
	}
	cands2, _ := d.CTFCandidates(t.Context(), compTask)
	if _, err = d.DecideCTFCandidate(t.Context(), compTask, fCandID, cands2[0].Revision, "accepted", "stage1 flag ok", false); err != nil {
		t.Fatal(err)
	}
	if _, err = commitGoal(es2, goal2, fact2); err == nil || !strings.Contains(err.Error(), "复合验收") {
		t.Fatalf("expected composite gate after flag only, got %v", err)
	}
	e3 := &CTFExecution{ID: uuid.NewString(), TaskID: compTask, InputHash: hash, Command: "curl promote", StartedAt: time.Now()}
	if err = d.SaveCTFExecution(t.Context(), e3); err != nil {
		t.Fatal(err)
	}
	pCandID, err := d.AddCTFExploitProofCandidate(t.Context(), compTask, e3.ID, "提权 operator 成功", "uid=2 granted")
	if err != nil {
		t.Fatal(err)
	}
	cands2, _ = d.CTFCandidates(t.Context(), compTask)
	if _, err = d.DecideCTFCandidate(t.Context(), compTask, pCandID, cands2[0].Revision, "accepted", "stage2 judge ok", true); err != nil {
		t.Fatal(err)
	}
	gotComp, _ := d.GetTask(compTask)
	if gotComp.Status != "done" {
		t.Fatalf("expected composite task done after stage2 finish, got %+v", gotComp)
	}

	// 3. CompleteCTFExploitProof works even with 0 executions.
	noExecTask, err := d.CreateTaskWithOptions("no exec", "无需提交 flag —— 漏洞利用证明", TaskCreateOptions{Mode: "ctf", ChallengeType: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(noExecTask.ID)
	if err = d.SyncCTFInput(t.Context(), noExecTask.ID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CompleteCTFExploitProof(t.Context(), noExecTask.ID, "", "人工验证通过", "judge confirmed"); err != nil {
		t.Fatalf("CompleteCTFExploitProof 0-exec failed: %v", err)
	}
	gotNoExec, _ := d.GetTask(noExecTask.ID)
	if gotNoExec.Status != "done" {
		t.Fatalf("expected 0-exec exploit proof task done, got %+v", gotNoExec)
	}
}
