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
