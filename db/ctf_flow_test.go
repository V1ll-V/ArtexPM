package db

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCTFSubmissionWaitAndRejectedOutputDeduplication(t *testing.T) {
	pg, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("local", "flag", TaskCreateOptions{Mode: "ctf"})
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.SyncCTFInput(t.Context(), task.ID, "input-a"); err != nil {
		t.Fatal(err)
	}
	add := func() int64 {
		t.Helper()
		e := &CTFExecution{ID: uuid.NewString(), TaskID: task.ID, InputHash: "input-a", StartedAt: time.Now()}
		if err := pg.SaveCTFExecution(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		id, err := pg.AddCTFOutputCandidate(t.Context(), task.ID, e.ID, "flag{local}")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	add()
	add()
	pending, err := pg.PendingCTFSubmission(t.Context(), task.ID)
	if err != nil || pending == nil {
		t.Fatal(pending, err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, pending.ID, pending.Revision, "rejected", "wrong answer"); err != nil {
		t.Fatal(err)
	}
	if pending, err = pg.PendingCTFSubmission(t.Context(), task.ID); err != nil || pending != nil {
		t.Fatal("duplicate still blocks", pending, err)
	}
	if id := add(); id != 0 {
		t.Fatal("rejected output created another wait", id)
	}
	if _, err = pg.Exec(`UPDATE tasks SET mode='pentest' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`UPDATE ctf_candidates SET state='candidate' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err = pg.PendingCTFSubmission(t.Context(), task.ID); err != nil || pending != nil {
		t.Fatal("generic task blocked by CTF evidence", err)
	}
	if _, err = pg.Exec(`UPDATE tasks SET mode='ctf',ctf_input_hash='input-b' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if pending, err = pg.PendingCTFSubmission(t.Context(), task.ID); err != nil || pending != nil {
		t.Fatal("old input blocked new task input", err)
	}
}

func TestSaveCTFExecutionStripsNULBytes(t *testing.T) {
	pg, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("nul-clean", "flag", TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.SyncCTFInput(t.Context(), task.ID, "input-nul"); err != nil {
		t.Fatal(err)
	}
	e := &CTFExecution{
		ID:            uuid.NewString(),
		TaskID:        task.ID,
		IntentID:      1,
		InputHash:     "input-nul",
		Command:       "python3 -c 'print(b\"abc\\x00def\")'\x00",
		StdoutExcerpt: "leak:\x00deadbeef\x00",
		StderrExcerpt: "warn:\x00ok",
		Error:         "err:\x00tail",
		Files:         json.RawMessage(`[{"name":"exp\u0000.py"}]`),
		Environment:   json.RawMessage(`{"tag":"v\u00001"}`),
		StartedAt:     time.Now().UTC(),
	}
	if err = pg.SaveCTFExecution(t.Context(), e); err != nil {
		t.Fatalf("SaveCTFExecution with NUL bytes failed: %v", err)
	}
}

func TestClaimIntentGuardedSerializesPwnExploit(t *testing.T) {
	pg, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("pwn-mutex", "flag", TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	es := pg.Exploration(task.ExplorationID)
	exp1, err := es.AddIntent(map[string]any{"summary": "exploit 1", "phase": "exploit"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	exp2, err := es.AddIntent(map[string]any{"summary": "exploit 2", "phase": "exploit"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := es.AddIntent(map[string]any{"summary": "recon 1", "phase": "recon"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pg.ClaimIntentGuarded(t.Context(), task.ID, exp1, "work#1")
	if err != nil || !ok {
		t.Fatalf("claim first exploit failed: ok=%v err=%v", ok, err)
	}
	// 第二条 exploit 在第一条 running 时必须被互斥拦截，而 recon 允许并发认领。
	ok2, err := pg.ClaimIntentGuarded(t.Context(), task.ID, exp2, "work#2")
	if err != nil || ok2 {
		t.Fatalf("expected second pwn exploit claim blocked while first running, got ok=%v err=%v", ok2, err)
	}
	okRec, err := pg.ClaimIntentGuarded(t.Context(), task.ID, rec1, "work#3")
	if err != nil || !okRec {
		t.Fatalf("expected recon intent still claimable, got ok=%v err=%v", okRec, err)
	}
	// 第一条转 paused 时同样互斥（防止劫持人工对话中的主攻）；直到 stopped 才放行第二条。
	if _, err = pg.Exec(`UPDATE exploration_nodes SET state='paused' WHERE id=$1`, exp1); err != nil {
		t.Fatal(err)
	}
	okPaused, err := pg.ClaimIntentGuarded(t.Context(), task.ID, exp2, "work#2")
	if err != nil || okPaused {
		t.Fatalf("expected second exploit blocked while first paused, got ok=%v err=%v", okPaused, err)
	}
	if _, err = pg.Exec(`UPDATE exploration_nodes SET state='stopped' WHERE id=$1`, exp1); err != nil {
		t.Fatal(err)
	}
	okAfter, err := pg.ClaimIntentGuarded(t.Context(), task.ID, exp2, "work#2")
	if err != nil || !okAfter {
		t.Fatalf("expected second exploit claimable after first stopped, got ok=%v err=%v", okAfter, err)
	}
}
