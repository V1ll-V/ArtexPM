package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func privateVerificationInputDB(t *testing.T) (*DB, error) {
	t.Helper()
	dsn := testDSN(t)
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { root.Close() })
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	schema := "verification_input_" + hex.EncodeToString(random)
	if _, err = root.Exec(`CREATE SCHEMA ` + schema); err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if _, err := root.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	uri, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	values := uri.Query()
	values.Set("search_path", schema)
	uri.RawQuery = values.Encode()
	d, err := Open(uri.String())
	if err == nil {
		t.Cleanup(func() { d.Close() })
	}
	return d, err
}

func TestGoalSubmissionFreezesProofAndDeduplicates(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	es, g, f, old := goalInputFixture(t, d)
	// A changed reason is part of the submitted argument and gets its own input.
	id, err := es.SubmitGoalEvidence(t.Context(), g, f, "CHECK_REQUIREMENT_AGAIN")
	if err != nil {
		t.Fatal(err)
	}
	again, err := es.SubmitGoalEvidence(t.Context(), g, f, "CHECK_REQUIREMENT_AGAIN")
	if err != nil {
		t.Fatal(err)
	}
	if id != again {
		t.Fatal("identical proof produced a duplicate evaluation")
	}
	var revision int64
	var raw []byte
	var hash, state string
	if err = d.QueryRow(`SELECT input_revision,input_manifest,input_hash FROM verification_jobs WHERE id=$1`, id).Scan(&revision, &raw, &hash); err != nil {
		t.Fatal(err)
	}
	if revision <= 0 || len(hash) != 64 || !strings.Contains(string(raw), "FACT_PROOF") || !strings.Contains(string(raw), "CHECK_REQUIREMENT_AGAIN") {
		t.Fatalf("incomplete frozen goal input: revision=%d hash=%s", revision, hash)
	}
	if err = d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, old.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != JobSuperseded {
		t.Fatalf("old request should be superseded, got %s", state)
	}
}

func TestGoalEvaluationFencesLeaseAndOwnership(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, name := range []string{"expired", "generation", "wrong_exploration", "deleted", "dismissed", "new_edge"} {
		t.Run(name, func(t *testing.T) {
			es, g, f, j := goalInputFixture(t, d)
			want := CommitStale
			switch name {
			case "expired":
				_, err = d.Exec(`UPDATE verification_jobs SET lease_until=now()-interval '1 second' WHERE id=$1`, j.ID)
				want = CommitLeaseLost
			case "generation":
				j.LeaseGeneration--
				want = CommitLeaseLost
			case "wrong_exploration":
				tk, e := d.CreateTask("other exploration", "other", nil, 0, 0)
				if e != nil {
					t.Fatal(e)
				}
				es = d.Exploration(tk.ExplorationID)
				want = CommitSubjectMismatch
			case "deleted":
				err = es.DeleteGoal(g)
			case "dismissed":
				err = es.SetNodeState(f, "dismissed")
			case "new_edge":
				n, e := es.AddNode(KindFact, map[string]any{"summary": "extra", "detail": "additional observation"}, 0, "confirmed", "test", nil)
				if e != nil {
					t.Fatal(e)
				}
				err = es.Link(n, RelProves, g)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, e := es.CommitGoalEvaluation(t.Context(), j.ID, j.LeaseGeneration, "met")
			if e != nil {
				t.Fatal(e)
			}
			if got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}

func TestGoalSubmissionRejectsUnrelatedProofAtomically(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a, err := d.CreateTask("owner", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.CreateTask("unrelated", "proof", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(a.ExplorationID)
	g, err := es.AddGoal(map[string]any{"text": "owner requirement"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	f, err := d.Exploration(b.ExplorationID).AddNode(KindFact, map[string]any{"summary": "unrelated", "detail": "not authorized for owner"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = es.SubmitGoalEvidence(t.Context(), g, f, "unrelated"); err == nil {
		t.Fatal("unrelated proof accepted")
	}
	var n int
	if err = d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE dst_id=$1 AND rel='proves'`, g).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("rejected request left an edge")
	}
	if err = d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE subject_kind='goal' AND subject_id=$1`, g).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("rejected request left a job")
	}
}

func TestFindingCommitRequiresNonemptyAcceptedScope(t *testing.T) {
	if _, err := CommitFindingVerdict(t.Context(), nil, CommitFindingVerdictInput{Result: VerdictResult{Decision: VerdictSupported, AcceptedClaim: " "}}); err == nil {
		t.Fatal("trusted commit boundary accepted empty scope")
	}
}

func TestFrozenFindingInputRejectsClaimMutation(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	_, rec, id := newGuardFixture(t, d, "frozen manifest")
	job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	b, err := d.PrepareVerificationInput(t.Context(), job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	b.Claim = "MUTATED_AFTER_FREEZE"
	if _, err = d.RecordVerificationExecutionInput(t.Context(), job.ID, job.LeaseGeneration, b); err != ErrVerificationInputStale {
		t.Fatalf("mutated claim accepted: %v", err)
	}
	// The original frozen input remains available and serializable.
	b, err = d.PrepareVerificationInput(t.Context(), job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if b.SubjectID != rec.FindingID || b.Claim == "MUTATED_AFTER_FREEZE" {
		t.Fatal("frozen manifest was replaced")
	}
}

func TestGoalEvaluationRejectsConcurrentGoalEdit(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	es, g, _, job := goalInputFixture(t, d)
	edit, err := d.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer edit.Rollback()
	if _, err = edit.Exec(`UPDATE exploration_nodes SET payload=payload || '{"text":"EDIT_WINS"}'::jsonb,content_version=content_version+1 WHERE id=$1`, g); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		conflict string
		err      error
	}
	done := make(chan outcome, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		c, e := es.CommitGoalEvaluation(t.Context(), job.ID, job.LeaseGeneration, "met")
		done <- outcome{c, e}
	}()
	<-started
	// The edited row is locked before the evaluator starts; no timing/sleep can
	// allow it to validate the old payload and overwrite the new requirement.
	if err = edit.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.conflict != CommitStale {
			t.Fatalf("old evaluation survived edit: %+v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("goal edit/evaluation deadlocked")
	}
}

func TestFindingBundlePreservesEvidenceAndDetail(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tk, err := d.CreateTask(t.Name(), "local proof", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := d.Exploration(tk.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{
		TaskID: tk.ID, Summary: "candidate", VulnClass: "test", Name: "test", Severity: "low",
		Evidence: "NON_HTTP_PROOF", EvidenceNote: "NOTE_MARKER", Preconditions: []string{"OWN_ACCOUNT"}, Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, accepted := range []string{"", "已接受的有限范围"} {
		if _, err := d.Exec(`UPDATE findings SET accepted_claim=$2 WHERE id=$1`, rec.FindingID, accepted); err != nil {
			t.Fatal(err)
		}
		b, err := d.BuildFindingBundle(t.Context(), rec.FindingID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(b.Detail) {
			t.Error("detail must contain proposed_detail JSON")
		}
		if strings.Contains(b.Claim, "OWN_ACCOUNT") {
			t.Error("candidate details mislabelled as accepted claim")
		}
		for _, marker := range []string{"NON_HTTP_PROOF", "NOTE_MARKER", "OWN_ACCOUNT"} {
			if !strings.Contains(string(raw), marker) {
				t.Errorf("bundle lost %s", marker)
			}
		}
	}
}

func goalInputFixture(t *testing.T, d *DB) (*ExplorationStore, int64, int64, *VerificationJob) {
	t.Helper()
	tk, err := d.CreateTask(t.Name(), "deliver local inventory", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	goal, err := es.AddGoal(map[string]any{"text": "ORIGINAL_REQUIREMENT"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	fact, err := es.AddNode(KindFact, map[string]any{"summary": "inventory", "detail": "FACT_PROOF"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(fact, RelProves, goal); err != nil {
		t.Fatal(err)
	}
	jid, err := es.EnqueueGoalEvaluation(goal, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, err := d.ClaimVerificationJobByID(t.Context(), jid, time.Minute)
	if err != nil || j == nil {
		t.Fatalf("claim: %v", err)
	}
	return es, goal, fact, j
}

func TestGoalEvaluationRejectsChangedInputAndPolicy(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, tc := range []struct {
		name, want string
		change     func(*ExplorationStore, int64, int64, *VerificationJob) error
	}{
		{"requirement", CommitStale, func(es *ExplorationStore, g, f int64, j *VerificationJob) error {
			return es.UpdateGoalPayload(g, "CHANGED_REQUIREMENT", "")
		}},
		{"fact", CommitStale, func(es *ExplorationStore, g, f int64, j *VerificationJob) error {
			_, err := d.Exec(`UPDATE exploration_nodes SET payload=payload || '{"detail":"CHANGED_PROOF"}'::jsonb WHERE id=$1`, f)
			return err
		}},
		{"edge", CommitStale, func(es *ExplorationStore, g, f int64, j *VerificationJob) error {
			_, err := d.Exec(`DELETE FROM exploration_edges WHERE src_id=$1 AND dst_id=$2 AND rel='proves'`, f, g)
			return err
		}},
		{"policy", CommitPolicyMismatch, func(es *ExplorationStore, g, f int64, j *VerificationJob) error {
			_, err := d.Exec(`UPDATE verification_jobs SET policy_version='obsolete-policy' WHERE id=$1`, j.ID)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es, g, f, j := goalInputFixture(t, d)
			if err := tc.change(es, g, f, j); err != nil {
				t.Fatal(err)
			}
			got, err := es.CommitGoalEvaluation(context.Background(), j.ID, j.LeaseGeneration, "met")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			var state string
			if err := d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, g).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state == "met" {
				t.Fatal("stale result marked goal met")
			}
		})
	}
}
