package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// The queue scans globally, so this test needs its own schema rather than
// modifying/superseding jobs belonging to other tests on the shared database.
func privateVerificationDB(t *testing.T) *db.DB {
	t.Helper()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("ARTEX_PG_DSN required for isolated queue test")
	}
	root := openTestPG(t)
	t.Cleanup(func() { root.Close() })
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "verification_test_" + hex.EncodeToString(random)
	if _, err := root.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := root.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := uri.Query()
	query.Set("search_path", schema)
	uri.RawQuery = query.Encode()
	d, err := db.Open(uri.String())
	if err != nil {
		t.Fatal("open private verification schema: " + err.Error())
	}
	t.Cleanup(func() { d.Close() })
	return d
}

type blockingVerification struct{ started chan time.Time }

func TestGoalVerificationContinuesWithOptionalFindingAutomationDisabled(t *testing.T) {
	d := privateVerificationDB(t)
	task, err := d.CreateTask(t.Name(), "deliver a local inventory", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(task.ExplorationID)
	goal, err := es.AddGoal(map[string]any{"text": "deliver a local inventory"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	fact, err := es.AddNode(db.KindFact, map[string]any{"summary": "local inventory", "detail": map[string]any{"service": "LOCAL_PROOF", "paths": []string{"/one"}}}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	goalJob, err := es.SubmitGoalEvidence(t.Context(), goal, fact, "local proof")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := es.RecordFinding(t.Context(), db.RecordFindingInput{TaskID: task.ID, Summary: "optional candidate", Evidence: "local only", Worker: "test"})
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{pg: d, dir: t.TempDir()}
	s := &Server{m: m, ctx: t.Context()}
	s.engine = NewEngine(m)
	s.engine.lifecycleReady = func() bool { return false }
	s.SetVerifier(&fakeVerifier{result: db.VerdictResult{GoalVerdict: "met", Rationale: "local inventory supplied", PolicyVersion: db.VerdictPolicyVersion}})
	sc := newScheduler(s)
	sc.fireVerdictWorkflow()
	sc.verifyWG.Wait()
	var state string
	if err = d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, goalJob).Scan(&state); err != nil || state != db.JobCommitted {
		t.Fatal("goal blocked by optional switch", state, err)
	}
	if err = d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, goal).Scan(&state); err != nil || state != "met" {
		t.Fatal("goal not evaluated", state, err)
	}
	var attempts int
	if err = d.QueryRow(`SELECT state,attempts FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1`, finding.FindingID).Scan(&state, &attempts); err != nil || state != db.JobQueued || attempts != 0 {
		t.Fatal("disabled finding automation consumed work", state, attempts, err)
	}
}

func TestMissingVerifierLeavesGoalQueuedWithoutConsumingAttempts(t *testing.T) {
	d := privateVerificationDB(t)
	task, err := d.CreateTask(t.Name(), "local proof", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(task.ExplorationID)
	goal, err := es.AddGoal(map[string]any{"text": "local proof"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	id, err := es.EnqueueGoalEvaluation(goal, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: t.Context()}
	sc := newScheduler(s)
	sc.runVerificationQueue()
	var state string
	var attempts int
	if err = d.QueryRow(`SELECT state,attempts FROM verification_jobs WHERE id=$1`, id).Scan(&state, &attempts); err != nil || state != db.JobQueued || attempts != 0 {
		t.Fatal(state, attempts, err)
	}
}

func (v *blockingVerification) Verify(ctx context.Context, _ *db.EvidenceBundle) (db.VerdictResult, error) {
	deadline, _ := ctx.Deadline()
	v.started <- deadline
	<-ctx.Done()
	return db.VerdictResult{}, ctx.Err()
}

func TestVerificationQueueCapsAcrossTicksAndCancelsOnShutdown(t *testing.T) {
	d := privateVerificationDB(t)
	for i := 0; i < 3; i++ {
		tk, err := d.CreateTask(t.Name(), "local candidate", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.Exploration(tk.ExplorationID).RecordFinding(t.Context(), db.RecordFindingInput{TaskID: tk.ID,
			Summary: "candidate", Evidence: "local evidence", Name: "fixture", VulnClass: "test", Severity: "low", Worker: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	verifier := &blockingVerification{started: make(chan time.Time, 3)}
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: parent, verifier: verifier}
	sc := newScheduler(s)
	sc.runVerificationQueue()
	for i := 0; i < verificationConcurrency; i++ {
		select {
		case deadline := <-verifier.started:
			if deadline.IsZero() || time.Until(deadline) > verificationTimeout {
				t.Fatal("worker has no bounded execution deadline")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("verification workers did not start")
		}
	}
	// Repeated scheduling while both workers are blocked must not lease job #3.
	for i := 0; i < 4; i++ {
		sc.runVerificationQueue()
	}
	var leased, queued int
	if err := d.QueryRow(`SELECT count(*) FILTER(WHERE state='leased'),count(*) FILTER(WHERE state='queued') FROM verification_jobs`).Scan(&leased, &queued); err != nil {
		t.Fatal(err)
	}
	if leased != verificationConcurrency || queued != 1 {
		t.Fatalf("concurrency escaped across ticks: leased=%d queued=%d", leased, queued)
	}
	cancel()
	stopped := make(chan struct{})
	go func() { sc.Run(parent); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduler failed to cancel and drain verification workers")
	}
	var pending, refuted, failedRecords int
	if err := d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE state='queued'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE technical_verdict='refuted'`).Scan(&refuted); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE last_error<>'' AND attempts=1`).Scan(&failedRecords); err != nil {
		t.Fatal(err)
	}
	if pending != 3 || refuted != 0 || failedRecords != 2 {
		t.Fatalf("shutdown did not persist honest retry states: pending=%d refuted=%d failures=%d", pending, refuted, failedRecords)
	}
}
