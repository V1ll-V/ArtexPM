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
