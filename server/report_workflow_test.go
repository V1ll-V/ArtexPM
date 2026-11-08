package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
)

func acceptedHTTPReportFixture(t *testing.T, d *db.DB) (*db.RecordedFinding, *db.VerificationJob, *evidence.Store) {
	t.Helper()
	rec, verification, store := verificationHTTPFixture(t, d)
	verdict := &fakeVerifier{result: db.VerdictResult{Decision: db.VerdictSupported, AcceptedClaim: "ACCEPTED_LIMITED_SCOPE", PolicyVersion: db.VerdictPolicyVersion}}
	if err := processVerificationJobWith(t.Context(), d, verdict, verification, store.LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.FanOutVerdictEvents(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimEventJob(t.Context(), db.EventJobReportRun, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("report claim: %v", err)
	}
	return rec, job, store
}

func TestPersistentReportWriterReceivesFrozenScopeAndCommits(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, store := acceptedHTTPReportFixture(t, d)
	prompt, err := agent.ReportSystemPrompt("按自定义风格报告，{{.Now}}", "local")
	if err != nil {
		t.Fatal(err)
	}
	provider := &verificationInputProvider{reply: `{"status":"ready","report":"# 有限范围报告\n\n只报告已验收的读取行为。"}`}
	if err = processReportJobWith(t.Context(), d, &agent.LLMReportWriter{Prov: provider}, job, prompt, store.LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatal("real non-streaming report writer not reached")
	}
	input := provider.request.Messages[0].Text()
	for _, marker := range []string{"ACCEPTED_LIMITED_SCOPE", "CROSS_ACCOUNT_VALUE", "OWN_VALUE", "reader-B", "baseline", "proof", "input_revision", "human_revision", "policy_version"} {
		if !strings.Contains(input, marker) {
			t.Errorf("writer input lost %s", marker)
		}
	}
	if !strings.Contains(provider.request.System[0], "自定义风格") || !strings.Contains(provider.request.System[0], "固定合同") || len(provider.request.Tools) != 0 {
		t.Fatal("style or code-owned execution constraints lost")
	}
	var state, runState, report, raw string
	var execution []byte
	var runID int64
	if err = d.QueryRow(`SELECT j.state,r.state,f.report,r.raw_output,r.execution_input,f.report_run_id
  FROM event_jobs j JOIN report_runs r ON r.job_id=j.id JOIN findings f ON f.id=r.finding_id WHERE j.id=$1`, job.ID).
		Scan(&state, &runState, &report, &raw, &execution, &runID); err != nil {
		t.Fatal(err)
	}
	if state != "done" || runState != "committed" || report != "# 有限范围报告\n\n只报告已验收的读取行为。" || !strings.Contains(raw, "ready") || !strings.Contains(string(execution), "CROSS_ACCOUNT_VALUE") || runID <= 0 {
		t.Fatal("report, execution, raw response and completion were not persisted")
	}
	if rec.FindingID <= 0 {
		t.Fatal("fixture missing")
	}
}

func TestPersistentReportWriterFailureKeepsReportUnpublished(t *testing.T) {
	for _, reply := range []string{"MALFORMED_REPORT_OUTPUT", `{"status":"needs_evidence","reason":"missing independent control"}`} {
		t.Run(fmt.Sprint(len(reply)), func(t *testing.T) {
			d := privateVerificationDB(t)
			rec, job, store := acceptedHTTPReportFixture(t, d)
			prompt, err := agent.ReportSystemPrompt("", "")
			if err != nil {
				t.Fatal(err)
			}
			provider := &verificationInputProvider{reply: reply}
			err = processReportJobWith(t.Context(), d, &agent.LLMReportWriter{Prov: provider}, job, prompt, store.LoadVerificationBodies)
			if err == nil {
				t.Fatal("invalid/unready report accepted")
			}
			if err = d.FailEventJob(t.Context(), job.ID, job.LeaseGeneration, err.Error(), 3); err != nil {
				t.Fatal(err)
			}
			var report, state, runState, raw, cause string
			if err = d.QueryRow(`SELECT COALESCE(f.report,''),j.state,r.state,r.raw_output,r.last_error FROM findings f
   JOIN report_runs r ON r.finding_id=f.id JOIN event_jobs j ON j.id=r.job_id WHERE f.id=$1`, rec.FindingID).
				Scan(&report, &state, &runState, &raw, &cause); err != nil {
				t.Fatal(err)
			}
			if report != "" || state != "queued" || runState != "failed" || raw != reply || cause == "" {
				t.Fatal("failed report was published or lost its retry/audit record")
			}
		})
	}
}

type callbackReportWriter func(context.Context, *db.ReportExecutionInput) (string, error)

func (f callbackReportWriter) WriteReport(ctx context.Context, in *db.ReportExecutionInput) (string, error) {
	return f(ctx, in)
}

func TestPersistentReportRejectsScopeChangedWhileGenerating(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, store := acceptedHTTPReportFixture(t, d)
	writer := callbackReportWriter(func(ctx context.Context, input *db.ReportExecutionInput) (string, error) {
		if input.Snapshot.AcceptedClaim != "ACCEPTED_LIMITED_SCOPE" {
			t.Fatal("writer did not receive original scope")
		}
		_, err := d.ExecContext(ctx, `UPDATE findings SET input_revision=input_revision+1,verdict_input_revision=input_revision+1,
    verdict_revision=verdict_revision+1,accepted_claim='NEW_SCOPE' WHERE id=$1`, rec.FindingID)
		return "# report generated from old scope", err
	})
	if err := processReportJobWith(t.Context(), d, writer, job, "local contract", store.LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	var report, state, runState string
	if err := d.QueryRow(`SELECT COALESCE(f.report,''),j.state,r.state FROM findings f JOIN report_runs r ON r.finding_id=f.id
  JOIN event_jobs j ON j.id=r.job_id WHERE f.id=$1`, rec.FindingID).Scan(&report, &state, &runState); err != nil {
		t.Fatal(err)
	}
	if report != "" || state != "superseded" || runState != "superseded" {
		t.Fatal("old report was stamped as the new verdict")
	}
}

func TestReportToolCannotInventTrustedExecutionContext(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, _ := acceptedHTTPReportFixture(t, d)
	s := &Server{m: &Manager{pg: d}}
	args := fmt.Sprintf(`{"finding_id":%d,"report":"# unbound","job_id":%d,"lease_generation":%d,"evidence_version":1}`, rec.NodeID, job.ID, job.LeaseGeneration)
	result, err := s.toolUpdateFindingReport().Call(t.Context(), json.RawMessage(args), nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "持久化报告任务") {
		t.Fatalf("tool accepted invented capability: %s %v", result.Flatten(), err)
	}
	var report string
	if err = d.QueryRow(`SELECT COALESCE(report,'') FROM findings WHERE id=$1`, rec.FindingID).Scan(&report); err != nil {
		t.Fatal(err)
	}
	if report != "" {
		t.Fatal("unbound tool wrote report")
	}
}

func TestReportToolWithBoundRunCommitsReportAndJob(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, store := acceptedHTTPReportFixture(t, d)
	run, err := d.PrepareReportRun(t.Context(), job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	input := &db.ReportExecutionInput{Snapshot: run.Snapshot, SystemPrompt: "local contract"}
	if err = store.LoadVerificationBodies(t.Context(), input.Snapshot.Evidence); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordReportExecutionInput(t.Context(), run, input); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: d}}
	args := fmt.Sprintf(`{"finding_id":%d,"report":"# bound tool report","evidence_version":%d}`, rec.NodeID, run.Snapshot.EvidenceVersion)
	result, err := s.toolUpdateFindingReport().Call(db.WithReportRun(t.Context(), run), json.RawMessage(args), nil)
	if err != nil || result.IsError {
		t.Fatalf("bound tool failed: %s %v", result.Flatten(), err)
	}
	var state, report string
	if err = d.QueryRow(`SELECT j.state,f.report FROM event_jobs j JOIN report_runs r ON r.job_id=j.id JOIN findings f ON f.id=r.finding_id WHERE j.id=$1`, job.ID).Scan(&state, &report); err != nil {
		t.Fatal(err)
	}
	if state != "done" || report != "# bound tool report" {
		t.Fatal("trusted compatibility tool did not commit atomically")
	}
}

func enqueuePlainReport(t *testing.T, d *db.DB) int64 {
	t.Helper()
	tk, err := d.CreateTask(t.Name(), "local report fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := d.Exploration(tk.ExplorationID).RecordFinding(t.Context(), db.RecordFindingInput{TaskID: tk.ID, Summary: "candidate",
		Evidence: "local command output", VulnClass: "test", Name: "fixture", Severity: "low", Worker: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err = d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1`, rec.FindingID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("verifier claim: %v", err)
	}
	if err = processVerificationJobWith(t.Context(), d, &fakeVerifier{result: db.VerdictResult{Decision: db.VerdictSupported, AcceptedClaim: "local proof", PolicyVersion: db.VerdictPolicyVersion}}, job); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.FanOutVerdictEvents(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT id FROM event_jobs WHERE job_kind='report_run' AND payload->>'finding_id'=$1`, fmt.Sprint(rec.FindingID)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReportQueueWithoutModelLeavesDurableJobQueued(t *testing.T) {
	d := privateVerificationDB(t)
	id := enqueuePlainReport(t, d)
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: t.Context()}
	sc := newScheduler(s)
	sc.runReportQueue()
	var state string
	var attempts int
	if err := d.QueryRow(`SELECT state,attempts FROM event_jobs WHERE id=$1`, id).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "queued" || attempts != 0 {
		t.Fatal("unconfigured reporter consumed or acknowledged a job")
	}
}

func TestReportQueueHonorsAgentDisableAndShorterTimeout(t *testing.T) {
	d := privateVerificationDB(t)
	id := enqueuePlainReport(t, d)
	if _, err := d.CreateAgent("reporter", "Reporter", "local fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE agents SET enabled=false WHERE key='reporter'`); err != nil {
		t.Fatal(err)
	}
	provider := &verificationInputProvider{reply: `{"status":"ready","report":"# report"}`}
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: t.Context(), llmProv: provider}
	sc := newScheduler(s)
	sc.runReportQueue()
	var attempts int
	if err := d.QueryRow(`SELECT attempts FROM event_jobs WHERE id=$1`, id).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || provider.calls != 0 {
		t.Fatal("disabled reporter executed")
	}
	if _, err := d.Exec(`UPDATE agents SET enabled=true WHERE key='reporter'`); err != nil {
		t.Fatal(err)
	}
	if err := d.SetAgentRunSeconds("reporter", 1); err != nil {
		t.Fatal(err)
	}
	started := make(chan time.Time, 1)
	s.SetReportWriter(callbackReportWriter(func(ctx context.Context, input *db.ReportExecutionInput) (string, error) {
		deadline, _ := ctx.Deadline()
		started <- deadline
		<-ctx.Done()
		return "", ctx.Err()
	}))
	sc.runReportQueue()
	select {
	case deadline := <-started:
		if time.Until(deadline) > time.Second {
			t.Fatal("configured shorter report timeout ignored")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("report not started")
	}
	stopped := make(chan struct{})
	go func() { sc.reportWG.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("report deadline did not cancel execution")
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM event_jobs WHERE id=$1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "queued" {
		t.Fatal("timed-out report was lost or completed")
	}
}

func TestReportQueueHoldsLeaseUntilCommitAndCancelsAcrossTicks(t *testing.T) {
	d := privateVerificationDB(t)
	for i := 0; i < 3; i++ {
		enqueuePlainReport(t, d)
	}
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan time.Time, 3)
	writer := callbackReportWriter(func(ctx context.Context, input *db.ReportExecutionInput) (string, error) {
		deadline, _ := ctx.Deadline()
		started <- deadline
		<-ctx.Done()
		return "", ctx.Err()
	})
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: parent, reportWriter: writer}
	sc := newScheduler(s)
	sc.runReportQueue()
	for i := 0; i < reportConcurrency; i++ {
		select {
		case deadline := <-started:
			if deadline.IsZero() || time.Until(deadline) > reportExecutionTimeout {
				t.Fatal("report execution lacks deadline")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("report execution did not start")
		}
	}
	for i := 0; i < 4; i++ {
		sc.runReportQueue()
	}
	var leased, queued, published, running int
	if err := d.QueryRow(`SELECT count(*) FILTER(WHERE state='leased'),count(*) FILTER(WHERE state='queued') FROM event_jobs`).Scan(&leased, &queued); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE COALESCE(report,'')<>''`).Scan(&published); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM report_runs WHERE state='running'`).Scan(&running); err != nil {
		t.Fatal(err)
	}
	if leased != 2 || queued != 1 || published != 0 || running != 2 || len(s.triggerQ) != 0 {
		t.Fatal("report was acknowledged on enqueue, lost its run, or exceeded concurrency")
	}
	cancel()
	stopped := make(chan struct{})
	go func() { sc.Run(parent); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("report workers not cancelled and drained")
	}
	if err := d.QueryRow(`SELECT count(*) FROM event_jobs WHERE state='queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 3 {
		t.Fatal("shutdown lost durable report work")
	}
}

func TestReportNeedsEvidenceDoesNotSpendThreeIdenticalAttempts(t *testing.T) {
	d := privateVerificationDB(t)
	id := enqueuePlainReport(t, d)
	calls := 0
	s := &Server{m: &Manager{pg: d, dir: t.TempDir()}, ctx: t.Context()}
	s.SetReportWriter(callbackReportWriter(func(context.Context, *db.ReportExecutionInput) (string, error) {
		calls++
		return "", fmt.Errorf("%w: missing baseline", agent.ErrReportNeedsEvidence)
	}))
	sc := newScheduler(s)
	sc.runReportQueue()
	sc.reportWG.Wait()
	sc.runReportQueue()
	sc.reportWG.Wait()
	var state string
	var attempts int
	if err := d.QueryRow(`SELECT state,attempts FROM event_jobs WHERE id=$1`, id).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || attempts != 1 || state != "failed" {
		t.Fatal(calls, attempts, state)
	}
}
