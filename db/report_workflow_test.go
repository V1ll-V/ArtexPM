package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func supportedReportFixture(t *testing.T, d *DB) (*RecordedFinding, *VerificationJob) {
	t.Helper()
	_, rec, id := newGuardFixture(t, d, "report fixture")
	job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim verifier: %v", err)
	}
	b, err := d.PrepareVerificationInput(t.Context(), id, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := CommitFindingVerdict(t.Context(), d, CommitFindingVerdictInput{FindingID: rec.FindingID, JobID: id, LeaseGeneration: job.LeaseGeneration,
		ExpectedInputRevision: b.InputRevision, ExpectedVerdictRevision: b.VerdictRevision, ExpectedHumanRevision: b.HumanRevision,
		Result: VerdictResult{Decision: VerdictSupported, AcceptedClaim: "仅支持夹具范围内的数据读取"}})
	if err != nil || conflict != CommitOK {
		t.Fatalf("verdict: %s %v", conflict, err)
	}
	if _, _, err = d.FanOutVerdictEvents(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	reportJob, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
	if err != nil || reportJob == nil {
		t.Fatalf("claim report: %v", err)
	}
	return rec, reportJob
}

func preparedReportFixture(t *testing.T, d *DB) (*RecordedFinding, *VerificationJob, *ReportRun, context.Context) {
	t.Helper()
	rec, job := supportedReportFixture(t, d)
	run, err := d.PrepareReportRun(t.Context(), job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordReportExecutionInput(t.Context(), run, &ReportExecutionInput{Snapshot: run.Snapshot, SystemPrompt: "local report contract"}); err != nil {
		t.Fatal(err)
	}
	return rec, job, run, WithReportRun(t.Context(), run)
}

func assertReportUntouched(t *testing.T, d *DB, id int64) {
	t.Helper()
	var report string
	var version int64
	if err := d.QueryRow(`SELECT COALESCE(report,''),report_verdict_revision FROM findings WHERE id=$1`, id).Scan(&report, &version); err != nil {
		t.Fatal(err)
	}
	if report != "" || version != 0 {
		t.Fatal("rejected write modified the report or stamped a new version")
	}
}

func TestReportCommitIsAtomicAndReplayIsIdempotent(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	rec, job, run, ctx := preparedReportFixture(t, d)
	if _, err = d.SetFindingReportGated(ctx, rec.NodeID, "# frozen report", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetFindingReportVersionByNodeID(ctx, rec.NodeID, "# frozen report", nil); err != nil {
		t.Fatal("identical replay after commit: " + err.Error())
	}
	if _, err = d.SetFindingReportGated(ctx, rec.NodeID, "# different report", nil); !errors.Is(err, ErrReportAlreadyCommitted) {
		t.Fatalf("changed replay: %v", err)
	}
	var state, runState, policy string
	var runID, inputRevision, verdictRevision, humanRevision, evidenceVersion int64
	if err = d.QueryRow(`SELECT j.state,r.state,f.report_run_id,f.report_input_revision,f.report_verdict_revision,f.report_human_revision,f.report_evidence_version,f.report_policy_version
  FROM event_jobs j JOIN report_runs r ON r.job_id=j.id JOIN findings f ON f.id=r.finding_id WHERE j.id=$1`, job.ID).
		Scan(&state, &runState, &runID, &inputRevision, &verdictRevision, &humanRevision, &evidenceVersion, &policy); err != nil {
		t.Fatal(err)
	}
	if state != "done" || runState != "committed" || runID != run.ID || inputRevision != run.Snapshot.InputRevision || verdictRevision != run.Snapshot.VerdictRevision || humanRevision != run.Snapshot.HumanRevision || evidenceVersion != run.Snapshot.EvidenceVersion || policy != run.Snapshot.PolicyVersion {
		t.Fatal("report/job/run did not commit with the frozen versions")
	}
	var historicalReport string
	if err = d.QueryRow(`SELECT report_text FROM report_runs WHERE id=$1`, run.ID).Scan(&historicalReport); err != nil {
		t.Fatal(err)
	}
	if historicalReport != "# frozen report" {
		t.Fatal("durable report run lost its final report text")
	}
	// An error callback arriving after a successful commit cannot reopen the job.
	if err = d.FailEventJob(t.Context(), job.ID, job.LeaseGeneration, "late failure", 3); err != nil {
		t.Fatal(err)
	}
	if err = d.RecoverReportJobs(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	next, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
	if err != nil || next != nil {
		t.Fatalf("committed report requeued: %+v %v", next, err)
	}
}

func TestReportWriteRollsBackWhenJobCompletionFails(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	rec, job, run, ctx := preparedReportFixture(t, d)
	_, err = d.Exec(`CREATE FUNCTION fail_report_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.state='done' THEN RAISE EXCEPTION 'controlled ack failure'; END IF; RETURN NEW; END $$;
  CREATE TRIGGER fail_report_ack BEFORE UPDATE ON event_jobs FOR EACH ROW EXECUTE FUNCTION fail_report_ack()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetFindingReportGated(ctx, rec.NodeID, "# should roll back", nil); err == nil {
		t.Fatal("forced completion failure did not fail")
	}
	assertReportUntouched(t, d, rec.FindingID)
	var state, runState string
	if err = d.QueryRow(`SELECT j.state,r.state FROM event_jobs j JOIN report_runs r ON r.job_id=j.id WHERE j.id=$1 AND r.id=$2`, job.ID, run.ID).Scan(&state, &runState); err != nil {
		t.Fatal(err)
	}
	if state != "leased" || runState != "running" {
		t.Fatal("failed transaction partially acknowledged report")
	}
	if _, err = d.Exec(`DROP TRIGGER fail_report_ack ON event_jobs`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetFindingReportGated(ctx, rec.NodeID, "# should roll back", nil); err != nil {
		t.Fatal(err)
	}
}

func TestReportRejectsChangedVersionsAndBinding(t *testing.T) {
	for _, name := range []string{"input_and_verdict", "human", "policy", "evidence", "expired", "generation", "wrong_node", "wrong_job_payload", "wrong_traffic_version", "deleted_task"} {
		t.Run(name, func(t *testing.T) {
			d, err := privateVerificationInputDB(t)
			if err != nil {
				t.Fatal(err)
			}
			rec, job, run, ctx := preparedReportFixture(t, d)
			nodeID := rec.NodeID
			var trafficVersion *int64
			switch name {
			case "input_and_verdict":
				// Same traffic version, but a new accepted scope exists when an old writer returns.
				_, err = d.Exec(`UPDATE findings SET input_revision=input_revision+1,verdict_input_revision=input_revision+1,
    verdict_revision=verdict_revision+1,accepted_claim='NEW_ACCEPTED_SCOPE' WHERE id=$1`, rec.FindingID)
			case "human":
				_, _, _, err = d.SetFindingStatusWithNotify(t.Context(), rec.FindingID, FindingFalsePositive)
			case "policy":
				_, err = d.Exec(`UPDATE findings SET verdict_policy_version='obsolete-policy' WHERE id=$1`, rec.FindingID)
			case "evidence":
				_, err = d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, rec.FindingID)
			case "expired":
				_, err = d.Exec(`UPDATE event_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ID)
			case "generation":
				copy := *run
				copy.LeaseGeneration--
				ctx = WithReportRun(t.Context(), &copy)
			case "wrong_node":
				nodeID++
			case "wrong_job_payload":
				_, err = d.Exec(`UPDATE event_jobs SET payload=jsonb_set(payload,'{finding_id}',to_jsonb($2::bigint)) WHERE id=$1`, job.ID, rec.FindingID+1)
			case "wrong_traffic_version":
				v := run.Snapshot.EvidenceVersion + 1
				trafficVersion = &v
			case "deleted_task":
				err = d.DeleteTask(run.Snapshot.TaskID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.SetFindingReportGated(ctx, nodeID, "# stale report", trafficVersion); err == nil {
				t.Fatal("stale/unbound report accepted")
			}
			assertReportUntouched(t, d, rec.FindingID)
		})
	}
}

func TestReportCrashRecoveryFencesOldRunAndRetriesNewGeneration(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	rec, job, old, oldCtx := preparedReportFixture(t, d)
	if err = d.RecordReportOutput(t.Context(), old, "generated before crash"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE event_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.RecoverReportJobs(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	next, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
	if err != nil || next == nil {
		t.Fatalf("reclaim: %v", err)
	}
	if next.LeaseGeneration <= job.LeaseGeneration {
		t.Fatal("recovery reused old generation")
	}
	run, err := d.PrepareReportRun(t.Context(), next.ID, next.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if run.SnapshotHash != old.SnapshotHash {
		t.Fatal("retry replaced frozen scope")
	}
	if _, err = d.RecordReportExecutionInput(t.Context(), run, &ReportExecutionInput{Snapshot: run.Snapshot, SystemPrompt: "local"}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetFindingReportGated(oldCtx, rec.NodeID, "old result", nil); !errors.Is(err, ErrReportLeaseLost) {
		t.Fatalf("old run not fenced: %v", err)
	}
	if err = d.RecordReportOutput(t.Context(), old, "late raw output"); !errors.Is(err, ErrReportLeaseLost) {
		t.Fatalf("old output not fenced: %v", err)
	}
	if _, err = d.SetFindingReportGated(WithReportRun(t.Context(), run), rec.NodeID, "# recovered report", nil); err != nil {
		t.Fatal(err)
	}
	var oldState, raw string
	if err = d.QueryRow(`SELECT state,raw_output FROM report_runs WHERE id=$1`, old.ID).Scan(&oldState, &raw); err != nil {
		t.Fatal(err)
	}
	if oldState != "expired" || raw != "generated before crash" {
		t.Fatal("crashed execution lost its audit trail")
	}
}

func TestReportRetriesAreFinite(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	_, job := supportedReportFixture(t, d)
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err = d.PrepareReportRun(t.Context(), job.ID, job.LeaseGeneration); err != nil {
			t.Fatal(err)
		}
		if _, err = d.Exec(`UPDATE event_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ID); err != nil {
			t.Fatal(err)
		}
		if err = d.RecoverReportJobs(t.Context(), 3); err != nil {
			t.Fatal(err)
		}
		next, e := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if attempt < 3 {
			if next == nil {
				t.Fatal("retry disappeared")
			}
			job = next
		} else if next != nil {
			t.Fatal("retry limit ignored")
		}
	}
	var state string
	var attempts int
	if err = d.QueryRow(`SELECT state,attempts FROM event_jobs WHERE id=$1`, job.ID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || attempts != 3 {
		t.Fatalf("not visibly exhausted: %s/%d", state, attempts)
	}
}

func TestReportRecoversCrashBeforePreparationAndLegacyAck(t *testing.T) {
	for _, name := range []string{"before_prepare", "legacy_ack"} {
		t.Run(name, func(t *testing.T) {
			d, err := privateVerificationInputDB(t)
			if err != nil {
				t.Fatal(err)
			}
			_, job := supportedReportFixture(t, d)
			if name == "before_prepare" {
				_, err = d.Exec(`UPDATE event_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ID)
			} else {
				_, err = d.Exec(`UPDATE event_jobs SET state='done',lease_until=NULL WHERE id=$1`, job.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = d.RecoverReportJobs(t.Context(), 3); err != nil {
				t.Fatal(err)
			}
			next, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
			if err != nil || next == nil {
				t.Fatalf("lost report not recovered: %v", err)
			}
			if _, err = d.PrepareReportRun(t.Context(), next.ID, next.LeaseGeneration); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReportCommitAndBindingUseTaskFirstLockOrder(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	rec, _, _, ctx := preparedReportFixture(t, d)
	var taskID int64
	if err = d.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, rec.FindingID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	blocker, err := d.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	var blockerPID int
	if err = blocker.QueryRow(`SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if err = LockTaskEvidenceTx(blocker, taskID); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, e := d.SetFindingReportGated(ctx, rec.NodeID, "# serialized report", nil); finished <- e }()
	waitCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// Observe an actual wait on our task lock, rather than guessing with sleep.
	for {
		var waiting bool
		err = d.QueryRowContext(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database()
   AND $1::integer=ANY(pg_blocking_pids(a.pid)))`, blockerPID).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if waitCtx.Err() != nil {
			t.Fatal(waitCtx.Err())
		}
	}
	if _, err = blocker.ExecContext(waitCtx, `SELECT id FROM findings WHERE id=$1 FOR UPDATE`, rec.FindingID); err != nil {
		t.Fatal(fmt.Errorf("report took finding before task: %w", err))
	}
	if err = blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-waitCtx.Done():
		t.Fatal("report/binding lock order deadlocked")
	}
}

func TestLegacyReportEntrypointsRequireBoundRun(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := supportedReportFixture(t, d)
	for _, entry := range []struct {
		name  string
		write func() (int64, error)
	}{
		{"gated", func() (int64, error) { return d.SetFindingReportGated(t.Context(), rec.NodeID, "old report", nil) }},
		{"legacy", func() (int64, error) { return d.SetFindingReportByNodeID(rec.NodeID, "old report") }},
		{"legacy_version", func() (int64, error) {
			return d.SetFindingReportVersionByNodeID(t.Context(), rec.NodeID, "old report", nil)
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			if _, err := entry.write(); err == nil {
				t.Fatal("unbound report entry bypassed the frozen-run gate")
			}
		})
	}
}

func TestReportJobCannotCompleteBeforeReportCommit(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	_, job := supportedReportFixture(t, d)
	if err = d.CompleteEventJob(t.Context(), job.ID, job.LeaseGeneration); err == nil {
		t.Fatal("report job acknowledged before a report was persisted")
	}
}

func TestReportSchemaUpgradesOldRowsAndCanRepeat(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	rec, job := supportedReportFixture(t, d)
	// Reconstruct the step-1 table shape, including the old premature ack.
	_, err = d.Exec(`UPDATE event_jobs SET state='done',lease_until=NULL;
  DROP TABLE report_runs;
  ALTER TABLE event_jobs DROP COLUMN report_snapshot,DROP COLUMN report_snapshot_hash;
  ALTER TABLE findings DROP COLUMN report_human_revision,DROP COLUMN report_policy_version,DROP COLUMN report_run_id;`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE findings SET report='legacy report without durable run' WHERE id=$1`, rec.FindingID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = d.Exec(schemaSQL); err != nil {
			t.Fatalf("schema application %d: %v", i+1, err)
		}
	}
	if err = d.RecoverReportJobs(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	next, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
	if err != nil || next == nil || next.ID != job.ID {
		t.Fatalf("legacy ack was lost after upgrade: %+v %v", next, err)
	}
	run, err := d.PrepareReportRun(t.Context(), next.ID, next.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecordReportExecutionInput(t.Context(), run, &ReportExecutionInput{Snapshot: run.Snapshot, SystemPrompt: "local contract"}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetFindingReportGated(WithReportRun(t.Context(), run), rec.NodeID, "# migrated durable report", nil); err != nil {
		t.Fatal(err)
	}
	var report, policy string
	var runID int64
	if err = d.QueryRow(`SELECT report,report_policy_version,report_run_id FROM findings WHERE id=$1`, rec.FindingID).Scan(&report, &policy, &runID); err != nil {
		t.Fatal(err)
	}
	if report != "# migrated durable report" || policy != VerdictPolicyVersion || runID != run.ID {
		t.Fatal("upgrade stamped old report instead of committing a new durable run")
	}
}

func TestReportRejectsChangedAuthorityWithoutNewVerdict(t *testing.T) {
	for _, field := range []string{"input", "human", "accepted_claim"} {
		t.Run(field, func(t *testing.T) {
			d, err := privateVerificationInputDB(t)
			if err != nil {
				t.Fatal(err)
			}
			rec, _, _, ctx := preparedReportFixture(t, d)
			switch field {
			case "input":
				_, err = d.Exec(`UPDATE findings SET input_revision=input_revision+1,verdict_input_revision=input_revision+1 WHERE id=$1`, rec.FindingID)
			case "human":
				_, err = d.Exec(`UPDATE findings SET human_revision=human_revision+1 WHERE id=$1`, rec.FindingID)
			case "accepted_claim":
				_, err = d.Exec(`UPDATE findings SET accepted_claim='CHANGED_SCOPE_WITHOUT_VERDICT_BUMP' WHERE id=$1`, rec.FindingID)
			}
			if err != nil {
				t.Fatal(err)
			}
			row, _, err := d.FindingVerdictByID(t.Context(), rec.FindingID)
			if err != nil {
				t.Fatal(err)
			}
			if !FindingVerdictEffective(row.State()) {
				t.Fatal("fixture accidentally invalidated the verdict instead of testing the frozen report scope")
			}
			if _, err = d.SetFindingReportGated(ctx, rec.NodeID, "# obsolete report", nil); !errors.Is(err, ErrReportStale) {
				t.Fatalf("changed %s accepted under same verdict version: %v", field, err)
			}
			assertReportUntouched(t, d, rec.FindingID)
		})
	}
}
