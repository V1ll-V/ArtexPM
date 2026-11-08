package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

type lifecycleArchiveFixture struct {
	d                     *DB
	task, exp, goal       int64
	f                     *RecordedFinding
	candidate             *RecordedFinding
	verification, goalJob *VerificationJob
	reportJob             *VerificationJob
	run                   *ReportRun
	oldReportContext      context.Context
}

func newLifecycleArchiveFixture(t *testing.T) lifecycleArchiveFixture {
	t.Helper()
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	f, report, run, ctx := preparedReportFixture(t, d)
	x := lifecycleArchiveFixture{d: d, f: f, reportJob: report, run: run, oldReportContext: ctx}
	if err = d.QueryRow(`SELECT f.task_id,t.exploration_id FROM findings f JOIN tasks t ON t.id=f.task_id WHERE f.id=$1`, f.FindingID).Scan(&x.task, &x.exp); err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(x.exp)
	x.candidate, err = es.RecordFinding(t.Context(), RecordFindingInput{TaskID: x.task, Summary: "candidate still under verification", Evidence: "local proof", Worker: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err = d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1`, x.candidate.FindingID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	x.verification, err = d.ClaimVerificationJobByID(t.Context(), jobID, time.Minute)
	if err != nil || x.verification == nil {
		t.Fatal(x.verification, err)
	}
	if _, err = d.PrepareVerificationInput(t.Context(), jobID, x.verification.LeaseGeneration); err != nil {
		t.Fatal(err)
	}
	x.goal, err = es.AddGoal(map[string]any{"text": "verify the delivered fact"}, "user")
	if err != nil {
		t.Fatal(err)
	}
	fact, err := es.AddNode(KindFact, map[string]any{"summary": "fixture fact", "evidence": "local content"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err = es.SubmitGoalEvidence(t.Context(), x.goal, fact, "fact proves the delivery")
	if err != nil {
		t.Fatal(err)
	}
	x.goalJob, err = d.ClaimVerificationJobByID(t.Context(), jobID, time.Minute)
	if err != nil || x.goalJob == nil {
		t.Fatal(x.goalJob, err)
	}
	if err = d.SetPaused(x.task, true); err != nil {
		t.Fatal(err)
	}
	return x
}
func snapshotLifecycleFixture(t *testing.T, x lifecycleArchiveFixture) (*TaskArchive, *TaskArchiveSnapshot) {
	t.Helper()
	a, err := x.d.QueueTaskArchive(x.task)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err := x.d.SnapshotTaskArchive(x.task)
	if err != nil {
		t.Fatal(err)
	}
	return a, s
}
func compactLifecycleFixture(t *testing.T, x lifecycleArchiveFixture) (*TaskArchive, *TaskArchiveSnapshot) {
	t.Helper()
	a, s := snapshotLifecycleFixture(t, x)
	if err := x.d.CompleteTaskArchive(a.ID, s, "/tmp/lifecycle-fixture.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	return a, s
}
func restoreLifecycleFixture(t *testing.T, x lifecycleArchiveFixture, a *TaskArchive, s *TaskArchiveSnapshot) {
	t.Helper()
	if _, err := x.d.QueueTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.RestoreTaskArchive(a.ID, s, 0); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleArchiveFreezesAndIncludesAllHistory(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	d := x.d
	if _, err := d.SetFindingReviewDecision(t.Context(), x.f.FindingID, FindingReviewFalsePositive, "counterexample", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	_, s := snapshotLifecycleFixture(t, x)
	if s.FormatVersion != TaskArchiveFormatVersion {
		t.Fatal(s.FormatVersion)
	}
	for _, name := range lifecycleArchiveTables {
		if _, ok := s.Tables[name]; !ok {
			t.Fatal("missing", name)
		}
	}
	if s.DataCounts["finding_human_decisions"] != 1 || s.DataCounts["finding_claims"] != 2 || s.DataCounts["report_runs"] != 1 || s.DataCounts["verification_jobs"] != 3 {
		t.Fatal(s.DataCounts)
	}
	for _, j := range []*VerificationJob{x.verification, x.goalJob} {
		if claimed, err := d.ClaimVerificationJobByID(t.Context(), j.ID, time.Minute); err != nil || claimed != nil {
			t.Fatal("archived verification was claimable", claimed, err)
		}
	}
	if claimed, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute); err != nil || claimed != nil {
		t.Fatal("archived report was claimable", claimed, err)
	}
	if err := d.RecordVerificationOutput(t.Context(), x.verification.ID, x.verification.LeaseGeneration, "late output"); !errors.Is(err, ErrVerificationLeaseLost) {
		t.Fatal(err)
	}
	if err := d.RecordReportOutput(t.Context(), x.run, "late report"); !errors.Is(err, ErrReportLeaseLost) {
		t.Fatal(err)
	}
	if _, err := d.SetFindingName(x.f.FindingID, "late edit"); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatal(err)
	}
	if _, _, _, err := d.CreateFindingReview(t.Context(), x.f.FindingID, "late review", nil); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatal(err)
	}
}

func TestLifecycleArchiveRestoreFencesOldExecutionsAndKeepsEffectiveScope(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	d := x.d
	if _, err := d.Exec(`UPDATE tasks SET run_epoch=10,closing_reason='goal_satisfied',closing_run_epoch=10,closing_since=now(),closing_basis='old' WHERE id=$1`, x.task); err != nil {
		t.Fatal(err)
	}
	a, s := compactLifecycleFixture(t, x)
	for _, name := range lifecycleArchiveTables {
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM ` + name).Scan(&n); err != nil || n != 0 {
			t.Fatal("hot lifecycle remains", name, n, err)
		}
	}
	restoreLifecycleFixture(t, x, a, s)
	if claimed, err := d.ClaimVerificationJobByID(t.Context(), x.verification.ID, time.Minute); err != nil || claimed != nil {
		t.Fatal("claimed before external restore completion", claimed, err)
	}
	if _, err := d.RestoreTaskArchive(a.ID, s, 0); err != nil {
		t.Fatal("database restore retry not idempotent", err)
	}
	if err := d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	row, _, err := d.FindingVerdictByID(t.Context(), x.f.FindingID)
	if err != nil || !FindingVerdictEffective(row.State()) || row.AcceptedClaim != "仅支持夹具范围内的数据读取" {
		t.Fatal("accepted scope lost", row, err)
	}
	state, err := d.TaskRuntimeState(t.Context(), x.task)
	if err != nil || state.RunEpoch <= 10 || state.Closing {
		t.Fatal("old runtime restored", state, err)
	}
	newJob, err := d.ClaimVerificationJobByID(t.Context(), x.verification.ID, time.Minute)
	if err != nil || newJob == nil || newJob.LeaseGeneration <= x.verification.LeaseGeneration {
		t.Fatal(newJob, err)
	}
	if err = d.RecordVerificationOutput(t.Context(), x.verification.ID, x.verification.LeaseGeneration, "old epoch"); !errors.Is(err, ErrVerificationLeaseLost) {
		t.Fatal(err)
	}
	goalJob, err := d.ClaimVerificationJobByID(t.Context(), x.goalJob.ID, time.Minute)
	if err != nil || goalJob == nil || goalJob.LeaseGeneration <= x.goalJob.LeaseGeneration {
		t.Fatal(goalJob, err)
	}
	if _, err = d.SetFindingReportGated(x.oldReportContext, x.f.NodeID, "late old report", nil); err == nil {
		t.Fatal("old report context became valid after restore")
	}
	newReport, err := d.ClaimEventJob(t.Context(), EventJobReportRun, time.Minute)
	if err != nil || newReport == nil || newReport.LeaseGeneration <= x.reportJob.LeaseGeneration {
		t.Fatal(newReport, err)
	}
	if _, err = d.PrepareReportRun(t.Context(), newReport.ID, newReport.LeaseGeneration); err != nil {
		t.Fatal("fresh report could not resume", err)
	}
}

func TestLifecycleArchiveFailureThawsWithoutRevivingOldLeases(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	a, _ := snapshotLifecycleFixture(t, x)
	if err := x.d.FailTaskArchiveJob(a.ID, Archiving, errors.New("injected package failure")); err != nil {
		t.Fatal(err)
	}
	j, err := x.d.ClaimVerificationJobByID(t.Context(), x.verification.ID, time.Minute)
	if err != nil || j == nil || j.LeaseGeneration <= x.verification.LeaseGeneration {
		t.Fatal(j, err)
	}
	if err = x.d.RecordVerificationOutput(t.Context(), x.verification.ID, x.verification.LeaseGeneration, "old output"); !errors.Is(err, ErrVerificationLeaseLost) {
		t.Fatal(err)
	}
	if err = x.d.RecordVerificationOutput(t.Context(), j.ID, j.LeaseGeneration, "fresh output"); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleArchiveRejectsCrossTaskAndMissingAuditBeforeWriting(t *testing.T) {
	for _, kind := range []string{"finding", "verification", "event", "run", "missing"} {
		t.Run(kind, func(t *testing.T) {
			x := newLifecycleArchiveFixture(t)
			a, s := compactLifecycleFixture(t, x)
			other, otherF, _ := newGuardFixture(t, x.d, "unrelated task")
			var rows []map[string]any
			table := "findings"
			field := "task_id"
			value := any(other.ID)
			switch kind {
			case "verification":
				table = "verification_jobs"
				field = "subject_id"
				value = otherF.FindingID
			case "event":
				table = "event_jobs"
				field = "source_event_id"
				value = int64(999999)
			case "run":
				table = "report_runs"
				field = "finding_id"
				value = otherF.FindingID
			case "missing":
				delete(s.Tables, "finding_human_decisions")
			}
			if kind != "missing" {
				if err := json.Unmarshal(s.Tables[table], &rows); err != nil {
					t.Fatal(err)
				}
				rows[0][field] = value
				s.Tables[table], _ = json.Marshal(rows)
			}
			if _, err := x.d.QueueTaskArchiveRestore(a.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := x.d.ClaimTaskArchiveJob(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := x.d.RestoreTaskArchive(a.ID, s, 0); err == nil {
				t.Fatal("invalid archive accepted")
			}
			var deleted bool
			if err := x.d.QueryRow(`SELECT deleted_at IS NOT NULL FROM tasks WHERE id=$1`, x.task).Scan(&deleted); err != nil || !deleted {
				t.Fatal("invalid restore changed task", deleted, err)
			}
		})
	}
}

func TestLifecycleArchiveLegacyNeverAutoSupportsAndKeepsHumanRejection(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			x := newLifecycleArchiveFixture(t)
			if _, err := x.d.SetFindingReviewDecision(t.Context(), x.candidate.FindingID, FindingReviewFalsePositive, "human counterexample", nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			a, s := compactLifecycleFixture(t, x)
			s.FormatVersion = version
			for _, table := range lifecycleArchiveTables {
				delete(s.Tables, table)
			}
			if version < 3 {
				delete(s.Tables, "finding_traffic_bindings")
				delete(s.Tables, "traffic_evidence_snapshots")
			}
			restoreLifecycleFixture(t, x, a, s)
			if err := x.d.CompleteTaskArchiveRestore(a.ID); err != nil {
				t.Fatal(err)
			}
			row, _, err := x.d.FindingVerdictByID(t.Context(), x.f.FindingID)
			if err != nil || FindingVerdictEffective(row.State()) || row.AcceptedClaim != "" || row.LegacySource == "" {
				t.Fatal("legacy finding promoted", row, err)
			}
			row, _, err = x.d.FindingVerdictByID(t.Context(), x.candidate.FindingID)
			if err != nil || row.TechnicalVerdict != VerdictRefuted || row.HumanRevision != 1 {
				t.Fatal("legacy human rejection lost", row, err)
			}
		})
	}
}

func TestLifecycleArchiveV4RestoresWithoutCTFMetadata(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	a, s := compactLifecycleFixture(t, x)
	s.FormatVersion = 4
	delete(s.Tables, "ctf_executions")
	delete(s.Tables, "ctf_candidates")
	rows, err := decodeArchiveRows(s.Tables["tasks"])
	if err != nil || len(rows) != 1 {
		t.Fatal("task snapshot", err)
	}
	for _, key := range []string{"mode", "challenge_type", "attachment_batch_id", "ctf_input_hash"} {
		delete(rows[0], key)
	}
	s.Tables["tasks"], err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	restoreLifecycleFixture(t, x, a, s)
	if err = x.d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	task, err := x.d.GetTask(x.task)
	if err != nil || task.Mode != "pentest" || task.ChallengeType != "" || task.AttachmentBatchID != "" {
		t.Fatalf("legacy task defaults: %+v %v", task, err)
	}
	verdict, _, err := x.d.FindingVerdictByID(t.Context(), x.f.FindingID)
	if err != nil || !FindingVerdictEffective(verdict.State()) {
		t.Fatal("v4 verdict history lost", verdict, err)
	}
}

func TestLifecycleDeleteCleansJobsAndPreservesOtherTask(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(fmt.Sprint(purge), func(t *testing.T) {
			x := newLifecycleArchiveFixture(t)
			_, other, _ := newGuardFixture(t, x.d, "other task")
			if _, err := x.d.DeleteTaskCascade(x.task, false, purge); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := x.d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE subject_kind='goal' AND subject_id=$1`, x.goal).Scan(&n); err != nil || n != 0 {
				t.Fatal("goal job leaked", n, err)
			}
			if purge {
				for _, name := range lifecycleArchiveTables {
					query := `SELECT count(*) FROM ` + name + ` WHERE finding_id=$1`
					if name == "event_jobs" {
						query = `SELECT count(*) FROM event_jobs WHERE id=$1`
					}
					if name == "verification_jobs" {
						query = `SELECT count(*) FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1`
					}
					id := x.f.FindingID
					if name == "event_jobs" {
						id = x.reportJob.ID
					}
					if err := x.d.QueryRow(query, id).Scan(&n); err != nil || n != 0 {
						t.Fatal("purged lifecycle remains", name, n, err)
					}
				}
			} else {
				var state string
				if err := x.d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, x.verification.ID).Scan(&state); err != nil || state != JobSuperseded {
					t.Fatal(state, err)
				}
				if err := x.d.QueryRow(`SELECT state FROM event_jobs WHERE id=$1`, x.reportJob.ID).Scan(&state); err != nil || state != JobSuperseded {
					t.Fatal(state, err)
				}
			}
			if err := x.d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1`, other.FindingID).Scan(&n); err != nil || n != 1 {
				t.Fatal("unrelated task changed", n, err)
			}
		})
	}
}

func TestLifecycleDeleteSingleFindingPurgesReportAndAudit(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	if _, err := x.d.DeleteFinding(x.f.FindingID); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, table := range []string{"report_runs", "event_jobs"} {
		if err := x.d.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatal(table, n, err)
		}
	}
	if _, err := x.d.DeleteFindingsByTask(x.task); err != nil {
		t.Fatal(err)
	}
	if err := x.d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE subject_kind='finding'`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestLifecycleArchiveRestoreErrorRollsBackAllRows(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	a, s := compactLifecycleFixture(t, x)
	if _, err := x.d.Exec(`CREATE FUNCTION reject_lifecycle_restore() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected restore error'; END $$; CREATE TRIGGER reject_lifecycle_restore BEFORE INSERT ON report_runs FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_restore()`); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.QueueTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.RestoreTaskArchive(a.ID, s, 0); err == nil {
		t.Fatal("injected restore error ignored")
	}
	for _, table := range append([]string{"findings"}, lifecycleArchiveTables...) {
		var n int
		if err := x.d.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("partial restore survived", table, n, err)
		}
	}
	if _, err := x.d.Exec(`DROP TRIGGER reject_lifecycle_restore ON report_runs`); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.RestoreTaskArchive(a.ID, s, 0); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleRestoreInsideEvidenceInstallerDoesNotWaitOnItself(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	a, s := compactLifecycleFixture(t, x)
	if _, err := x.d.QueueTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := x.d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if _, e := x.d.RestoreTaskArchive(a.ID, s, 0); e != nil {
			return e
		}
		return x.d.CompleteTaskArchiveRestore(a.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleArchiveCommittedReportAndGoalSurvive(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	d := x.d
	if _, err := d.SetFindingReportGated(x.oldReportContext, x.f.NodeID, "# Frozen accepted scope", nil); err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(x.exp)
	if conflict, err := es.CommitGoalEvaluation(t.Context(), x.goalJob.ID, x.goalJob.LeaseGeneration, "met"); err != nil || conflict != CommitOK {
		t.Fatal(conflict, err)
	}
	a, s := compactLifecycleFixture(t, x)
	restoreLifecycleFixture(t, x, a, s)
	if err := d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	var report, state, goalState, jobState string
	if err := d.QueryRow(`SELECT report FROM findings WHERE id=$1`, x.f.FindingID).Scan(&report); err != nil || report != "# Frozen accepted scope" {
		t.Fatal(report, err)
	}
	if err := d.QueryRow(`SELECT state FROM report_runs WHERE id=$1`, x.run.ID).Scan(&state); err != nil || state != "committed" {
		t.Fatal(state, err)
	}
	if err := d.QueryRow(`SELECT state FROM event_jobs WHERE id=$1`, x.reportJob.ID).Scan(&state); err != nil || state != "done" {
		t.Fatal(state, err)
	}
	if err := d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, x.goal).Scan(&goalState); err != nil || goalState != "met" {
		t.Fatal(goalState, err)
	}
	if err := d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, x.goalJob.ID).Scan(&jobState); err != nil || jobState != JobCommitted {
		t.Fatal(jobState, err)
	}
	if _, err := d.SetFindingReportGated(x.oldReportContext, x.f.NodeID, "# Different late report", nil); err == nil {
		t.Fatal("old committed run rewrote report")
	}
}

func TestLifecycleArchiveV4HumanPrioritySurvives(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	if _, err := x.d.SetFindingReviewDecision(t.Context(), x.candidate.FindingID, FindingReviewFalsePositive, "preserve this counterexample", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	a, s := compactLifecycleFixture(t, x)
	restoreLifecycleFixture(t, x, a, s)
	if err := x.d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	row, _, err := x.d.FindingVerdictByID(t.Context(), x.candidate.FindingID)
	if err != nil || row.TechnicalVerdict != VerdictRefuted || row.HumanRevision != 1 {
		t.Fatal(row, err)
	}
	if _, err = x.d.RequestFindingReview(t.Context(), x.candidate.FindingID, "cannot-ignore-restored-human"); !errors.Is(err, ErrFindingHumanDecisionActive) {
		t.Fatal(err)
	}
	var note string
	if err = x.d.QueryRow(`SELECT note FROM finding_human_decisions WHERE finding_id=$1 AND human_revision=1`, x.candidate.FindingID).Scan(&note); err != nil || note != "preserve this counterexample" {
		t.Fatal(note, err)
	}
}

func TestLifecycleArchiveStalePackageCannotCompactNewAttempt(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	a, old := snapshotLifecycleFixture(t, x)
	if err := x.d.FailTaskArchiveJob(a.ID, Archiving, errors.New("retry")); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.SetFindingReviewDecision(t.Context(), x.candidate.FindingID, FindingReviewFalsePositive, "newer human decision", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.QueueTaskArchive(x.task); err != nil {
		t.Fatal(err)
	}
	if _, err := x.d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := x.d.CompleteTaskArchive(a.ID, old, "/tmp/old.tar.zst", "old", 1, 1); err == nil {
		t.Fatal("stale package removed newer decisions")
	}
	fresh, err := x.d.SnapshotTaskArchive(x.task)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.d.CompleteTaskArchive(a.ID, fresh, "/tmp/fresh.tar.zst", "fresh", 1, 1); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleDeleteGoalPurgesItsEvaluationOnly(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	if err := x.d.Exploration(x.exp).DeleteGoal(x.goal); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := x.d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE id=$1`, x.goalJob.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if err := x.d.QueryRow(`SELECT count(*) FROM verification_jobs WHERE id=$1`, x.verification.ID).Scan(&n); err != nil || n != 1 {
		t.Fatal("unrelated finding job lost", n, err)
	}
}

func TestLifecycleArchiveEventsStayFrozenUntilRestoreCompletes(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	if _, _, _, err := x.d.SetFindingStatusWithNotify(t.Context(), x.candidate.FindingID, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	a, s := snapshotLifecycleFixture(t, x)
	if events, jobs, err := x.d.FanOutVerdictEvents(t.Context(), 100); err != nil || events != 0 || jobs != 0 {
		t.Fatal("archiving events escaped", events, jobs, err)
	}
	if err := x.d.CompleteTaskArchive(a.ID, s, "/tmp/events.tar.zst", "events", 1, 1); err != nil {
		t.Fatal(err)
	}
	restoreLifecycleFixture(t, x, a, s)
	if events, jobs, err := x.d.FanOutVerdictEvents(t.Context(), 100); err != nil || events != 0 || jobs != 0 {
		t.Fatal("report queued before files ready", events, jobs, err)
	}
	if err := x.d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, jobs, err := x.d.FanOutVerdictEvents(t.Context(), 100); err != nil || jobs != 1 {
		t.Fatal("restored event was lost", jobs, err)
	}
}

func TestLifecycleArchiveClaimFreezeOrderingWithRealLocks(t *testing.T) {
	for _, freezeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("freeze_first_", freezeFirst), func(t *testing.T) {
			x := newLifecycleArchiveFixture(t)
			if _, err := x.d.Exec(`UPDATE verification_jobs SET lease_until=now()-interval '1 second' WHERE id=$1`, x.verification.ID); err != nil {
				t.Fatal(err)
			}
			blocker, err := x.d.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			var pid int
			if err = blocker.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if freezeFirst {
				_, err = blocker.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, x.task)
			} else {
				// Claim uses SKIP LOCKED for job rows. A table barrier instead
				// blocks its UPDATE after it has acquired the evidence lock.
				_, err = blocker.Exec(`LOCK TABLE verification_jobs IN SHARE ROW EXCLUSIVE MODE`)
			}
			if err != nil {
				t.Fatal(err)
			}
			type claimResult struct {
				job *VerificationJob
				err error
			}
			claimed := make(chan claimResult, 1)
			queued := make(chan error, 1)
			claim := func() {
				j, e := x.d.ClaimVerificationJobByID(t.Context(), x.verification.ID, time.Minute)
				claimed <- claimResult{j, e}
			}
			freeze := func() { _, e := x.d.QueueTaskArchive(x.task); queued <- e }
			if freezeFirst {
				go freeze()
			} else {
				go claim()
			}
			waitClosingBlock(t, x.d, pid)
			if freezeFirst {
				go claim()
			} else {
				go freeze()
			}
			if err = blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			c := <-claimed
			if c.err != nil {
				t.Fatal(c.err)
			}
			if err = <-queued; err != nil {
				t.Fatal(err)
			}
			if freezeFirst && c.job != nil {
				t.Fatal("claim passed freeze")
			}
			if !freezeFirst && c.job == nil {
				t.Fatal("earlier claim was lost")
			}
			if c.job != nil {
				if err = x.d.RecordVerificationOutput(t.Context(), c.job.ID, c.job.LeaseGeneration, "late claimed output"); !errors.Is(err, ErrVerificationLeaseLost) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestLifecycleArchiveLegacyResidualJobsCannotRegainAuthority(t *testing.T) {
	x := newLifecycleArchiveFixture(t)
	a, s := compactLifecycleFixture(t, x)
	s.FormatVersion = 3
	// Reproduce pre-v4 hot-store residue, including leases still in date.
	tx, err := x.d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"verification_jobs", "event_jobs", "report_runs"} {
		rows, err := decodeArchiveRows(s.Tables[table])
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if table == "report_runs" {
				r["state"] = "running"
				r["lease_generation"] = x.run.LeaseGeneration
			} else {
				r["state"] = "leased"
				r["lease_until"] = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
				if table == "verification_jobs" {
					r["lease_generation"] = x.verification.LeaseGeneration
				} else {
					r["lease_generation"] = x.reportJob.LeaseGeneration
				}
			}
		}
		raw, _ := json.Marshal(rows)
		if err = insertArchiveRows(tx, table, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	restoreLifecycleFixture(t, x, a, s)
	if err = x.d.CompleteTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if err = x.d.RecordVerificationOutput(t.Context(), x.verification.ID, x.verification.LeaseGeneration, "old verifier"); !errors.Is(err, ErrVerificationLeaseLost) {
		t.Fatal("legacy lease was revived", err)
	}
	if err = x.d.RecordReportOutput(t.Context(), x.run, "old report"); !errors.Is(err, ErrReportLeaseLost) {
		t.Fatal("legacy report run was revived", err)
	}
	newID, err := x.d.RequestFindingReview(t.Context(), x.candidate.FindingID, "fresh-after-legacy-restore")
	if err != nil || newID == x.verification.ID {
		t.Fatal(newID, err)
	}
	// The quarantined legacy audit must also be archivable by the new format.
	newArchive, fresh := snapshotLifecycleFixture(t, x)
	if err = x.d.CompleteTaskArchive(newArchive.ID, fresh, "/tmp/rearchived.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal("legacy residue prevented re-archive", err)
	}
}
