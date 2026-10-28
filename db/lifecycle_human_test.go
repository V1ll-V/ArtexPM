package db

import (
	"errors"
	"testing"
	"time"
)

func TestLifecycleHumanDecisionEventFailureRollsBackEverything(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	_, f, job := newGuardFixture(t, d, t.Name())
	if _, err = d.Exec(`CREATE FUNCTION reject_human_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected event failure'; END $$;
CREATE TRIGGER reject_human_event BEFORE INSERT ON verdict_events FOR EACH ROW EXECUTE FUNCTION reject_human_event()`); err != nil {
		t.Fatal(err)
	}
	status := FindingFalsePositive
	if _, err = d.SetFindingReviewDecision(t.Context(), f.FindingID, FindingReviewFalsePositive, "counterexample", nil, &status, nil); !errors.Is(err, ErrVerdictEventDrop) {
		t.Fatalf("expected reliable event failure: %v", err)
	}
	var revision, decisions int64
	var actual, review, jobState string
	if err = d.QueryRow(`SELECT human_revision,status,review_decision,(SELECT count(*) FROM finding_human_decisions WHERE finding_id=f.id),(SELECT state FROM verification_jobs WHERE id=$2) FROM findings f WHERE id=$1`, f.FindingID, job).Scan(&revision, &actual, &review, &decisions, &jobState); err != nil {
		t.Fatal(err)
	}
	if revision != 0 || actual != FindingPending || review != "" || decisions != 0 || jobState != JobQueued {
		t.Fatalf("partial human decision committed: %d %s %s %d %s", revision, actual, review, decisions, jobState)
	}
}

func TestLifecycleHumanAdoptionRecordsOneDecisionAndOneEvent(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	_, f, _ := newGuardFixture(t, d, t.Name())
	run, conv, _, err := d.CreateFindingReview(t.Context(), f.FindingID, "check bounded scope", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.StartFindingRetest(t.Context(), run.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.RecordFindingReviewResult(t.Context(), conv.ID, FindingReviewConfirmed, "high", "bounded support", "local proof", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err = d.FinishFindingRetest(run.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	row, _, err := d.FindingVerdictByID(t.Context(), f.FindingID)
	if err != nil || row.HumanRevision != 0 || FindingVerdictEffective(row.State()) {
		t.Fatalf("model review adopted itself: %+v %v", row, err)
	}
	status := FindingConfirmed
	if _, err = d.SetFindingReviewDecision(t.Context(), f.FindingID, FindingReviewConfirmed, "human adopted", &run.ID, &status, nil); err != nil {
		t.Fatal(err)
	}
	row, _, err = d.FindingVerdictByID(t.Context(), f.FindingID)
	if err != nil || row.HumanRevision != 1 || row.VerdictRevision != 1 || !FindingVerdictEffective(row.State()) {
		t.Fatalf("incorrect adoption: %+v %v", row, err)
	}
	var events int
	if err = d.QueryRow(`SELECT count(*) FROM verdict_events WHERE finding_id=$1 AND kind='finding_supported'`, f.FindingID).Scan(&events); err != nil || events != 1 {
		t.Fatal(events, err)
	}
	if _, jobs, e := d.FanOutVerdictEvents(t.Context(), 100); e != nil || jobs != 1 {
		t.Fatalf("human support did not queue report: %d %v", jobs, e)
	}
}

func TestLifecycleClearRestoresAutomaticAuthority(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	_, f, _ := newGuardFixture(t, d, t.Name())
	if _, err = d.SetFindingReviewDecision(t.Context(), f.FindingID, FindingReviewExaggerated, "scope not established", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	row, _, err := d.FindingVerdictByID(t.Context(), f.FindingID)
	if err != nil || row.TechnicalVerdict != VerdictNeedsReview {
		t.Fatal(row, err)
	}
	if _, err = d.RequestFindingReview(t.Context(), f.FindingID, "must-not-override-human"); !errors.Is(err, ErrFindingHumanDecisionActive) {
		t.Fatal(err)
	}
	if _, err = d.SetFindingReviewDecision(t.Context(), f.FindingID, "", "", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	j, err := d.ClaimVerificationJob(t.Context(), time.Minute)
	if err != nil || j == nil {
		t.Fatal(j, err)
	}
	b, err := d.PrepareVerificationInput(t.Context(), j.ID, j.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := CommitFindingVerdict(t.Context(), d, CommitFindingVerdictInput{FindingID: f.FindingID, JobID: j.ID, LeaseGeneration: j.LeaseGeneration, ExpectedInputRevision: b.InputRevision, ExpectedVerdictRevision: b.VerdictRevision, ExpectedHumanRevision: b.HumanRevision, Result: VerdictResult{Decision: VerdictSupported, AcceptedClaim: "only the now verified scope"}})
	if err != nil || conflict != CommitOK {
		t.Fatal(conflict, err)
	}
}

func TestLifecycleHumanConfirmationPreservesAcceptedScope(t *testing.T) {
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := supportedReportFixture(t, d)
	if _, err = d.Exec(`UPDATE findings SET accepted_detail='{"preconditions":["only session A"],"severity":"low"}',proposed_detail='{"severity":"critical"}' WHERE id=$1`, f.FindingID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = d.SetFindingStatusWithNotify(t.Context(), f.FindingID, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	var severity, condition string
	if err = d.QueryRow(`SELECT accepted_detail->>'severity',accepted_detail->'preconditions'->>0 FROM findings WHERE id=$1`, f.FindingID).Scan(&severity, &condition); err != nil {
		t.Fatal(err)
	}
	if severity != "low" || condition != "only session A" {
		t.Fatalf("human confirmation broadened scope: %s %s", severity, condition)
	}
}

func TestLifecycleHumanReviewWithoutStatusIsAuthoritative(t *testing.T) {
	d, e := privateVerificationInputDB(t)
	if e != nil {
		t.Fatal(e)
	}
	_, f, _ := newGuardFixture(t, d, t.Name())
	ok, e := d.SetFindingReviewDecision(t.Context(), f.FindingID, FindingReviewFalsePositive, "counterexample", nil, nil, nil)
	if e != nil || !ok {
		t.Fatal(ok, e)
	}
	var rev int64
	var decision string
	if e = d.QueryRow(`SELECT human_revision,technical_verdict FROM findings WHERE id=$1`, f.FindingID).Scan(&rev, &decision); e != nil {
		t.Fatal(e)
	}
	if rev != 1 || decision != VerdictRefuted {
		t.Fatalf("review ignored: revision=%d verdict=%s", rev, decision)
	}
}
func TestLifecycleRepeatedStatusStillRecordsHumanDecision(t *testing.T) {
	d, e := privateVerificationInputDB(t)
	if e != nil {
		t.Fatal(e)
	}
	_, f, _ := newGuardFixture(t, d, t.Name())
	for range 2 {
		if _, _, _, e = d.SetFindingStatusWithNotify(t.Context(), f.FindingID, FindingFalsePositive); e != nil {
			t.Fatal(e)
		}
	}
	var n int64
	if e = d.QueryRow(`SELECT human_revision FROM findings WHERE id=$1`, f.FindingID).Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n != 2 {
		t.Fatalf("human revision=%d", n)
	}
}
func TestLifecycleClearCreatesFreshTraceableRequest(t *testing.T) {
	d, e := privateVerificationInputDB(t)
	if e != nil {
		t.Fatal(e)
	}
	_, f, old := newGuardFixture(t, d, t.Name())
	if _, _, _, e = d.SetFindingStatusWithNotify(t.Context(), f.FindingID, FindingFalsePositive); e != nil {
		t.Fatal(e)
	}
	if _, e = d.SetFindingReviewDecision(t.Context(), f.FindingID, "", "", nil, nil, nil); e != nil {
		t.Fatal(e)
	}
	j, e := d.ClaimVerificationJob(t.Context(), time.Minute)
	if e != nil || j == nil || j.ID == old || j.ReviewRequestID == "" {
		t.Fatalf("clear did not create a new request: %+v %v", j, e)
	}
}
