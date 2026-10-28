package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestFindingManifestQueueFailureRollsBackEvidence(t *testing.T) {
	d, in, f, refs := manifestFixture(t)
	before := readManifestState(t, d, f.FindingID)
	if _, err := d.Exec(`CREATE FUNCTION reject_manifest_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected queue failure'; END $$;
CREATE TRIGGER reject_manifest_event BEFORE INSERT ON verdict_events FOR EACH ROW EXECUTE FUNCTION reject_manifest_event()`); err != nil {
		t.Fatal(err)
	}
	in.ExistingFindingID = f.FindingID
	in.Summary = "changed claim"
	refs[0].Ref.Note = "changed evidence"
	err := d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error { _, e := RecordFindingTx(t.Context(), tx, in, refs); return e })
	if !errors.Is(err, ErrVerdictEventDrop) {
		t.Fatal(err)
	}
	if after := readManifestState(t, d, f.FindingID); after != before {
		t.Fatalf("failed enqueue changed manifest: %+v -> %+v", before, after)
	}
	traffic, err := d.GetFindingTraffic(t.Context(), f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if traffic.Bindings[0].Note != "baseline" {
		t.Fatal("binding update survived rollback")
	}
}

func TestFindingManifestColumnUpgradeAndRepeatPreservesDecisions(t *testing.T) {
	d, _, f, _ := manifestFixture(t)
	if _, _, _, err := d.SetFindingStatusWithNotify(t.Context(), f.FindingID, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE findings DROP COLUMN input_manifest_hash`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := d.Exec(schemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	var hash, verdict string
	var revision int64
	if err := d.QueryRow(`SELECT input_manifest_hash,technical_verdict,human_revision FROM findings WHERE id=$1`, f.FindingID).Scan(&hash, &verdict, &revision); err != nil {
		t.Fatal(err)
	}
	if hash != "" || verdict != VerdictRefuted || revision != 1 {
		t.Fatalf("migration rewrote human decision: %s %s %d", hash, verdict, revision)
	}
	raw, err := normalizeArchivedFindingVersions(json.RawMessage(`[{"id":123}]`))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(raw, &rows); err != nil || rows[0]["input_manifest_hash"] != "" {
		t.Fatal(string(raw), err)
	}
}

func manifestFixture(t *testing.T) (*DB, RecordFindingInput, *RecordedFinding, []PreparedTrafficEvidence) {
	t.Helper()
	d, err := privateVerificationInputDB(t)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask(t.Name(), "verify a bounded claim", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	in := RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "bounded claim", Evidence: "original proof", Preconditions: []string{"session B", "session A"}, Worker: "test"}
	var refs []PreparedTrafficEvidence
	for _, role := range []string{"baseline", "proof"} {
		s := TrafficEvidenceSnapshot{SourceTrafficID: role, URL: "https://example.invalid/" + role, Method: "GET", ReqHash: role + "-request", RespHash: role + "-response", ReqLen: 12, RespLen: 34}
		s.ID = TrafficSnapshotID(s)
		refs = append(refs, PreparedTrafficEvidence{Ref: TrafficRef{TrafficID: role, Role: role, Note: role}, Snapshot: s})
	}
	var f *RecordedFinding
	err = d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error { var e error; f, e = RecordFindingTx(t.Context(), tx, in, refs); return e })
	if err != nil {
		t.Fatal(err)
	}
	return d, in, f, refs
}

type manifestState struct {
	Input, Evidence, Claims, Jobs, Events int64
	Hash                                  string
}

func readManifestState(t *testing.T, d *DB, id int64) (s manifestState) {
	t.Helper()
	if err := d.QueryRow(`SELECT input_revision,evidence_version,input_manifest_hash,
 (SELECT count(*) FROM finding_claims WHERE finding_id=f.id),
 (SELECT count(*) FROM verification_jobs WHERE subject_kind='finding' AND subject_id=f.id),
 (SELECT count(*) FROM verdict_events WHERE finding_id=f.id) FROM findings f WHERE id=$1`, id).Scan(&s.Input, &s.Evidence, &s.Hash, &s.Claims, &s.Jobs, &s.Events); err != nil {
		t.Fatal(err)
	}
	return
}

func TestFindingManifestIdenticalS3IsNoOp(t *testing.T) {
	d, in, f, refs := manifestFixture(t)
	before := readManifestState(t, d, f.FindingID)
	in.ExistingFindingID = f.FindingID
	in.Summary = "  bounded claim  "
	in.Preconditions = []string{" session A ", "session B", "session A"}
	for range 2 {
		if err := d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error { _, e := RecordFindingTx(t.Context(), tx, in, refs); return e }); err != nil {
			t.Fatal(err)
		}
	}
	after := readManifestState(t, d, f.FindingID)
	if before != after || len(after.Hash) != 64 {
		t.Fatalf("identical retry changed state: before=%+v after=%+v", before, after)
	}
	var raw []byte
	if err := d.QueryRow(`SELECT evidence_refs FROM finding_claims WHERE finding_id=$1`, f.FindingID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored []struct {
		SnapshotID  string `json:"snapshot_id"`
		RequestHash string `json:"request_hash"`
		Role        string `json:"role"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[0].SnapshotID == "" || stored[0].RequestHash == "" || stored[0].Role == "" {
		t.Fatalf("missing evidence manifest: %s", raw)
	}
}

func TestFindingManifestRealS3ChangeInvalidatesAndRequeuesOnce(t *testing.T) {
	d, in, f, refs := manifestFixture(t)
	if _, _, _, err := d.SetFindingStatusWithNotify(t.Context(), f.FindingID, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	before := readManifestState(t, d, f.FindingID)
	in.ExistingFindingID = f.FindingID
	in.Summary = "new claim with new evidence"
	refs[0].Ref.Note = "different identity comparison"
	if err := d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error { _, e := RecordFindingTx(t.Context(), tx, in, refs); return e }); err != nil {
		t.Fatal(err)
	}
	after := readManifestState(t, d, f.FindingID)
	if after.Input != before.Input+1 || after.Evidence != before.Evidence+1 || after.Jobs != before.Jobs+1 || after.Claims != before.Claims+1 || after.Hash == before.Hash {
		t.Fatalf("one logical change must create one input: %+v -> %+v", before, after)
	}
	row, _, err := d.FindingVerdictByID(t.Context(), f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if FindingVerdictEffective(row.State()) || row.HumanRevision != 1 {
		t.Fatalf("new input kept effective verdict or lost human decision: %+v", row)
	}
}

func TestFindingManifestDisplayOrderDoesNotInvalidate(t *testing.T) {
	d, _, f, _ := manifestFixture(t)
	before := readManifestState(t, d, f.FindingID)
	traffic, err := d.GetFindingTraffic(t.Context(), f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	order := []int64{traffic.Bindings[1].ID, traffic.Bindings[0].ID}
	if err = d.EditFindingTraffic(t.Context(), f.FindingID, 0, traffic.Version, nil, nil, false, order); err != nil {
		t.Fatal(err)
	}
	if after := readManifestState(t, d, f.FindingID); after != before {
		t.Fatalf("display order changed semantic input: %+v -> %+v", before, after)
	}
	note := "different evidence interpretation"
	if err = d.EditFindingTraffic(t.Context(), f.FindingID, order[0], traffic.Version, nil, &note, false, nil); err != nil {
		t.Fatal(err)
	}
	after := readManifestState(t, d, f.FindingID)
	if after.Input != before.Input+1 || after.Jobs != before.Jobs+1 {
		t.Fatalf("evidence note did not trigger re-evaluation: %+v", after)
	}
	if err = d.EditFindingTraffic(t.Context(), f.FindingID, order[0], after.Evidence, nil, &note, false, nil); err != nil {
		t.Fatal(err)
	}
	if again := readManifestState(t, d, f.FindingID); again != after {
		t.Fatalf("identical edit changed input: %+v", again)
	}
}

func TestFindingReviewRequestRetryCannotSupersedeNewerRequest(t *testing.T) {
	d, _, f, _ := manifestFixture(t)
	a, err := d.RequestFindingReview(t.Context(), f.FindingID, "request-A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.RequestFindingReview(t.Context(), f.FindingID, "request-B")
	if err != nil || a == b {
		t.Fatal(a, b, err)
	}
	for range 2 {
		retry, e := d.RequestFindingReview(t.Context(), f.FindingID, "request-A")
		if e != nil || retry != a {
			t.Fatal(retry, e)
		}
	}
	j, err := d.ClaimVerificationJob(t.Context(), time.Minute)
	if err != nil || j == nil || j.ID != b || j.ReviewRequestID != "request-B" || j.PolicyVersion != VerdictPolicyVersion {
		t.Fatalf("old retry displaced current request: %+v %v", j, err)
	}
	var state string
	if err = d.QueryRow(`SELECT state FROM verification_jobs WHERE id=$1`, a).Scan(&state); err != nil || state != JobSuperseded {
		t.Fatal(state, err)
	}
}
