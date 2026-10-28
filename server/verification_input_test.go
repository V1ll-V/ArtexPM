package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/norma/llm"
)

type verificationInputProvider struct {
	request llm.CompletionRequest
	calls   int
	reply   string
}

func verificationHTTPFixture(t *testing.T, d *db.DB) (*db.RecordedFinding, *db.VerificationJob, *evidence.Store) {
	t.Helper()
	tk, err := d.CreateTask(t.Name(), "verify local access control", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := evidence.New(d, nil, t.TempDir())
	blob := func(body string) string {
		sum := sha256.Sum256([]byte(body))
		hash := hex.EncodeToString(sum[:])
		dir := filepath.Join(store.Dir, "blobs", hash[:2])
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, hash+".bin"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	var prepared []db.PreparedTrafficEvidence
	for _, tc := range []struct{ role, account, body string }{{"baseline", "owner-A", `{"owner":"owner-A","secret":"OWN_VALUE"}`}, {"proof", "reader-B", `{"owner":"owner-A","secret":"CROSS_ACCOUNT_VALUE"}`}} {
		req := "account=" + tc.account
		snap := db.TrafficEvidenceSnapshot{SourceTrafficID: t.Name() + tc.role, Method: "POST", URL: "https://fixture.invalid/record/1", Status: 200,
			ReqHead: "Cookie: session=" + tc.account, RespHead: "Content-Type: application/json", ReqHash: blob(req), RespHash: blob(tc.body), ReqLen: int64(len(req)), RespLen: int64(len(tc.body))}
		snap.ID = db.TrafficSnapshotID(snap)
		prepared = append(prepared, db.PreparedTrafficEvidence{Ref: db.TrafficRef{TrafficID: snap.SourceTrafficID, Role: tc.role, Note: "local identity control"}, Snapshot: snap})
	}
	var rec *db.RecordedFinding
	err = d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error {
		var e error
		rec, e = db.RecordFindingTx(t.Context(), tx, db.RecordFindingInput{TaskID: tk.ID, ExplorationID: tk.ExplorationID,
			Summary: "跨账号读取夹具数据", Name: "local fixture", VulnClass: "idor", Severity: "low", Evidence: "原始非 HTTP 补充材料", Worker: "test", Preconditions: []string{"两个独立账号"}}, prepared)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err = d.QueryRow(`SELECT id FROM verification_jobs WHERE subject_kind='finding' AND subject_id=$1 ORDER BY id DESC LIMIT 1`, rec.FindingID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	return rec, job, store
}

func TestRealVerifierWorkflowReceivesBodiesAndPersistsInput(t *testing.T) {
	d := privateVerificationDB(t)
	defer d.Close()
	rec, job, store := verificationHTTPFixture(t, d)
	p := &verificationInputProvider{reply: `{"decision":"supported","accepted_claim":"本地夹具中 reader-B 能读取 owner-A 的记录"}`}
	if err := processVerificationJobWith(t.Context(), d, &agent.LLMVerifier{Prov: p}, job, store.LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 {
		t.Fatal("actual LLMVerifier completion not reached")
	}
	input := p.request.Messages[0].Text()
	for _, marker := range []string{"baseline", "proof", "owner-A", "reader-B", "OWN_VALUE", "CROSS_ACCOUNT_VALUE", "原始非 HTTP 补充材料", "两个独立账号"} {
		if !strings.Contains(input, marker) {
			t.Errorf("model input lost %s", marker)
		}
	}
	var manifest, execution, result []byte
	var state, hash string
	if err := d.QueryRow(`SELECT input_manifest,execution_input,result,state,execution_hash FROM verification_jobs WHERE id=$1`, job.ID).Scan(&manifest, &execution, &result, &state, &hash); err != nil {
		t.Fatal(err)
	}
	if state != db.JobCommitted || len(hash) != 64 || !strings.Contains(string(execution), "CROSS_ACCOUNT_VALUE") || strings.Contains(string(manifest), "CROSS_ACCOUNT_VALUE") || !strings.Contains(string(result), "supported") {
		t.Fatal("manifest/execution/result audit trail incomplete")
	}
	row, _, err := d.FindingVerdictByID(t.Context(), rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if !db.FindingVerdictEffective(row.State()) {
		t.Fatal("successful verification did not commit")
	}
}

func TestRealVerifierMissingBodyCannotConfirmFinding(t *testing.T) {
	d := privateVerificationDB(t)
	defer d.Close()
	rec, job, _ := verificationHTTPFixture(t, d)
	missing := evidence.New(d, nil, t.TempDir())
	p := &verificationInputProvider{reply: `{"decision":"supported","accepted_claim":"unsupported guess"}`}
	if err := processVerificationJobWith(t.Context(), d, &agent.LLMVerifier{Prov: p}, job, missing.LoadVerificationBodies); err == nil {
		t.Fatal("missing bodies accepted as supported")
	}
	row, _, err := d.FindingVerdictByID(t.Context(), rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if row.TechnicalVerdict != db.VerdictUnverified {
		t.Fatal("failure changed technical verdict")
	}
	var execution []byte
	if err := d.QueryRow(`SELECT execution_input FROM verification_jobs WHERE id=$1`, job.ID).Scan(&execution); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(execution), `"missing": true`) {
		t.Fatal("missing evidence was not auditable")
	}
}

func TestRealVerifierMalformedOutputIsAuditedBeforeRetry(t *testing.T) {
	d := privateVerificationDB(t)
	rec, job, store := verificationHTTPFixture(t, d)
	p := &verificationInputProvider{reply: "MALFORMED_MODEL_OUTPUT"}
	err := processVerificationJobWith(t.Context(), d, &agent.LLMVerifier{Prov: p}, job, store.LoadVerificationBodies)
	if err == nil {
		t.Fatal("malformed model output accepted")
	}
	if e := d.FailVerificationJob(t.Context(), job.ID, job.LeaseGeneration, err.Error(), 3); e != nil {
		t.Fatal(e)
	}
	var audit []byte
	var state string
	if err = d.QueryRow(`SELECT attempt_log,state FROM verification_jobs WHERE id=$1`, job.ID).Scan(&audit, &state); err != nil {
		t.Fatal(err)
	}
	if state != db.JobQueued || !strings.Contains(string(audit), "MALFORMED_MODEL_OUTPUT") || !strings.Contains(string(audit), "error") || !strings.Contains(string(audit), "input_hash") {
		t.Fatal("malformed response or retry failure was lost")
	}
	row, _, err := d.FindingVerdictByID(t.Context(), rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if row.TechnicalVerdict != db.VerdictUnverified {
		t.Fatal("parse failure was treated as a refutation")
	}
}

func TestVerificationRetryReusesFrozenExecutionInput(t *testing.T) {
	d := privateVerificationDB(t)
	_, job, store := verificationHTTPFixture(t, d)
	b, err := d.PrepareVerificationInput(t.Context(), job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.LoadVerificationBodies(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	first, err := d.RecordVerificationExecutionInput(t.Context(), job.ID, job.LeaseGeneration, b)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	// Hydration is not allowed to change an already persisted execution input.
	b.Refs[len(b.Refs)-1].RespBody.Text = "DIFFERENT_BODY_VIEW"
	saved, err := d.RecordVerificationExecutionInput(t.Context(), job.ID, job.LeaseGeneration, b)
	if err != nil {
		t.Fatal(err)
	}
	savedJSON, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(savedJSON), "DIFFERENT_BODY_VIEW") || !strings.Contains(string(savedJSON), "CROSS_ACCOUNT_VALUE") {
		t.Fatal("retry replaced the original body view")
	}
	var hash string
	if err = d.QueryRow(`SELECT execution_hash FROM verification_jobs WHERE id=$1`, job.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(firstJSON)
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("execution hash does not identify the original input")
	}
}

func TestRealGoalVerifierUsesFactMaterialAndGoalContract(t *testing.T) {
	d := privateVerificationDB(t)
	defer d.Close()
	tk, err := d.CreateTask(t.Name(), "inventory", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(tk.ExplorationID)
	g, err := es.AddGoal(map[string]any{"text": "列出已核验的服务与路径"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	f, err := es.AddNode(db.KindFact, map[string]any{"summary": "清单已采集", "detail": map[string]any{"service": "SERVICE_PROOF", "paths": []string{"/one", "/two"}}}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := es.SubmitGoalEvidence(t.Context(), g, f, "明确服务及路径覆盖要求")
	if err != nil {
		t.Fatal(err)
	}
	job, err := d.ClaimVerificationJobByID(t.Context(), id, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	p := &verificationInputProvider{reply: `{"goal_verdict":"met","rationale":"清单给出已核验的服务及路径"}`}
	if err = processVerificationJobWith(t.Context(), d, &agent.LLMVerifier{Prov: p}, job); err != nil {
		t.Fatal(err)
	}
	input := p.request.Messages[0].Text()
	if !strings.Contains(input, "SERVICE_PROOF") || !strings.Contains(input, "明确服务及路径覆盖要求") || !strings.Contains(p.request.System[0], "goal_verdict") {
		t.Fatal("goal verifier lost material, reason or dedicated contract")
	}
	var state string
	var result []byte
	if err = d.QueryRow(`SELECT state FROM exploration_nodes WHERE id=$1`, g).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "met" {
		t.Fatalf("goal state %s", state)
	}
	if err = d.QueryRow(`SELECT result FROM verification_jobs WHERE id=$1`, id).Scan(&result); err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err = json.Unmarshal(result, &saved); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "清单给出已核验") {
		t.Fatal("goal rationale not retained")
	}
}

func (p *verificationInputProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("non-streaming expected")
}
func (p *verificationInputProvider) Complete(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.request = r
	p.calls++
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.reply)}}, "end_turn", llm.Usage{}, nil
}

func TestRealVerifierReceivesFindingMaterial(t *testing.T) {
	d := privateVerificationDB(t)
	defer d.Close()
	tk, err := d.CreateTask(t.Name(), "verify", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := d.Exploration(tk.ExplorationID).RecordFinding(t.Context(), db.RecordFindingInput{TaskID: tk.ID,
		Summary: "candidate", Name: "fixture", VulnClass: "test", Severity: "low", Evidence: "RAW_PROOF_MARKER", EvidenceNote: "NOTE_MARKER", Preconditions: []string{"OWN_ACCOUNT"}, Worker: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE findings SET accepted_claim='普通文本范围' WHERE id=$1`, rec.FindingID); err != nil {
		t.Fatal(err)
	}
	b, err := d.BuildFindingBundle(t.Context(), rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	p := &verificationInputProvider{reply: `{"decision":"needs_review","missing_evidence":["cross-account control"]}`}
	v := &agent.LLMVerifier{Prov: p}
	if _, err := v.Verify(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 {
		t.Fatal("real provider completion was not reached")
	}
	raw := p.request.Messages[0].Text()
	for _, marker := range []string{"RAW_PROOF_MARKER", "NOTE_MARKER", "OWN_ACCOUNT", "普通文本范围"} {
		if !strings.Contains(raw, marker) {
			t.Errorf("model input lost %s", marker)
		}
	}
}
