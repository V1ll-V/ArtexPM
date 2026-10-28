package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrReportContextRequired      = errors.New("报告写入需要服务端绑定的持久化报告任务，请通过验收报告流程生成")
	ErrReportStale                = errors.New("报告所依据的验收范围或版本已变化，旧报告不能提交")
	ErrReportLeaseLost            = errors.New("报告任务租约已失效")
	ErrReportSubjectMismatch      = errors.New("报告任务与漏洞主体不匹配")
	ErrReportAlreadyCommitted     = errors.New("本次报告任务已提交，不能用另一份内容覆盖")
	ErrReportAtomicCommitRequired = errors.New("报告任务只能在报告成功持久化的同一事务中确认完成")
)

type ReportSnapshot struct {
	FindingID       int64           `json:"finding_id"`
	NodeID          int64           `json:"finding_node_id"`
	TaskID          int64           `json:"task_id"`
	InputRevision   int64           `json:"input_revision"`
	VerdictRevision int64           `json:"verdict_revision"`
	HumanRevision   int64           `json:"human_revision"`
	EvidenceVersion int64           `json:"evidence_version"`
	PolicyVersion   string          `json:"policy_version"`
	AcceptedClaim   string          `json:"accepted_claim"`
	AcceptedDetail  json.RawMessage `json:"accepted_detail"`
	Evidence        *EvidenceBundle `json:"evidence"`
}

type ReportRun struct {
	ID              int64          `json:"id"`
	JobID           int64          `json:"job_id"`
	LeaseGeneration int64          `json:"lease_generation"`
	SnapshotHash    string         `json:"snapshot_hash"`
	Snapshot        ReportSnapshot `json:"snapshot"`
	State           string         `json:"state"`
}

type ReportExecutionInput struct {
	SystemPrompt string         `json:"system_prompt"`
	Snapshot     ReportSnapshot `json:"snapshot"`
}

type reportContextKey struct{}
type reportScope struct {
	runID, jobID, generation int64
	hash                     string
}

// Only trusted host code binds a persisted report execution to a tool call.
// No job/version/lease parameter supplied by a model grants this capability.
func WithReportRun(ctx context.Context, run *ReportRun) context.Context {
	if run == nil {
		return ctx
	}
	return context.WithValue(ctx, reportContextKey{}, reportScope{run.ID, run.JobID, run.LeaseGeneration, run.SnapshotHash})
}

func canonicalReportHash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&decoded); err != nil {
		return "", err
	}
	raw, err = json.Marshal(decoded)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func reportSnapshotHash(snapshot ReportSnapshot) (string, error) {
	if snapshot.Evidence != nil {
		plain := manifestView(snapshot.Evidence)
		snapshot.Evidence = &plain
	}
	return canonicalReportHash(snapshot)
}

func currentReportSnapshotTx(ctx context.Context, tx *sql.Tx, findingID, verdictRevision int64) (ReportSnapshot, error) {
	var snapshot ReportSnapshot
	if verdictRevision <= 0 {
		return snapshot, ErrReportStale
	}
	// buildFindingBundleTx takes task -> finding locks and the archive barrier.
	bundle, err := buildFindingBundleTx(ctx, tx, findingID)
	if err != nil {
		return snapshot, err
	}
	if !FindingVerdictEffective(VerdictState{TechnicalVerdict: bundle.TechnicalVerdict, InputRevision: bundle.InputRevision,
		VerdictRevision: bundle.VerdictRevision, VerdictInputRevision: bundle.VerdictInputRevision, VerdictPolicyVersion: bundle.VerdictPolicyVersion}) {
		return snapshot, ErrVerdictNotSupported
	}
	if bundle.VerdictRevision != verdictRevision {
		return snapshot, ErrReportStale
	}
	snapshot = ReportSnapshot{FindingID: findingID, TaskID: bundle.TaskID, InputRevision: bundle.InputRevision,
		VerdictRevision: bundle.VerdictRevision, HumanRevision: bundle.HumanRevision, EvidenceVersion: bundle.EvidenceVer,
		PolicyVersion: bundle.VerdictPolicyVersion, AcceptedClaim: bundle.PreviousAcceptedClaim, Evidence: bundle}
	var detail []byte
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(node_id,0),COALESCE(accepted_detail,'{}') FROM findings WHERE id=$1`, findingID).Scan(&snapshot.NodeID, &detail)
	if err != nil {
		return snapshot, err
	}
	snapshot.AcceptedDetail = json.RawMessage(detail)
	if snapshot.NodeID <= 0 {
		return snapshot, ErrFindingNotFound
	}
	if strings.TrimSpace(snapshot.AcceptedClaim) == "" {
		return snapshot, ErrVerdictNotSupported
	}
	return snapshot, nil
}

type reportJobRow struct {
	kind, state, hash string
	generation        int64
	valid             bool
	payload, snapshot []byte
}

func readReportJobTx(ctx context.Context, tx *sql.Tx, id int64, lock bool) (j reportJobRow, err error) {
	query := `SELECT job_kind,state,lease_generation,COALESCE(lease_until>clock_timestamp(),false),payload,report_snapshot,report_snapshot_hash FROM event_jobs WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	err = tx.QueryRowContext(ctx, query, id).Scan(&j.kind, &j.state, &j.generation, &j.valid, &j.payload, &j.snapshot, &j.hash)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrReportLeaseLost
	}
	return
}
func validReportJob(j reportJobRow, generation int64) error {
	if j.kind != EventJobReportRun {
		return ErrReportSubjectMismatch
	}
	if j.state != JobLeased || j.generation != generation || !j.valid {
		return ErrReportLeaseLost
	}
	return nil
}

func reportJobMatchesSnapshot(j reportJobRow, snapshot ReportSnapshot) error {
	var payload struct {
		FindingID       int64 `json:"finding_id"`
		VerdictRevision int64 `json:"verdict_revision"`
	}
	if err := json.Unmarshal(j.payload, &payload); err != nil {
		return err
	}
	if payload.FindingID != snapshot.FindingID || payload.VerdictRevision != snapshot.VerdictRevision {
		return ErrReportSubjectMismatch
	}
	return nil
}

func (d *DB) PrepareReportRun(ctx context.Context, jobID, generation int64) (out *ReportRun, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		j, e := readReportJobTx(ctx, tx, jobID, false)
		if e != nil {
			return e
		}
		if e = validReportJob(j, generation); e != nil {
			return e
		}
		var payload struct {
			FindingID       int64 `json:"finding_id"`
			VerdictRevision int64 `json:"verdict_revision"`
		}
		if e = json.Unmarshal(j.payload, &payload); e != nil {
			return e
		}
		if payload.FindingID <= 0 {
			return ErrReportSubjectMismatch
		}
		current, e := currentReportSnapshotTx(ctx, tx, payload.FindingID, payload.VerdictRevision)
		if e != nil {
			return e
		}
		hash, e := reportSnapshotHash(current)
		if e != nil {
			return e
		}
		j, e = readReportJobTx(ctx, tx, jobID, true)
		if e != nil {
			return e
		}
		if e = validReportJob(j, generation); e != nil {
			return e
		}
		if e = reportJobMatchesSnapshot(j, current); e != nil {
			return e
		}
		if len(j.snapshot) > 0 {
			var frozen ReportSnapshot
			if e = json.Unmarshal(j.snapshot, &frozen); e != nil {
				return e
			}
			frozenHash, e := reportSnapshotHash(frozen)
			if e != nil {
				return e
			}
			if j.hash != hash || frozenHash != hash {
				return ErrReportStale
			}
			current = frozen
		} else {
			raw, e := json.Marshal(current)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE event_jobs SET report_snapshot=$2,report_snapshot_hash=$3 WHERE id=$1`, jobID, string(raw), hash); e != nil {
				return e
			}
		}
		raw, e := json.Marshal(current)
		if e != nil {
			return e
		}
		run := &ReportRun{JobID: jobID, LeaseGeneration: generation, Snapshot: current, SnapshotHash: hash}
		e = tx.QueryRowContext(ctx, `INSERT INTO report_runs(job_id,lease_generation,finding_id,snapshot,snapshot_hash)
   VALUES($1,$2,$3,$4,$5) ON CONFLICT(job_id,lease_generation) DO UPDATE SET job_id=report_runs.job_id RETURNING id,state`,
			jobID, generation, current.FindingID, string(raw), hash).Scan(&run.ID, &run.State)
		if e == nil {
			out = run
		}
		return e
	})
	return
}

func readReportRunTx(ctx context.Context, tx *sql.Tx, id int64, lock bool) (run ReportRun, err error) {
	query := `SELECT id,job_id,lease_generation,snapshot,snapshot_hash,state FROM report_runs WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, query, id).Scan(&run.ID, &run.JobID, &run.LeaseGeneration, &raw, &run.SnapshotHash, &run.State)
	if errors.Is(err, sql.ErrNoRows) {
		return run, ErrReportLeaseLost
	}
	if err != nil {
		return run, err
	}
	err = json.Unmarshal(raw, &run.Snapshot)
	return
}

func (d *DB) RecordReportExecutionInput(ctx context.Context, run *ReportRun, input *ReportExecutionInput) (out *ReportExecutionInput, err error) {
	if run == nil || input == nil {
		return nil, ErrReportContextRequired
	}
	hash, err := reportSnapshotHash(input.Snapshot)
	if err != nil {
		return nil, err
	}
	if hash != run.SnapshotHash {
		return nil, ErrReportStale
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(raw) > 512*1024 {
		return nil, fmt.Errorf("报告输入超过 512 KiB，请收敛范围")
	}
	executionHash, err := canonicalReportHash(input)
	if err != nil {
		return nil, err
	}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		j, e := readReportJobTx(ctx, tx, run.JobID, true)
		if e != nil {
			return e
		}
		if e = validReportJob(j, run.LeaseGeneration); e != nil {
			return e
		}
		if e = reportJobMatchesSnapshot(j, input.Snapshot); e != nil {
			return e
		}
		saved, e := readReportRunTx(ctx, tx, run.ID, true)
		if e != nil {
			return e
		}
		if saved.JobID != run.JobID || saved.LeaseGeneration != run.LeaseGeneration || saved.SnapshotHash != hash || j.hash != hash {
			return ErrReportSubjectMismatch
		}
		if saved.State != "prepared" && saved.State != "running" {
			return ErrReportLeaseLost
		}
		var stored []byte
		if e = tx.QueryRowContext(ctx, `SELECT execution_input FROM report_runs WHERE id=$1`, run.ID).Scan(&stored); e != nil {
			return e
		}
		if len(stored) > 0 {
			var previous ReportExecutionInput
			if e = json.Unmarshal(stored, &previous); e != nil {
				return e
			}
			out = &previous
			return nil
		}
		if _, e = tx.ExecContext(ctx, `UPDATE report_runs SET execution_input=$2,execution_hash=$3,state='running' WHERE id=$1`, run.ID, string(raw), executionHash); e != nil {
			return e
		}
		out = input
		return nil
	})
	return
}

func (d *DB) commitFindingReportBound(ctx context.Context, nodeID int64, report string, trafficVersion *int64) (count int64, err error) {
	scope, ok := ctx.Value(reportContextKey{}).(reportScope)
	if !ok {
		// Preserve the useful candidate error without granting any unbound write.
		var supported bool
		e := d.QueryRowContext(ctx, `SELECT `+EffectiveVerdictPredicate("f")+` FROM findings f WHERE node_id=$1`, nodeID).Scan(&supported)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return 0, e
		}
		if !supported {
			return 0, ErrVerdictNotSupported
		}
		return 0, ErrReportContextRequired
	}
	if strings.TrimSpace(report) == "" || len(report) > 512*1024 {
		return 0, fmt.Errorf("报告不能为空或超过 512 KiB")
	}
	reportSum := sha256.Sum256([]byte(report))
	reportHash := hex.EncodeToString(reportSum[:])
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		run, e := readReportRunTx(ctx, tx, scope.runID, false)
		if e != nil {
			return e
		}
		if run.JobID != scope.jobID || run.LeaseGeneration != scope.generation || run.SnapshotHash != scope.hash || run.Snapshot.NodeID != nodeID {
			return ErrReportSubjectMismatch
		}
		current, e := currentReportSnapshotTx(ctx, tx, run.Snapshot.FindingID, run.Snapshot.VerdictRevision)
		if e != nil {
			return e
		}
		hash, e := reportSnapshotHash(current)
		if e != nil {
			return e
		}
		frozenHash, e := reportSnapshotHash(run.Snapshot)
		if e != nil {
			return e
		}
		if hash != scope.hash || frozenHash != scope.hash {
			return ErrReportStale
		}
		if trafficVersion != nil && *trafficVersion != run.Snapshot.EvidenceVersion {
			return ErrEvidenceConflict
		}
		j, e := readReportJobTx(ctx, tx, scope.jobID, true)
		if e != nil {
			return e
		}
		run, e = readReportRunTx(ctx, tx, scope.runID, true)
		if e != nil {
			return e
		}
		if j.kind != EventJobReportRun || j.hash != scope.hash || j.generation != scope.generation {
			return ErrReportLeaseLost
		}
		if e = reportJobMatchesSnapshot(j, run.Snapshot); e != nil {
			return e
		}
		if run.State == "committed" && j.state == "done" {
			var savedHash string
			if e = tx.QueryRowContext(ctx, `SELECT report_hash FROM report_runs WHERE id=$1`, run.ID).Scan(&savedHash); e != nil {
				return e
			}
			if savedHash != reportHash {
				return ErrReportAlreadyCommitted
			}
			count = 1
			return nil
		}
		if e = validReportJob(j, scope.generation); e != nil {
			return e
		}
		if run.State != "running" {
			return ErrReportLeaseLost
		}
		var execution []byte
		if e = tx.QueryRowContext(ctx, `SELECT execution_input FROM report_runs WHERE id=$1`, run.ID).Scan(&execution); e != nil {
			return e
		}
		var input ReportExecutionInput
		if len(execution) == 0 {
			return ErrReportContextRequired
		}
		if e = json.Unmarshal(execution, &input); e != nil {
			return e
		}
		if !VerificationMaterialComplete(input.Snapshot.Evidence) {
			return fmt.Errorf("报告缺少已校验的必要正文")
		}
		if _, e = tx.ExecContext(ctx, `UPDATE findings SET report=$2,report_evidence_version=$3,
   report_input_revision=$4,report_verdict_revision=$5,report_human_revision=$6,report_policy_version=$7,report_run_id=$8 WHERE id=$1`,
			current.FindingID, report, run.Snapshot.EvidenceVersion, run.Snapshot.InputRevision, run.Snapshot.VerdictRevision, run.Snapshot.HumanRevision, run.Snapshot.PolicyVersion, run.ID); e != nil {
			return e
		}
		// A failure/expiry here rolls back the report write as well.
		result, e := tx.ExecContext(ctx, `UPDATE event_jobs SET state='done',lease_until=NULL,last_error='',updated_at=now()
   WHERE id=$1 AND state='leased' AND lease_generation=$2 AND lease_until>clock_timestamp()`, scope.jobID, scope.generation)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrReportLeaseLost
		}
		if _, e = tx.ExecContext(ctx, `UPDATE report_runs SET state='committed',report_hash=$2,report_text=$3,finished_at=clock_timestamp(),last_error='' WHERE id=$1`, run.ID, reportHash, report); e != nil {
			return e
		}
		count = 1
		return nil
	})
	return
}
