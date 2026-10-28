package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

const JobArchiveSuspended = "archive_suspended"

var lifecycleArchiveTables = []string{"finding_claims", "finding_human_decisions", "finding_retests", "verification_jobs", "verdict_events", "event_jobs", "report_runs"}

const taskFindingIDs = `SELECT id FROM findings WHERE task_id=$1`
const taskVerificationScope = `(subject_kind='finding' AND subject_id IN (` + taskFindingIDs + `)) OR
 (subject_kind='goal' AND subject_id IN (SELECT n.id FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1))`

// Select by authoritative event/run ownership as well as the legacy payload.
// Text comparison avoids casting malformed JSON identifiers to bigint.
func findingEventJobs(ids string) string {
	return `SELECT j.id FROM event_jobs j WHERE j.source_event_id IN (SELECT id FROM verdict_events WHERE finding_id IN (` + ids + `))
 OR j.payload->>'finding_id' IN (SELECT id::text FROM (` + ids + `) f)
 OR j.id IN (SELECT job_id FROM report_runs WHERE finding_id IN (` + ids + `))`
}

func freezeTaskLifecycleTx(tx *sql.Tx, taskID int64) error {
	statements := []string{
		`UPDATE verification_jobs SET state='archive_suspended',lease_until=NULL,lease_generation=lease_generation+1 WHERE (` + taskVerificationScope + `) AND state IN ('queued','leased')`,
		`UPDATE event_jobs j SET state='archive_suspended',lease_until=NULL,lease_generation=lease_generation+1 WHERE id IN (` + findingEventJobs(taskFindingIDs) + `) AND (state IN ('queued','leased') OR (state='done' AND NOT EXISTS(SELECT 1 FROM report_runs r WHERE r.job_id=j.id AND r.state='committed')))`,
		`UPDATE report_runs SET state='expired',last_error='归档中断，旧执行不得提交',finished_at=clock_timestamp() WHERE finding_id IN (` + taskFindingIDs + `) AND state IN ('prepared','running')`,
		`UPDATE finding_retests SET status='stopped',error='归档中断，请在恢复后重新发起',finished_at=clock_timestamp() WHERE finding_id IN (` + taskFindingIDs + `) AND status IN ('pending','running')`,
	}
	for _, q := range statements {
		if _, err := tx.Exec(q, taskID); err != nil {
			return err
		}
	}
	return nil
}
func thawTaskLifecycleTx(tx *sql.Tx, taskID int64) error {
	for _, q := range []string{
		`UPDATE verification_jobs SET state='queued',lease_until=NULL,lease_generation=lease_generation+1 WHERE (` + taskVerificationScope + `) AND state='archive_suspended'`,
		`UPDATE event_jobs SET state='queued',lease_until=NULL,lease_generation=lease_generation+1 WHERE id IN (` + findingEventJobs(taskFindingIDs) + `) AND state='archive_suspended'`,
	} {
		if _, err := tx.Exec(q, taskID); err != nil {
			return err
		}
	}
	return nil
}
func purgeFindingLifecycleTx(tx *sql.Tx, ids string, arg int64) error {
	jobs := findingEventJobs(ids)
	for _, q := range []string{
		`DELETE FROM event_jobs WHERE id IN (` + jobs + `)`,
		`DELETE FROM report_runs WHERE finding_id IN (` + ids + `)`,
		`DELETE FROM verification_jobs WHERE subject_kind='finding' AND subject_id IN (` + ids + `)`,
	} {
		if _, err := tx.Exec(q, arg); err != nil {
			return err
		}
	}
	return nil
}
func retireTaskLifecycleTx(tx *sql.Tx, taskID int64, purgeFindings bool) error {
	if _, err := tx.Exec(`DELETE FROM verification_jobs WHERE subject_kind='goal' AND subject_id IN
 (SELECT n.id FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1)`, taskID); err != nil {
		return err
	}
	if purgeFindings {
		return purgeFindingLifecycleTx(tx, taskFindingIDs, taskID)
	}
	for _, q := range []string{
		`UPDATE verification_jobs SET state='superseded',lease_until=NULL,lease_generation=lease_generation+1,last_error='原任务已删除' WHERE subject_kind='finding' AND subject_id IN (` + taskFindingIDs + `) AND state IN ('queued','leased','archive_suspended')`,
		`UPDATE event_jobs j SET state='superseded',lease_until=NULL,lease_generation=lease_generation+1,last_error='原任务已删除' WHERE id IN (` + findingEventJobs(taskFindingIDs) + `) AND (state IN ('queued','leased','archive_suspended') OR (state='done' AND NOT EXISTS(SELECT 1 FROM report_runs r WHERE r.job_id=j.id AND r.state='committed')))`,
		`UPDATE report_runs SET state='superseded',last_error='原任务已删除',finished_at=clock_timestamp() WHERE finding_id IN (` + taskFindingIDs + `) AND state IN ('prepared','running')`,
		`UPDATE verdict_events SET processed_at=COALESCE(processed_at,clock_timestamp()) WHERE finding_id IN (` + taskFindingIDs + `)`,
		`UPDATE finding_retests SET status='stopped',error='原任务已删除',finished_at=clock_timestamp() WHERE finding_id IN (` + taskFindingIDs + `) AND status IN ('pending','running')`,
	} {
		if _, err := tx.Exec(q, taskID); err != nil {
			return err
		}
	}
	return nil
}

func validateLifecycleArchive(s *TaskArchiveSnapshot) error {
	if s.FormatVersion < 4 {
		return nil
	}
	all := map[string][]map[string]any{}
	for _, name := range append([]string{"findings", "exploration_nodes"}, lifecycleArchiveTables...) {
		raw, ok := s.Tables[name]
		if !ok || len(raw) == 0 {
			return fmt.Errorf("archive missing lifecycle table %s", name)
		}
		rows, err := decodeArchiveRows(raw)
		if err != nil {
			return err
		}
		if s.DataCounts[name] != int64(len(rows)) {
			return fmt.Errorf("archive row count mismatch: %s", name)
		}
		seen := map[int64]bool{}
		for _, row := range rows {
			id, ok := jsonInt64(row["id"])
			if !ok || id <= 0 || seen[id] {
				return fmt.Errorf("invalid/duplicate archive id: %s", name)
			}
			seen[id] = true
		}
		all[name] = rows
	}
	nodes := map[int64]string{}
	findings := map[int64]bool{}
	findingNodes := map[int64]int64{}
	events := map[int64]int64{}
	jobs := map[int64]int64{}
	runs := map[int64]int64{}
	for _, row := range all["exploration_nodes"] {
		id, _ := jsonInt64(row["id"])
		exp, _ := jsonInt64(row["exploration_id"])
		if exp != s.ExplorationID {
			return errors.New("archive node belongs to another exploration")
		}
		nodes[id], _ = row["kind"].(string)
	}
	for _, row := range all["findings"] {
		id, _ := jsonInt64(row["id"])
		task, _ := jsonInt64(row["task_id"])
		node, _ := jsonInt64(row["node_id"])
		if task != s.TaskID || (node > 0 && nodes[node] == "") {
			return errors.New("archive finding belongs to another task/node")
		}
		findings[id] = true
		findingNodes[id] = node
	}
	for _, name := range []string{"finding_claims", "finding_human_decisions", "finding_retests", "verdict_events", "report_runs"} {
		for _, row := range all[name] {
			fid, _ := jsonInt64(row["finding_id"])
			if !findings[fid] {
				return fmt.Errorf("%s references a finding outside this archive", name)
			}
		}
	}
	for _, row := range all["verification_jobs"] {
		kind, _ := row["subject_kind"].(string)
		subject, _ := jsonInt64(row["subject_id"])
		if !((kind == SubjectFinding && findings[subject]) || (kind == SubjectGoal && nodes[subject] == "goal")) {
			return errors.New("verification job subject outside archive")
		}
		if manifest, ok := row["input_manifest"].(map[string]any); ok {
			raw, _ := json.Marshal(manifest)
			var bundle EvidenceBundle
			if err := json.Unmarshal(raw, &bundle); err != nil {
				return err
			}
			hash, err := bundleHash(&bundle)
			if err != nil {
				return err
			}
			stored, _ := row["input_hash"].(string)
			if bundle.SubjectKind != kind || bundle.SubjectID != subject || bundle.TaskID != s.TaskID || hash != stored || bundle.InputHash != stored {
				return errors.New("frozen verification input scope/hash mismatch")
			}
		}
	}
	for _, row := range all["verdict_events"] {
		id, _ := jsonInt64(row["id"])
		events[id], _ = jsonInt64(row["finding_id"])
	}
	for _, row := range all["event_jobs"] {
		id, _ := jsonInt64(row["id"])
		event, _ := jsonInt64(row["source_event_id"])
		payload, _ := row["payload"].(map[string]any)
		fid, _ := jsonInt64(payload["finding_id"])
		if !findings[fid] || (event > 0 && events[event] != fid) {
			return errors.New("report job/event ownership mismatch")
		}
		jobs[id] = fid
		if snap, ok := row["report_snapshot"].(map[string]any); ok {
			hash, _ := row["report_snapshot_hash"].(string)
			if err := validateArchivedReportSnapshot(snap, fid, s.TaskID, findingNodes[fid], hash); err != nil {
				return err
			}
		}
	}
	for _, row := range all["report_runs"] {
		id, _ := jsonInt64(row["id"])
		job, _ := jsonInt64(row["job_id"])
		fid, _ := jsonInt64(row["finding_id"])
		if jobs[job] != fid {
			return errors.New("report run job/finding mismatch")
		}
		runs[id] = fid
		snap, _ := row["snapshot"].(map[string]any)
		hash, _ := row["snapshot_hash"].(string)
		if err := validateArchivedReportSnapshot(snap, fid, s.TaskID, findingNodes[fid], hash); err != nil {
			return err
		}
	}
	for _, row := range all["findings"] {
		id, _ := jsonInt64(row["id"])
		run, _ := jsonInt64(row["report_run_id"])
		if run > 0 && runs[run] != id {
			return errors.New("finding report audit pointer outside archive")
		}
		human, _ := jsonInt64(row["human_revision"])
		if human > 0 {
			found := false
			for _, h := range all["finding_human_decisions"] {
				fid, _ := jsonInt64(h["finding_id"])
				rev, _ := jsonInt64(h["human_revision"])
				if fid == id && rev == human {
					found = true
				}
			}
			if !found {
				return errors.New("missing current human decision audit")
			}
		}
		review, _ := jsonInt64(row["review_run_id"])
		if review > 0 {
			found := false
			for _, r := range all["finding_retests"] {
				rid, _ := jsonInt64(r["id"])
				fid, _ := jsonInt64(r["finding_id"])
				if rid == review && fid == id {
					found = true
				}
			}
			if !found {
				return errors.New("review audit pointer outside archive")
			}
		}
	}
	return nil
}
func validateArchivedReportSnapshot(snap map[string]any, finding, task, node int64, expectedHash string) error {
	fid, _ := jsonInt64(snap["finding_id"])
	tid, _ := jsonInt64(snap["task_id"])
	nid, _ := jsonInt64(snap["finding_node_id"])
	if fid != finding || tid != task || nid != node {
		return errors.New("frozen report scope outside archive")
	}
	raw, _ := json.Marshal(snap)
	var value ReportSnapshot
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	hash, err := reportSnapshotHash(value)
	if err != nil {
		return err
	}
	if expectedHash == "" || hash != expectedHash {
		return errors.New("archived report snapshot hash mismatch")
	}
	return nil
}

// Recheck frozen lifecycle rows before compaction. A package from a failed
// earlier attempt must not remove newer human decisions or lease generations.
func verifyFrozenLifecycleTx(tx *sql.Tx, s *TaskArchiveSnapshot) error {
	queries := map[string]string{
		"findings":          `SELECT * FROM findings WHERE task_id=$1 ORDER BY id`,
		"exploration_nodes": `SELECT n.* FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id WHERE t.id=$1 ORDER BY n.id`,
		"verification_jobs": `SELECT * FROM verification_jobs WHERE ` + taskVerificationScope + ` ORDER BY id`,
		"event_jobs":        `SELECT * FROM event_jobs WHERE id IN (` + findingEventJobs(taskFindingIDs) + `) ORDER BY id`,
	}
	for _, name := range []string{"finding_claims", "finding_human_decisions", "finding_retests", "verdict_events", "report_runs"} {
		queries[name] = `SELECT * FROM ` + name + ` WHERE finding_id IN (` + taskFindingIDs + `) ORDER BY id`
	}
	for name, q := range queries {
		raw, _, err := queryArchiveRows(tx, q, s.TaskID)
		if err != nil {
			return err
		}
		before, err := canonicalReportHash(s.Tables[name])
		if err != nil {
			return err
		}
		after, err := canonicalReportHash(raw)
		if err != nil {
			return err
		}
		if before != after {
			return fmt.Errorf("archive lifecycle changed since snapshot: %s", name)
		}
	}
	return nil
}

func normalizeLifecycleArchiveTables(tables map[string]json.RawMessage, version int) error {
	rows, err := decodeArchiveRows(tables["findings"])
	if err != nil {
		return err
	}
	for _, r := range rows {
		defaults := map[string]any{"technical_verdict": VerdictUnverified, "proposed_claim": "", "proposed_detail": map[string]any{}, "accepted_claim": "", "accepted_detail": map[string]any{}, "input_manifest_hash": "", "legacy_source": "", "verdict_policy_version": "", "report_policy_version": ""}
		for _, k := range []string{"input_revision", "verdict_revision", "human_revision", "verdict_input_revision", "report_input_revision", "report_verdict_revision", "report_human_revision", "evidence_version", "report_evidence_version"} {
			defaults[k] = 0
		}
		for k, v := range defaults {
			if r[k] == nil {
				r[k] = v
			}
		}
		if version < 4 {
			if run, ok := jsonInt64(r["review_run_id"]); ok && run > 0 {
				note, _ := r["review_note"].(string)
				r["review_note"] = fmt.Sprintf("%s\n旧存档复核记录 #%d 未包含完整运行，仅保留意见。", note, run)
			}
			r["review_run_id"] = nil
			for _, k := range []string{"input_revision", "verdict_revision", "human_revision", "verdict_input_revision", "report_input_revision", "report_verdict_revision", "report_human_revision"} {
				r[k] = 0
			}
			r["technical_verdict"] = VerdictUnverified
			r["accepted_claim"] = ""
			r["accepted_detail"] = map[string]any{}
			r["verdict_policy_version"] = ""
			r["report_policy_version"] = ""
			r["report_run_id"] = nil
			r["input_manifest_hash"] = ""
			r["legacy_source"] = fmt.Sprintf("legacy_archive_v%d", version)
			r["proposed_claim"] = r["summary"]
			r["proposed_detail"] = map[string]any{"vulnclass": r["vulnclass"], "name": r["name"], "severity": r["severity"], "evidence": r["evidence"]}
			if report, _ := r["report"].(string); report != "" {
				r["report_evidence_version"] = -1
			}
		}
	}
	tables["findings"], err = json.Marshal(rows)
	if err != nil {
		return err
	}
	rows, err = decodeArchiveRows(tables["exploration_nodes"])
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r["content_version"] == nil {
			r["content_version"] = 0
		}
		if r["evaluation_revision"] == nil {
			r["evaluation_revision"] = 0
		}
		if r["evaluation_input_hash"] == nil {
			r["evaluation_input_hash"] = ""
		}
		if version < 4 {
			r["evaluation_revision"] = 0
			r["evaluation_input_hash"] = ""
			if r["kind"] == "goal" && (r["state"] == "met" || r["state"] == "submitted") {
				r["state"] = "open"
			}
		}
	}
	tables["exploration_nodes"], err = json.Marshal(rows)
	return err
}

func restoreLifecycleArchiveTx(tx *sql.Tx, s *TaskArchiveSnapshot, tables map[string]json.RawMessage) error {
	if s.FormatVersion < 4 {
		// Older compaction left polymorphic jobs in the hot DB. Retain that
		// history, but fence every old lease and free the old deduplication keys
		// before these subject IDs become live again.
		for _, q := range []string{
			`UPDATE verification_jobs SET state='superseded',lease_until=NULL,lease_generation=lease_generation+1,
 idempotency_key='legacy_archive:'||id::text||':'||idempotency_key,last_error='旧存档恢复，历史执行已作废' WHERE (` + taskVerificationScope + `)`,
			`UPDATE event_jobs SET state='superseded',lease_until=NULL,lease_generation=lease_generation+1,
 dedup_key='legacy_archive:'||id::text||':'||dedup_key,payload=payload||jsonb_build_object('legacy_source_event_id',source_event_id),source_event_id=NULL,
 last_error='旧存档恢复，历史报告执行已作废' WHERE id IN (` + findingEventJobs(taskFindingIDs) + `)`,
			`UPDATE report_runs SET state='expired',last_error='旧存档恢复，旧执行不得提交',finished_at=clock_timestamp()
 WHERE finding_id IN (` + taskFindingIDs + `) AND state IN ('prepared','running')`,
		} {
			if _, err := tx.Exec(q, s.TaskID); err != nil {
				return err
			}
		}
		// Legacy packages have no complete verdict audit. Restore explicit human
		// rejection conservatively; never turn historical confirmation into support.
		_, err := tx.Exec(`UPDATE findings SET technical_verdict=CASE WHEN status='false_positive' OR review_decision='false_positive' THEN 'refuted' ELSE 'needs_review' END,
 human_revision=1,verdict_revision=1,verdict_input_revision=input_revision,verdict_policy_version=$2
 WHERE task_id=$1 AND (status IN ('confirmed','false_positive') OR review_decision<>'')`, s.TaskID, VerdictPolicyVersion)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO finding_human_decisions(finding_id,human_revision,decision,source,note,actor)
 SELECT id,human_revision,technical_verdict,'legacy_archive','旧存档人工意见；原确认须重新复核','system' FROM findings WHERE task_id=$1 AND human_revision>0`, s.TaskID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO verdict_events(finding_id,kind,finding_revision,payload)
 SELECT id,CASE WHEN technical_verdict='refuted' THEN 'finding_refuted' ELSE 'finding_needs_review' END,verdict_revision,
 jsonb_build_object('source','legacy_archive','human_revision',human_revision) FROM findings WHERE task_id=$1 AND human_revision>0`, s.TaskID)
		if err != nil {
			return err
		}
		return nil
	}
	for _, name := range lifecycleArchiveTables {
		rows, err := decodeArchiveRows(tables[name])
		if err != nil {
			return err
		}
		for _, r := range rows {
			if name == "verification_jobs" || name == "event_jobs" {
				gen, ok := jsonInt64(r["lease_generation"])
				if !ok || gen < 0 || gen == int64(^uint64(0)>>1) {
					return errors.New("invalid archived lease generation")
				}
				if r["state"] == "queued" || r["state"] == "leased" || r["state"] == JobArchiveSuspended {
					r["state"] = JobArchiveSuspended
					r["lease_generation"] = gen + 1
				}
				r["lease_until"] = nil
			}
			if name == "report_runs" && (r["state"] == "prepared" || r["state"] == "running") {
				r["state"] = "expired"
				r["last_error"] = "恢复时作废旧执行"
			}
			if name == "finding_retests" {
				if r["status"] == "pending" || r["status"] == "running" {
					r["status"] = "stopped"
					r["error"] = "恢复后请重新发起复核/复测"
				}
				if id, ok := jsonInt64(r["conversation_id"]); ok {
					var exists bool
					if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversations WHERE id=$1)`, id).Scan(&exists); err != nil {
						return err
					}
					if !exists {
						r["conversation_id"] = nil
					}
				}
			}
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			return err
		}
		if err = insertArchiveRows(tx, name, raw); err != nil {
			return fmt.Errorf("restore lifecycle %s: %w", name, err)
		}
	}
	return nil
}
