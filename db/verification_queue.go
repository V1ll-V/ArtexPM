package db

import "context"

type VerificationQueueCandidate struct {
	ID          int64
	TaskID      int64
	SubjectKind string
}

// Read candidates before taking a lease, so a missing model cannot consume all
// retry attempts. ClaimVerificationJobByID performs the actual atomic claim.
func (d *DB) VerificationCandidates(ctx context.Context, after int64, includeFindings bool) ([]VerificationQueueCandidate, error) {
	rows, err := d.QueryContext(ctx, `SELECT j.id,j.subject_kind,COALESCE(f.task_id,t.id,0)
 FROM verification_jobs j
 LEFT JOIN findings f ON j.subject_kind='finding' AND f.id=j.subject_id
 LEFT JOIN exploration_nodes n ON j.subject_kind='goal' AND n.id=j.subject_id
 LEFT JOIN tasks t ON t.exploration_id=n.exploration_id
 WHERE j.id>$1 AND (j.state='queued' OR (j.state='leased' AND (j.lease_until IS NULL OR j.lease_until<now())))
 AND ($2 OR j.subject_kind='goal') ORDER BY j.id LIMIT 100`, after, includeFindings)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []VerificationQueueCandidate{}
	for rows.Next() {
		var row VerificationQueueCandidate
		if err = rows.Scan(&row.ID, &row.SubjectKind, &row.TaskID); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
