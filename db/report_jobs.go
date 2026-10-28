package db

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"
)

func (d *DB) RecordReportOutput(ctx context.Context, run *ReportRun, raw string) error {
	if run == nil {
		return ErrReportContextRequired
	}
	truncated := len(raw) > 512*1024
	if truncated {
		raw = raw[:512*1024]
	}
	encoding := "utf-8"
	if !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		raw = base64.StdEncoding.EncodeToString([]byte(raw))
		encoding = "base64"
	}
	result, err := d.ExecContext(ctx, `UPDATE report_runs r SET raw_output=$2,output_encoding=$3,output_truncated=$4
 WHERE r.id=$1 AND r.job_id=$5 AND r.lease_generation=$6 AND r.snapshot_hash=$7 AND r.state='running'
 AND EXISTS(SELECT 1 FROM event_jobs j WHERE j.id=r.job_id AND j.job_kind='report_run'
 AND j.state='leased' AND j.lease_generation=r.lease_generation AND j.lease_until>clock_timestamp())`,
		run.ID, raw, encoding, truncated, run.JobID, run.LeaseGeneration, run.SnapshotHash)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrReportLeaseLost
	}
	return nil
}

func (d *DB) SupersedeReportJob(ctx context.Context, id, generation int64, reason string) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE event_jobs SET state='superseded',lease_until=NULL,last_error=$3,updated_at=now()
   WHERE id=$1 AND job_kind='report_run' AND state='leased' AND lease_generation=$2`, id, generation, reason)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE report_runs SET state='superseded',last_error=$3,finished_at=clock_timestamp()
   WHERE job_id=$1 AND lease_generation=$2 AND state IN ('prepared','running')`, id, generation, reason)
		return err
	})
}

// Recover crashes before/after preparation, and repair legacy acknowledgements
// that have no committed durable report execution. Modern commits are atomic.
func (d *DB) RecoverReportJobs(ctx context.Context, maxAttempts int) error {
	if maxAttempts < 1 {
		return fmt.Errorf("报告重试上限必须为正数")
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE event_jobs j SET state='queued',lease_until=NULL,attempts=0,last_error='恢复没有持久化报告的旧确认',updated_at=now()
   WHERE j.job_kind='report_run' AND j.state='done'
   AND NOT EXISTS(SELECT 1 FROM report_runs r WHERE r.job_id=j.id AND r.state='committed')`); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,lease_generation FROM event_jobs WHERE job_kind='report_run'
   AND ((state='leased' AND (lease_until IS NULL OR lease_until<=clock_timestamp())) OR (state='queued' AND attempts>=$1))
   FOR UPDATE`, maxAttempts)
		if err != nil {
			return err
		}
		type expired struct{ id, generation int64 }
		var jobs []expired
		for rows.Next() {
			var j expired
			if err := rows.Scan(&j.id, &j.generation); err != nil {
				rows.Close()
				return err
			}
			jobs = append(jobs, j)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, j := range jobs {
			if _, err = tx.ExecContext(ctx, `UPDATE event_jobs SET state=CASE WHEN attempts>=$2 THEN 'failed' ELSE 'queued' END,
    lease_until=NULL,last_error='报告租约过期或重试耗尽',updated_at=now() WHERE id=$1`, j.id, maxAttempts); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE report_runs SET state='expired',last_error='租约已过期',finished_at=clock_timestamp()
    WHERE job_id=$1 AND lease_generation=$2 AND state IN ('prepared','running')`, j.id, j.generation); err != nil {
				return err
			}
		}
		return nil
	})
}
