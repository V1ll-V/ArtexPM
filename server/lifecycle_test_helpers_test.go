package server

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Exercise the actual persisted authority, never manufacture a report context.
func acceptedReportContext(t *testing.T, s *Server, findingID int64) context.Context {
	t.Helper()
	ctx := t.Context()
	pg := s.m.pg
	if _, _, _, err := pg.SetFindingStatusWithNotify(ctx, findingID, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pg.FanOutVerdictEvents(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	job, err := pg.ClaimEventJob(ctx, db.EventJobReportRun, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	run, err := pg.PrepareReportRun(ctx, job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if run.Snapshot.FindingID != findingID {
		t.Fatal("claimed another finding", run.Snapshot.FindingID, findingID)
	}
	if err = s.evidenceStore().LoadVerificationBodies(ctx, run.Snapshot.Evidence); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.RecordReportExecutionInput(ctx, run, &db.ReportExecutionInput{Snapshot: run.Snapshot, SystemPrompt: "local fixture"}); err != nil {
		t.Fatal(err)
	}
	return db.WithReportRun(ctx, run)
}
