package server

import (
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestLifecycleArchiveRealPackageRestoresAuditReportAndFiles(t *testing.T) {
	d := privateVerificationDB(t)
	var schema string
	if err := d.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := uri.Query()
	q.Set("search_path", schema)
	uri.RawQuery = q.Encode()
	t.Setenv("ARTEX_PG_DSN", uri.String())
	s, f, _ := trafficEvidenceServer(t)
	s.ctx = t.Context()
	if _, _, _, err = s.m.pg.SetFindingStatusWithNotify(t.Context(), f.FindingID, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.m.pg.FanOutVerdictEvents(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	job, err := s.m.pg.ClaimEventJob(t.Context(), db.EventJobReportRun, time.Minute)
	if err != nil || job == nil {
		t.Fatal(job, err)
	}
	prompt, err := agent.ReportSystemPrompt(agent.ReporterDefaultPrompt, s.m.dir)
	if err != nil {
		t.Fatal(err)
	}
	provider := &verificationInputProvider{reply: `{"status":"ready","report":"# Accepted local fixture scope"}`}
	if err = processReportJobWith(t.Context(), s.m.pg, &agent.LLMReportWriter{Prov: provider}, job, prompt, s.evidenceStore().LoadVerificationBodies); err != nil {
		t.Fatal(err)
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || finding == nil || finding.TaskID == nil {
		t.Fatal(finding, err)
	}
	id := *finding.TaskID
	taskID := strconv.FormatInt(id, 10)
	localFile := filepath.Join(s.m.dir, "tasks", taskID, "uploads", "proof.txt")
	if err = os.MkdirAll(filepath.Dir(localFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(localFile, []byte("immutable local fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.m.SetTaskPaused(taskID, true); err != nil {
		t.Fatal(err)
	}
	a, err := s.m.pg.QueueTaskArchive(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal("real package archive", err)
	}
	if current, err := s.m.pg.GetFinding(f.FindingID); err != nil || current != nil {
		t.Fatal("hot finding survived archive", current, err)
	}
	if _, err = os.Stat(localFile); !os.IsNotExist(err) {
		t.Fatal("hot proof file survived archive", err)
	}
	cold, err := s.m.pg.GetTaskArchive(a.ID)
	if err != nil || cold.FormatVersion != db.TaskArchiveFormatVersion || cold.State != db.ArchiveReady {
		t.Fatal(cold, err)
	}
	if _, err = s.m.pg.QueueTaskArchiveRestore(a.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal("real package restore", err)
	}
	restored, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || restored == nil || restored.Report != "# Accepted local fixture scope" {
		t.Fatal(restored, err)
	}
	verdict, _, err := s.m.pg.FindingVerdictByID(t.Context(), f.FindingID)
	if err != nil || !db.FindingVerdictEffective(verdict.State()) || verdict.HumanRevision != 1 {
		t.Fatal(verdict, err)
	}
	for table, want := range map[string]int{"finding_claims": 1, "finding_human_decisions": 1, "report_runs": 1} {
		var n int
		if err = s.m.pg.QueryRow(`SELECT count(*) FROM `+table+` WHERE finding_id=$1`, f.FindingID).Scan(&n); err != nil || n != want {
			t.Fatal(table, n, err)
		}
	}
	body, err := os.ReadFile(localFile)
	if err != nil || string(body) != "immutable local fixture" {
		t.Fatal(string(body), err)
	}
	if remaining, err := s.m.pg.GetTaskArchive(a.ID); err != nil || remaining != nil {
		t.Fatal("restore barrier remained", remaining, err)
	}
}
