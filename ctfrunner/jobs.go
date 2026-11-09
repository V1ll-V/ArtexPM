package ctfrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type JobInfo struct {
	ID         string `json:"id"`
	ExecID     string `json:"exec_id,omitempty"`
	Command    string `json:"command"`
	PID        int    `json:"pid"`
	Status     string `json:"status"` // "running", "finished", "failed", "terminated"
	ExitCode   int    `json:"exit_code"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type JobStatus struct {
	JobInfo
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

var validJobIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

func generateJobID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "job-" + hex.EncodeToString(b)
}

const jobManagerScript = `
import sys, os, subprocess, json, datetime, signal

action = sys.argv[1]

def read_file(path, default=""):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except Exception:
        return default

def tail_file(path, n):
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
            return "".join(lines[-n:])
    except Exception:
        return ""

if action == "start":
    job_id = sys.argv[2]
    cmd = sys.argv[3]
    exec_id = sys.argv[4] if len(sys.argv) > 4 else ""
    job_dir = f"/work/.jobs/{job_id}"
    os.makedirs(job_dir, exist_ok=True)
    with open(f"{job_dir}/cmd", "w") as f:
        f.write(cmd)
    if exec_id:
        with open(f"{job_dir}/exec_id", "w") as f:
            f.write(exec_id)
    with open(f"{job_dir}/started_at", "w") as f:
        f.write(datetime.datetime.now(datetime.timezone.utc).isoformat())

    runner_script = f"""#!/bin/bash
({cmd}) > {job_dir}/stdout.log 2> {job_dir}/stderr.log
echo $? > {job_dir}/exit_code
date -u +"%Y-%m-%dT%H:%M:%SZ" > {job_dir}/finished_at
"""
    with open(f"{job_dir}/run.sh", "w") as f:
        f.write(runner_script)
    os.chmod(f"{job_dir}/run.sh", 0o755)

    p = subprocess.Popen(["/bin/bash", f"{job_dir}/run.sh"],
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)
    with open(f"{job_dir}/pid", "w") as f:
        f.write(str(p.pid))
    print(json.dumps({"id": job_id, "pid": p.pid, "started": True}))

elif action == "status":
    job_id = sys.argv[2]
    tail_n = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    job_dir = f"/work/.jobs/{job_id}"
    if not os.path.exists(job_dir):
        print(json.dumps({"error": "job not found"}))
        sys.exit(0)

    cmd = read_file(f"{job_dir}/cmd")
    exec_id = read_file(f"{job_dir}/exec_id")
    started_at = read_file(f"{job_dir}/started_at")
    finished_at = read_file(f"{job_dir}/finished_at")
    pid_str = read_file(f"{job_dir}/pid")
    pid = int(pid_str) if pid_str.isdigit() else 0
    exit_code_str = read_file(f"{job_dir}/exit_code")

    status = "unknown"
    exit_code = -1
    if exit_code_str != "":
        exit_code = int(exit_code_str)
        status = "finished" if exit_code == 0 else "failed"
    elif pid > 0:
        try:
            os.kill(pid, 0)
            status = "running"
        except OSError:
            status = "terminated"
    else:
        status = "terminated"

    stdout = tail_file(f"{job_dir}/stdout.log", tail_n)
    stderr = tail_file(f"{job_dir}/stderr.log", tail_n)

    print(json.dumps({
        "id": job_id,
        "exec_id": exec_id,
        "command": cmd,
        "pid": pid,
        "status": status,
        "exit_code": exit_code,
        "started_at": started_at,
        "finished_at": finished_at,
        "stdout": stdout,
        "stderr": stderr
    }))

elif action == "stop":
    job_id = sys.argv[2]
    job_dir = f"/work/.jobs/{job_id}"
    pid_str = read_file(f"{job_dir}/pid")
    stopped = False
    if pid_str.isdigit():
        pid = int(pid_str)
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            stopped = True
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
                stopped = True
            except Exception:
                pass
    if not os.path.exists(f"{job_dir}/exit_code"):
        with open(f"{job_dir}/exit_code", "w") as f:
            f.write("143")
        with open(f"{job_dir}/finished_at", "w") as f:
            f.write(datetime.datetime.now(datetime.timezone.utc).isoformat())
    print(json.dumps({"id": job_id, "stopped": stopped}))

elif action == "list":
    jobs_dir = "/work/.jobs"
    res = []
    if os.path.exists(jobs_dir):
        for entry in sorted(os.listdir(jobs_dir)):
            p = os.path.join(jobs_dir, entry)
            if os.path.isdir(p):
                cmd = read_file(f"{p}/cmd")
                exec_id = read_file(f"{p}/exec_id")
                pid_str = read_file(f"{p}/pid")
                pid = int(pid_str) if pid_str.isdigit() else 0
                exit_code_str = read_file(f"{p}/exit_code")
                started_at = read_file(f"{p}/started_at")
                finished_at = read_file(f"{p}/finished_at")
                status = "running"
                exit_code = -1
                if exit_code_str != "":
                    exit_code = int(exit_code_str)
                    status = "finished" if exit_code == 0 else "failed"
                elif pid > 0:
                    try:
                        os.kill(pid, 0)
                        status = "running"
                    except OSError:
                        status = "terminated"
                else:
                    status = "terminated"
                res.append({
                    "id": entry,
                    "exec_id": exec_id,
                    "command": cmd,
                    "pid": pid,
                    "status": status,
                    "exit_code": exit_code,
                    "started_at": started_at,
                    "finished_at": finished_at
                })
    print(json.dumps(res))
`

func (s *Server) execJobHelper(ctx context.Context, containerID string, args ...string) (string, error) {
	cmdParts := []string{"python3", "-c", shellQuote(jobManagerScript)}
	for _, a := range args {
		cmdParts = append(cmdParts, shellQuote(a))
	}
	res, err := s.Engine.Exec(ctx, containerID, strings.Join(cmdParts, " "))
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("job helper failed (%d): %s %s", res.ExitCode, string(res.Stdout), string(res.Stderr))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func (s *Server) startJob(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	if !v.InputsReady {
		fail(w, errors.New("inputs not ready"))
		return
	}
	var in struct {
		Command string `json:"command"`
		JobID   string `json:"job_id"`
		ExecID  string `json:"exec_id"`
	}
	if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil || strings.TrimSpace(in.Command) == "" {
		fail(w, errors.New("invalid job specification"))
		return
	}
	jobID := strings.TrimSpace(in.JobID)
	if jobID == "" {
		jobID = generateJobID()
	} else if !validJobIDPattern.MatchString(jobID) {
		fail(w, errors.New("invalid job_id (alphanumeric, underscore, dash, max 64 chars)"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	out, err := s.execJobHelper(ctx, v.ContainerID, "start", jobID, in.Command, strings.TrimSpace(in.ExecID))
	if err != nil {
		fail(w, err)
		return
	}
	var res map[string]any
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v, raw: %s", err, out))
		return
	}
	_ = s.save(v)
	reply(w, 200, res)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	out, err := s.execJobHelper(ctx, v.ContainerID, "list")
	if err != nil {
		fail(w, err)
		return
	}
	var res []JobInfo
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v", err))
		return
	}
	reply(w, 200, res)
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	jobID := r.PathValue("job_id")
	if !validJobIDPattern.MatchString(jobID) {
		fail(w, errors.New("invalid job_id"))
		return
	}
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	tailN := 100
	if q := r.URL.Query().Get("tail"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			tailN = min(n, 2000)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	out, err := s.execJobHelper(ctx, v.ContainerID, "status", jobID, strconv.Itoa(tailN))
	if err != nil {
		fail(w, err)
		return
	}
	var res JobStatus
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v", err))
		return
	}
	if res.ID == "" {
		reply(w, 404, map[string]string{"error": "job not found"})
		return
	}
	reply(w, 200, res)
}

func (s *Server) stopJob(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	jobID := r.PathValue("job_id")
	if !validJobIDPattern.MatchString(jobID) {
		fail(w, errors.New("invalid job_id"))
		return
	}
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	out, err := s.execJobHelper(ctx, v.ContainerID, "stop", jobID)
	if err != nil {
		fail(w, err)
		return
	}
	var res map[string]any
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v", err))
		return
	}
	reply(w, 200, res)
}
