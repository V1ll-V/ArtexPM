package ctfrunner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

type InteractiveSessionInfo struct {
	ID         string `json:"id"`
	ExecID     string `json:"exec_id,omitempty"`
	Command    string `json:"command"`
	PID        int    `json:"pid"`
	Running    bool   `json:"running"`
	ExitCode   int    `json:"exit_code"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type InteractiveWriteRequest struct {
	Data        string `json:"data"`
	Encoding    string `json:"encoding,omitempty"` // "utf-8" or "base64", default "utf-8"
	AutoNewline bool   `json:"auto_newline,omitempty"`
}

type InteractiveWriteResult struct {
	ID           string `json:"id"`
	BytesWritten int    `json:"bytes_written"`
	Running      bool   `json:"running"`
}

type InteractiveReadResult struct {
	ID       string `json:"id"`
	ExecID   string `json:"exec_id,omitempty"`
	Offset   int64  `json:"offset"`
	Output   string `json:"output"`
	NewBytes int    `json:"new_bytes"`
	Running  bool   `json:"running"`
	ExitCode int    `json:"exit_code"`
}

var validInteractiveIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

func generateInteractiveID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "pty-" + hex.EncodeToString(b)
}

const interactiveManagerScript = `
import sys, os, pty, time, subprocess, select, json, base64, fcntl, signal, socket, struct
try:
    import termios
except ImportError:
    termios = None

action = sys.argv[1]

def read_file(path, default=""):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except Exception:
        return default

if action == "start":
    sid = sys.argv[2]
    cmd = sys.argv[3]
    exec_id = sys.argv[4] if len(sys.argv) > 4 else ""
    s_dir = f"/work/.interactive/{sid}"
    os.makedirs(s_dir, exist_ok=True)
    with open(f"{s_dir}/cmd", "w") as f:
        f.write(cmd)
    if exec_id:
        with open(f"{s_dir}/exec_id", "w") as f:
            f.write(exec_id)

    daemon_script = f"""#!/usr/bin/env python3
import os, sys, pty, time, subprocess, select, json, base64, fcntl, signal, socket, struct
try:
    import termios
except ImportError:
    termios = None

sid = {repr(sid)}
cmd = {repr(cmd)}
s_dir = {repr(s_dir)}
sock_path = f"{{s_dir}}/ctl.sock"
log_path = f"{{s_dir}}/output.log"
status_path = f"{{s_dir}}/status.json"

if os.path.exists(sock_path):
    try:
        os.remove(sock_path)
    except Exception:
        pass

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(10)
srv.setblocking(False)

master, slave = pty.openpty()

# Disable echo on slave to avoid duplicate input in log
if termios:
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] = attrs[3] & ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    except Exception:
        pass

proc = subprocess.Popen(cmd, shell=True, stdin=slave, stdout=slave, stderr=slave, close_fds=True, preexec_fn=os.setsid)
os.close(slave)

flags = fcntl.fcntl(master, fcntl.F_GETFL)
fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
with open(status_path, "w") as f:
    json.dump({{"id": sid, "command": cmd, "pid": proc.pid, "running": True, "exit_code": -1, "started_at": now_iso}}, f)

with open(f"{{s_dir}}/ready", "w") as f:
    f.write(str(proc.pid))

log_file = open(log_path, "ab", buffering=0)

last_activity = time.time()
running = True
exit_code = -1

while True:
    rlist = [master, srv]
    try:
        readable, _, _ = select.select(rlist, [], [], 0.1)
    except Exception:
        break

    for fd in readable:
        if fd == master:
            try:
                data = os.read(master, 8192)
                if data:
                    log_file.write(data)
                    last_activity = time.time()
            except OSError:
                pass
        elif fd == srv:
            try:
                conn, _ = srv.accept()
                raw = conn.recv(65536)
                if raw:
                    last_activity = time.time()
                    msg = json.loads(raw.decode())
                    act = msg.get("action")
                    if act == "write":
                        data_b64 = msg.get("data_b64", "")
                        b = base64.b64decode(data_b64)
                        os.write(master, b)
                        conn.sendall(json.dumps({{"ok": True, "written": len(b), "running": proc.poll() is None}}).encode())
                    elif act == "close":
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except OSError:
                            pass
                        conn.sendall(json.dumps({{"ok": True}}).encode())
                    elif act == "status":
                        conn.sendall(json.dumps({{"running": proc.poll() is None, "pid": proc.pid, "exit_code": proc.returncode if proc.poll() is not None else -1}}).encode())
                conn.close()
            except Exception:
                pass

    if proc.poll() is not None and running:
        exit_code = proc.returncode
        running = False
        # Drain remaining bytes
        while True:
            try:
                data = os.read(master, 8192)
                if not data:
                    break
                log_file.write(data)
            except OSError:
                break
        fin_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(status_path, "w") as f:
            json.dump({{"id": sid, "command": cmd, "pid": proc.pid, "running": False, "exit_code": exit_code, "started_at": now_iso, "finished_at": fin_iso}}, f)

    # Inactivity shutdown after 15 minutes
    if time.time() - last_activity > 900:
        if running:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
        break

    if not running:
        # After process exits, keep daemon alive for up to 60s for final reads or until close
        if time.time() - last_activity > 60:
            break

log_file.close()
srv.close()
os.close(master)
"""
    with open(f"{s_dir}/daemon.py", "w") as f:
        f.write(daemon_script)
    os.chmod(f"{s_dir}/daemon.py", 0o755)

    p = subprocess.Popen(["/usr/bin/python3", f"{s_dir}/daemon.py"],
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)

    # Wait up to 3 seconds for ready
    ready = False
    for _ in range(30):
        if os.path.exists(f"{s_dir}/ready"):
            ready = True
            break
        time.sleep(0.1)

    st_raw = read_file(f"{s_dir}/status.json")
    if st_raw:
        print(st_raw)
    else:
        print(json.dumps({"id": sid, "command": cmd, "pid": p.pid, "running": ready, "exit_code": -1}))

elif action == "write":
    sid = sys.argv[2]
    data_b64 = sys.argv[3]
    s_dir = f"/work/.interactive/{sid}"
    sock_path = f"{s_dir}/ctl.sock"
    if not os.path.exists(sock_path):
        print(json.dumps({"error": "interactive session not found or closed"}))
        sys.exit(0)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(sock_path)
        s.sendall(json.dumps({"action": "write", "data_b64": data_b64}).encode())
        resp = s.recv(4096)
        s.close()
        res = json.loads(resp.decode())
        print(json.dumps({"id": sid, "bytes_written": res.get("written", 0), "running": res.get("running", False)}))
    except Exception as e:
        print(json.dumps({"error": f"write failed: {e}"}))

elif action == "read":
    sid = sys.argv[2]
    offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    wait_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    max_bytes = int(sys.argv[5]) if len(sys.argv) > 5 else 65536

    s_dir = f"/work/.interactive/{sid}"
    log_path = f"{s_dir}/output.log"
    status_path = f"{s_dir}/status.json"

    if not os.path.exists(s_dir):
        print(json.dumps({"error": "interactive session not found"}))
        sys.exit(0)

    # Wait for output if wait_ms > 0 and offset >= current file size
    t_end = time.time() + (wait_ms / 1000.0)
    while wait_ms > 0 and time.time() < t_end:
        sz = os.path.getsize(log_path) if os.path.exists(log_path) else 0
        if sz > offset:
            break
        # Check if process is still running
        st_data = {}
        try:
            with open(status_path, "r") as sf:
                st_data = json.load(sf)
        except Exception:
            pass
        if not st_data.get("running", True):
            break
        time.sleep(0.05)

    data = b""
    sz = os.path.getsize(log_path) if os.path.exists(log_path) else 0
    if os.path.exists(log_path) and offset < sz:
        try:
            with open(log_path, "rb") as f:
                f.seek(offset)
                data = f.read(max_bytes)
        except Exception:
            pass

    new_offset = offset + len(data)
    running = True
    exit_code = -1
    try:
        with open(status_path, "r") as sf:
            st = json.load(sf)
            running = st.get("running", True)
            exit_code = st.get("exit_code", -1)
    except Exception:
        pass

    exec_id = read_file(f"{s_dir}/exec_id")
    text_out = data.decode("utf-8", errors="replace")
    print(json.dumps({
        "id": sid,
        "exec_id": exec_id,
        "offset": new_offset,
        "output": text_out,
        "new_bytes": len(data),
        "running": running,
        "exit_code": exit_code
    }))

elif action == "close":
    sid = sys.argv[2]
    s_dir = f"/work/.interactive/{sid}"
    sock_path = f"{s_dir}/ctl.sock"
    status_path = f"{s_dir}/status.json"

    closed = False
    if os.path.exists(sock_path):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(sock_path)
            s.sendall(json.dumps({"action": "close"}).encode())
            s.close()
            closed = True
        except Exception:
            pass

    # Read pid and kill process group if still alive
    st = {}
    try:
        with open(status_path, "r") as sf:
            st = json.load(sf)
    except Exception:
        pass

    pid = st.get("pid", 0)
    if pid > 0:
        try:
            os.killpg(pid, signal.SIGTERM)
            time.sleep(0.1)
            os.killpg(pid, signal.SIGKILL)
            closed = True
        except OSError:
            pass

    st["running"] = False
    st["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        with open(status_path, "w") as sf:
            json.dump(st, sf)
    except Exception:
        pass

    print(json.dumps({"id": sid, "closed": True}))

elif action == "list":
    base_dir = "/work/.interactive"
    res = []
    if os.path.exists(base_dir):
        for entry in sorted(os.listdir(base_dir)):
            p = os.path.join(base_dir, entry)
            if os.path.isdir(p):
                sf = os.path.join(p, "status.json")
                if os.path.exists(sf):
                    try:
                        with open(sf, "r") as f:
                            res.append(json.load(f))
                    except Exception:
                        pass
    print(json.dumps(res))
`

func (s *Server) execInteractiveHelper(ctx context.Context, containerID string, args ...string) (string, error) {
	cmdParts := []string{"python3", "-c", shellQuote(interactiveManagerScript)}
	for _, a := range args {
		cmdParts = append(cmdParts, shellQuote(a))
	}
	res, err := s.Engine.Exec(ctx, containerID, strings.Join(cmdParts, " "))
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("interactive helper failed (%d): %s %s", res.ExitCode, string(res.Stdout), string(res.Stderr))
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

func (s *Server) startInteractive(w http.ResponseWriter, r *http.Request) {
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
		Command   string `json:"command"`
		SessionID string `json:"session_id"`
		ExecID    string `json:"exec_id"`
	}
	if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil || strings.TrimSpace(in.Command) == "" {
		fail(w, errors.New("invalid interactive session specification"))
		return
	}
	sid := strings.TrimSpace(in.SessionID)
	if sid == "" {
		sid = generateInteractiveID()
	} else if !validInteractiveIDPattern.MatchString(sid) {
		fail(w, errors.New("invalid session_id (alphanumeric, underscore, dash, max 64 chars)"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	out, err := s.execInteractiveHelper(ctx, v.ContainerID, "start", sid, in.Command, in.ExecID)
	if err != nil {
		fail(w, err)
		return
	}
	var res InteractiveSessionInfo
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v (raw: %s)", err, out))
		return
	}
	if res.ExecID == "" {
		res.ExecID = in.ExecID
	}
	reply(w, 201, res)
}

func (s *Server) writeInteractive(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	sid := r.PathValue("sid")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	if !validInteractiveIDPattern.MatchString(sid) {
		fail(w, errors.New("invalid sid"))
		return
	}

	var in InteractiveWriteRequest
	if err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, errors.New("invalid write request"))
		return
	}

	var rawBytes []byte
	if strings.ToLower(in.Encoding) == "base64" {
		decoded, decErr := base64.StdEncoding.DecodeString(in.Data)
		if decErr != nil {
			fail(w, fmt.Errorf("invalid base64: %v", decErr))
			return
		}
		rawBytes = decoded
	} else {
		rawBytes = []byte(in.Data)
	}

	if in.AutoNewline && len(rawBytes) > 0 && rawBytes[len(rawBytes)-1] != '\n' {
		rawBytes = append(rawBytes, '\n')
	}

	dataB64 := base64.StdEncoding.EncodeToString(rawBytes)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	out, err := s.execInteractiveHelper(ctx, v.ContainerID, "write", sid, dataB64)
	if err != nil {
		fail(w, err)
		return
	}
	var res map[string]any
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v", err))
		return
	}
	if errMsg, ok := res["error"].(string); ok && errMsg != "" {
		fail(w, errors.New(errMsg))
		return
	}
	reply(w, 200, res)
}

func (s *Server) readInteractive(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	sid := r.PathValue("sid")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	if !validInteractiveIDPattern.MatchString(sid) {
		fail(w, errors.New("invalid sid"))
		return
	}

	offsetStr := r.URL.Query().Get("offset")
	offset := int64(0)
	if offsetStr != "" {
		if o, err := strconv.ParseInt(offsetStr, 10, 64); err == nil && o >= 0 {
			offset = o
		}
	}

	waitMs := 0
	if wStr := r.URL.Query().Get("wait_ms"); wStr != "" {
		if wVal, err := strconv.Atoi(wStr); err == nil && wVal > 0 {
			waitMs = min(wVal, 10000) // max wait 10s
		}
	}

	maxBytes := 65536
	if mStr := r.URL.Query().Get("max_bytes"); mStr != "" {
		if mVal, err := strconv.Atoi(mStr); err == nil && mVal > 0 {
			maxBytes = min(mVal, 512<<10) // max 512KB
		}
	}

	timeoutSec := (waitMs/1000 + 5)
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	out, err := s.execInteractiveHelper(ctx, v.ContainerID, "read", sid, strconv.FormatInt(offset, 10), strconv.Itoa(waitMs), strconv.Itoa(maxBytes))
	if err != nil {
		fail(w, err)
		return
	}
	var res InteractiveReadResult
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v", err))
		return
	}
	reply(w, 200, res)
}

func (s *Server) closeInteractive(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	sid := r.PathValue("sid")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}
	if !validInteractiveIDPattern.MatchString(sid) {
		fail(w, errors.New("invalid sid"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	out, err := s.execInteractiveHelper(ctx, v.ContainerID, "close", sid)
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

func (s *Server) listInteractive(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	unlock := s.lock(key)
	defer unlock()
	v, err := s.load(key)
	if err != nil {
		fail(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	out, err := s.execInteractiveHelper(ctx, v.ContainerID, "list")
	if err != nil {
		fail(w, err)
		return
	}
	var res []InteractiveSessionInfo
	if err = json.Unmarshal([]byte(out), &res); err != nil {
		fail(w, fmt.Errorf("decode error: %v", err))
		return
	}
	reply(w, 200, res)
}
