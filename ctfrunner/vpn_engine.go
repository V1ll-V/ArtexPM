package ctfrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var vpnTaskLocks sync.Map

func lockVPNTask(taskID string) func() {
	v, _ := vpnTaskLocks.LoadOrStore(taskID, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func vpnContainerName(taskID string) string {
	return "artex-ctf-wg-" + taskID
}

func (e *Engine) wgImage() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CTF_WG_IMAGE")); v != "" {
		return v
	}
	return "autumn27/artex-ctf-wg:0.8.1"
}

func (e *Engine) vpnNetworkName() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CTF_VPN_NETWORK")); v != "" {
		return v
	}
	return "artex-ctf-vpn"
}

func (e *Engine) vpnSubnet() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CTF_VPN_SUBNET")); v != "" {
		return v
	}
	return "10.220.0.0/16"
}

// EnsureVPNNetwork creates an isolated bridge network outside Docker's default
// 172.17.0.0/16 subnet so challenge VPNs using 172.17.x.0/24 never collide.
func (e *Engine) EnsureVPNNetwork(ctx context.Context) error {
	netName := e.vpnNetworkName()
	var existing map[string]any
	err := e.json(ctx, "GET", "/networks/"+url.PathEscape(netName), nil, &existing)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), ": 404 ") {
		return err
	}
	payload := map[string]any{
		"Name":           netName,
		"Driver":         "bridge",
		"CheckDuplicate": true,
		"Labels": map[string]string{
			"artex.ctf.managed": "true",
			"artex.ctf.role":    "vpn-net",
		},
		"IPAM": map[string]any{
			"Driver": "default",
			"Config": []map[string]any{
				{"Subnet": e.vpnSubnet()},
			},
		},
	}
	if err = e.json(ctx, "POST", "/networks/create", payload, nil); err != nil {
		// Concurrent network creation returns 409; re-check before failing.
		if strings.Contains(err.Error(), ": 409 ") {
			if checkErr := e.json(ctx, "GET", "/networks/"+url.PathEscape(netName), nil, &existing); checkErr == nil {
				return nil
			}
		}
		return fmt.Errorf("创建隔离 CTF VPN 网络 %s (%s) 失败：%w", netName, e.vpnSubnet(), err)
	}
	return nil
}

func (e *Engine) resolveSessionNetwork(ctx context.Context, task, vpnHash string) (netMode, wgID string, err error) {
	vpnHash = strings.TrimSpace(vpnHash)
	if vpnHash == "" {
		return "bridge", "", nil
	}
	wg, err := e.requireVPNContainer(ctx, task, vpnHash)
	if err != nil {
		return "", "", err
	}
	return "container:" + wg.ID, wg.ID, nil
}

func (e *Engine) requireVPNContainer(ctx context.Context, task, vpnHash string) (Container, error) {
	c, err := e.Container(ctx, vpnContainerName(task))
	if err != nil {
		return Container{}, fmt.Errorf("任务 #%s 的 WireGuard VPN 容器未就绪：%w", task, err)
	}
	if c.Config.Labels["artex.ctf.managed"] != "true" ||
		c.Config.Labels["artex.ctf.role"] != "wg" ||
		c.Config.Labels["artex.ctf.task"] != task ||
		c.Config.Labels["artex.ctf.vpn"] != vpnHash {
		return Container{}, fmt.Errorf("任务 #%s 的 WireGuard VPN 容器配置版本不一致，需要重新同步", task)
	}
	if !c.State.Running {
		if err = e.json(ctx, "POST", "/containers/"+c.ID+"/start", nil, nil); err != nil {
			return Container{}, fmt.Errorf("启动 WireGuard VPN 容器失败：%w", err)
		}
		if err = e.waitVPNReady(ctx, c.ID); err != nil {
			return Container{}, err
		}
	}
	return c, nil
}

// EnsureVPN ensures a dedicated per-task WireGuard sidecar container is running
// with the exact validated VPN configuration and tears down stale containers on update.
func (e *Engine) EnsureVPN(ctx context.Context, taskID, expectedHash, rawConfig string) (VPNStatus, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return VPNStatus{}, errors.New("task_id 不能为空")
	}
	unlock := lockVPNTask(taskID)
	defer unlock()

	prof, err := ParseWireGuardConfig(rawConfig)
	if err != nil {
		return VPNStatus{}, err
	}
	if expectedHash != "" && prof.Hash != expectedHash {
		return VPNStatus{}, fmt.Errorf("WireGuard 配置摘要不匹配：%s != %s", prof.Hash, expectedHash)
	}

	name := vpnContainerName(taskID)
	if existing, err := e.Container(ctx, name); err == nil {
		if existing.Config.Labels["artex.ctf.managed"] == "true" &&
			existing.Config.Labels["artex.ctf.role"] == "wg" &&
			existing.Config.Labels["artex.ctf.task"] == taskID &&
			existing.Config.Labels["artex.ctf.vpn"] == prof.Hash {
			if !existing.State.Running {
				if startErr := e.json(ctx, "POST", "/containers/"+existing.ID+"/start", nil, nil); startErr == nil {
					if readyErr := e.waitVPNReady(ctx, existing.ID); readyErr == nil {
						return e.ProbeVPN(ctx, taskID)
					}
				}
			} else if st, probeErr := e.ProbeVPN(ctx, taskID); probeErr == nil && st.Running && st.TunnelIP != "" {
				return st, nil
			}
		}
		// Hash changed or previous sidecar unhealthy: drop tool containers first so none keep dead netns refs.
		_ = e.removeTaskToolContainers(ctx, taskID)
		if err = e.removeContainerOnly(ctx, name); err != nil {
			return VPNStatus{}, err
		}
	} else if !strings.Contains(err.Error(), ": 404 ") {
		return VPNStatus{}, err
	}

	if err = e.EnsureVPNNetwork(ctx); err != nil {
		return VPNStatus{}, err
	}

	wgImg := e.wgImage()
	var img struct{ ID string }
	if err = e.json(ctx, "GET", "/images/"+url.PathEscape(wgImg)+"/json", nil, &img); err != nil {
		return VPNStatus{}, fmt.Errorf("WireGuard Sidecar 镜像 %s 不可用（请构建 Dockerfile.ctf-wg）：%w", wgImg, err)
	}

	payload := map[string]any{
		"Image": wgImg,
		"User":  "0:0",
		"Labels": map[string]string{
			"artex.ctf.managed": "true",
			"artex.ctf.role":    "wg",
			"artex.ctf.task":    taskID,
			"artex.ctf.vpn":     prof.Hash,
		},
		"HostConfig": map[string]any{
			"Memory":      int64(128 << 20),
			"NanoCpus":    int64(5e8),
			"PidsLimit":   int64(64),
			"CapDrop":     []string{"ALL"},
			"CapAdd":      []string{"NET_ADMIN", "SYS_MODULE"},
			"NetworkMode": e.vpnNetworkName(),
			"Sysctls": map[string]string{
				"net.ipv4.conf.all.src_valid_mark":     "1",
				"net.ipv4.conf.default.src_valid_mark": "1",
			},
			"Devices": []map[string]any{
				{
					"PathOnHost":        "/dev/net/tun",
					"PathInContainer":   "/dev/net/tun",
					"CgroupPermissions": "rwm",
				},
			},
		},
	}
	var created struct{ ID string }
	if err = e.json(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), payload, &created); err != nil {
		return VPNStatus{}, fmt.Errorf("创建 WireGuard 容器失败：%w", err)
	}

	tarBuf, err := buildVPNTar(prof.RunnerConfig, prof.DNS)
	if err != nil {
		_ = e.removeContainerOnly(ctx, name)
		return VPNStatus{}, err
	}
	if err = e.putArchiveRoot(ctx, created.ID, bytes.NewReader(tarBuf)); err != nil {
		_ = e.removeContainerOnly(ctx, name)
		return VPNStatus{}, fmt.Errorf("注入 WireGuard 配置失败：%w", err)
	}
	if err = e.json(ctx, "POST", "/containers/"+created.ID+"/start", nil, nil); err != nil {
		_ = e.removeContainerOnly(ctx, name)
		return VPNStatus{}, fmt.Errorf("启动 WireGuard 容器失败：%w", err)
	}
	if err = e.waitVPNReady(ctx, created.ID); err != nil {
		logs := e.containerLogs(ctx, created.ID)
		_ = e.removeContainerOnly(ctx, name)
		if logs != "" {
			return VPNStatus{}, fmt.Errorf("%w：%s", err, logs)
		}
		return VPNStatus{}, err
	}
	// Trigger cleanup of any previously created non-VPN tool containers so the next execution re-attaches to wg0.
	_ = e.removeTaskToolContainersWithWrongVPN(ctx, taskID, prof.Hash, created.ID)
	return e.ProbeVPN(ctx, taskID)
}

// RemoveVPN stops and deletes a task's WireGuard sidecar container and detaches
// any existing tool containers (without deleting their /work volumes).
func (e *Engine) RemoveVPN(ctx context.Context, taskID string) error {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil
	}
	unlock := lockVPNTask(taskID)
	defer unlock()

	if err := e.removeTaskToolContainersWithWrongVPN(ctx, taskID, "", ""); err != nil {
		return err
	}
	return e.removeContainerOnly(ctx, vpnContainerName(taskID))
}

// RemoveTaskContainers deletes all managed containers and volumes belonging to taskID.
func (e *Engine) RemoveTaskContainers(ctx context.Context, taskID string) error {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil
	}
	unlock := lockVPNTask(taskID)
	defer unlock()

	containers, err := e.listTaskContainers(ctx, taskID)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range containers {
		if rmErr := e.removeContainerOnly(ctx, id); rmErr != nil {
			errs = append(errs, rmErr)
		}
	}
	vols, err := e.listTaskVolumes(ctx, taskID)
	if err != nil {
		errs = append(errs, err)
	} else {
		for _, v := range vols {
			if rmErr := e.removeVolume(ctx, v); rmErr != nil {
				errs = append(errs, rmErr)
			}
		}
	}
	return errors.Join(errs...)
}

// ProbeVPN inspects a task's WireGuard sidecar container without exposing private keys.
func (e *Engine) ProbeVPN(ctx context.Context, taskID string) (VPNStatus, error) {
	numID, _ := strconv.ParseInt(taskID, 10, 64)
	name := vpnContainerName(taskID)
	st := VPNStatus{
		TaskID:    numID,
		Container: name,
		Network:   e.vpnNetworkName(),
	}
	c, err := e.Container(ctx, name)
	if err != nil {
		if strings.Contains(err.Error(), ": 404 ") {
			return st, nil
		}
		st.Error = err.Error()
		return st, err
	}
	st.Active = true
	st.Running = c.State.Running
	st.ContainerID = c.ID
	st.Hash = c.Config.Labels["artex.ctf.vpn"]
	if !c.State.Running {
		st.Error = "WireGuard Sidecar 容器未处于运行状态"
		return st, nil
	}

	probeCmd := `test -f /run/wg/ready && echo "READY=1" || echo "READY=0"; ip -4 -o addr show dev wg0 2>/dev/null | awk '{print "ADDR="$4}'; wg show wg0 dump 2>/dev/null | sed -n '2,$p'; grep -E '^nameserver ' /etc/resolv.conf 2>/dev/null | awk '{print "DNS="$2}'`
	res, err := e.execRoot(ctx, c.ID, probeCmd)
	if err != nil {
		st.Error = err.Error()
		return st, err
	}
	var dnsList []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "ADDR="):
			st.TunnelIP = strings.TrimPrefix(line, "ADDR=")
			st.Interface = "wg0"
		case strings.HasPrefix(line, "DNS="):
			dnsList = append(dnsList, strings.TrimPrefix(line, "DNS="))
		case !strings.HasPrefix(line, "READY="):
			fields := strings.Split(line, "\t")
			if len(fields) >= 7 {
				if fields[2] != "(none)" {
					st.Endpoint = fields[2]
				}
				if hs, parseErr := strconv.ParseInt(fields[4], 10, 64); parseErr == nil && hs > 0 {
					st.HandshakeAt = time.Unix(hs, 0).UTC().Format(time.RFC3339)
					if age := time.Now().Unix() - hs; age >= 0 {
						st.HandshakeAge = age
					}
				}
				if rx, parseErr := strconv.ParseInt(fields[5], 10, 64); parseErr == nil {
					st.RxBytes = rx
				}
				if tx, parseErr := strconv.ParseInt(fields[6], 10, 64); parseErr == nil {
					st.TxBytes = tx
				}
			}
		}
	}
	st.DNS = strings.Join(dnsList, ", ")
	return st, nil
}

func (e *Engine) waitVPNReady(ctx context.Context, containerID string) error {
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		c, err := e.Container(ctx, containerID)
		if err != nil {
			return err
		}
		if !c.State.Running {
			return errors.New("WireGuard 容器启动后提前退出")
		}
		res, err := e.execRoot(ctx, containerID, `test -f /run/wg/ready && ip link show dev wg0 >/dev/null 2>&1`)
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("等待 WireGuard 隧道 wg0 就绪超时")
}

func (e *Engine) containerLogs(ctx context.Context, id string) string {
	resp, err := e.call(ctx, "GET", "/containers/"+url.PathEscape(id)+"/logs?stdout=1&stderr=1&tail=20", nil, "")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// Strip Docker multiplexed 8-byte stream frame headers if present.
	var clean bytes.Buffer
	for len(raw) >= 8 && (raw[0] == 1 || raw[0] == 2) && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
		sz := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7])
		raw = raw[8:]
		if sz > len(raw) {
			sz = len(raw)
		}
		clean.Write(raw[:sz])
		raw = raw[sz:]
	}
	if clean.Len() > 0 {
		return strings.TrimSpace(clean.String())
	}
	return strings.TrimSpace(string(raw))
}

func (e *Engine) putArchiveRoot(ctx context.Context, id string, r io.Reader) error {
	resp, err := e.call(ctx, "PUT", "/containers/"+url.PathEscape(id)+"/archive?path=/", r, "application/x-tar")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("docker archive %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (e *Engine) removeContainerOnly(ctx context.Context, idOrName string) error {
	err := e.json(ctx, "DELETE", "/containers/"+url.PathEscape(idOrName)+"?force=1", nil, nil)
	if err != nil && strings.Contains(err.Error(), ": 404 ") {
		return nil
	}
	return err
}

func (e *Engine) removeVolume(ctx context.Context, name string) error {
	err := e.json(ctx, "DELETE", "/volumes/"+url.PathEscape(name)+"?force=1", nil, nil)
	if err != nil && strings.Contains(err.Error(), ": 404 ") {
		return nil
	}
	return err
}

type dockerListedContainer struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

func (e *Engine) listTaskContainers(ctx context.Context, taskID string) ([]string, error) {
	filterBytes, _ := json.Marshal(map[string][]string{
		"label": {"artex.ctf.managed=true", "artex.ctf.task=" + taskID},
	})
	var list []dockerListedContainer
	if err := e.json(ctx, "GET", "/containers/json?all=1&filters="+url.QueryEscape(string(filterBytes)), nil, &list); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list))
	for _, c := range list {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

func (e *Engine) removeTaskToolContainers(ctx context.Context, taskID string) error {
	filterBytes, _ := json.Marshal(map[string][]string{
		"label": {"artex.ctf.managed=true", "artex.ctf.task=" + taskID},
	})
	var list []dockerListedContainer
	if err := e.json(ctx, "GET", "/containers/json?all=1&filters="+url.QueryEscape(string(filterBytes)), nil, &list); err != nil {
		return err
	}
	var errs []error
	for _, c := range list {
		if c.Labels["artex.ctf.role"] == "wg" {
			continue
		}
		if err := e.removeContainerOnly(ctx, c.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) removeTaskToolContainersWithWrongVPN(ctx context.Context, taskID, vpnHash, wgID string) error {
	filterBytes, _ := json.Marshal(map[string][]string{
		"label": {"artex.ctf.managed=true", "artex.ctf.task=" + taskID},
	})
	var list []dockerListedContainer
	if err := e.json(ctx, "GET", "/containers/json?all=1&filters="+url.QueryEscape(string(filterBytes)), nil, &list); err != nil {
		return err
	}
	var errs []error
	for _, c := range list {
		if c.Labels["artex.ctf.role"] == "wg" {
			continue
		}
		if c.Labels["artex.ctf.vpn"] == vpnHash && c.Labels["artex.ctf.wg_id"] == wgID {
			continue
		}
		if err := e.removeContainerOnly(ctx, c.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) listTaskVolumes(ctx context.Context, taskID string) ([]string, error) {
	filterBytes, _ := json.Marshal(map[string][]string{
		"label": {"artex.ctf.managed=true", "artex.ctf.task=" + taskID},
	})
	var res struct {
		Volumes []struct {
			Name string `json:"Name"`
		} `json:"Volumes"`
	}
	if err := e.json(ctx, "GET", "/volumes?filters="+url.QueryEscape(string(filterBytes)), nil, &res); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Volumes))
	for _, v := range res.Volumes {
		names = append(names, v.Name)
	}
	return names, nil
}

func buildVPNTar(runnerConfig string, dns []string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarFile(tw, "run/wg/wg0.conf", []byte(runnerConfig), 0600); err != nil {
		return nil, err
	}
	dnsBody := ""
	if len(dns) > 0 {
		dnsBody = strings.Join(dns, "\n") + "\n"
	}
	if err := writeTarFile(tw, "run/wg/dns", []byte(dnsBody), 0644); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte, mode int64) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(data)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func (s *Server) registerVPNRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tasks/{id}/vpn", func(w http.ResponseWriter, r *http.Request) {
		taskID, err := parseTaskIDParam(r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		st, err := s.Engine.ProbeVPN(r.Context(), fmt.Sprint(taskID))
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, 200, st)
	})
	mux.HandleFunc("PUT /tasks/{id}/vpn", func(w http.ResponseWriter, r *http.Request) {
		taskID, err := parseTaskIDParam(r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		var req struct {
			Hash   string `json:"hash"`
			Config string `json:"config"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxVPNConfigBytes+4096)).Decode(&req); err != nil {
			fail(w, errors.New("invalid vpn request body"))
			return
		}
		st, err := s.Engine.EnsureVPN(r.Context(), fmt.Sprint(taskID), strings.TrimSpace(req.Hash), req.Config)
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, 200, st)
	})
	mux.HandleFunc("DELETE /tasks/{id}/vpn", func(w http.ResponseWriter, r *http.Request) {
		taskID, err := parseTaskIDParam(r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		if err := s.Engine.RemoveVPN(r.Context(), fmt.Sprint(taskID)); err != nil {
			fail(w, err)
			return
		}
		reply(w, 200, map[string]any{"removed": true, "task_id": taskID})
	})
	mux.HandleFunc("DELETE /tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		taskID, err := parseTaskIDParam(r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		idStr := fmt.Sprint(taskID)
		if err := s.Engine.RemoveTaskContainers(r.Context(), idStr); err != nil {
			fail(w, err)
			return
		}
		s.purgeTaskState(idStr)
		reply(w, 200, map[string]any{"deleted": true, "task_id": taskID})
	})
}

func (s *Server) purgeTaskState(taskID string) {
	if s.StateDir == "" {
		return
	}
	entries, err := os.ReadDir(s.StateDir)
	if err != nil {
		return
	}
	prefix := taskID + "-"
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		key := strings.TrimSuffix(name, ".json")
		unlock := s.lock(key)
		_ = os.Remove(filepath.Join(s.StateDir, name))
		unlock()
	}
}

func parseTaskIDParam(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid task id")
	}
	return id, nil
}
