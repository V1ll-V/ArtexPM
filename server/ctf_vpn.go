package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/ctfrunner"
)

func sanitizeVPNFilename(name string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == "/" || base == `\` {
		return "wg0.conf"
	}
	base = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '/' || r == '\\' {
			return -1
		}
		return r
	}, base)
	if base == "" {
		return "wg0.conf"
	}
	return base
}

func prepareTaskVPNForCreate(mode, rawConfig, filename string) (sanitized, hash, cleanName string, err error) {
	if strings.TrimSpace(rawConfig) == "" {
		return "", "", "", nil
	}
	if strings.TrimSpace(mode) != "ctf" {
		return "", "", "", errors.New("仅 CTF 模式支持配置 WireGuard VPN")
	}
	prof, err := ctfrunner.ParseWireGuardConfig(rawConfig)
	if err != nil {
		return "", "", "", errors.New("WireGuard 配置无效：" + err.Error())
	}
	return prof.RawSanitized, prof.Hash, sanitizeVPNFilename(filename), nil
}

func (s *Server) prewarmTaskVPN(t *Task, vpnHash, vpnConfig string) {
	if t == nil || vpnHash == "" || vpnConfig == "" {
		return
	}
	svc := s.ctfService()
	if svc.Runner == nil || !svc.Runner.Configured() {
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := svc.Runner.SyncTaskVPN(ctx, taskID, vpnHash, vpnConfig); err != nil {
		log.Printf("[ctf-vpn] 任务 #%s 预热 WireGuard 容器失败（将在首次工具调用时重试）：%v", t.ID, err)
	}
}

func (s *Server) requireCTFTask(w http.ResponseWriter, r *http.Request) (*Task, int64, bool) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return nil, 0, false
	}
	if t.Mode != "ctf" {
		writeErr(w, 400, "仅 CTF 任务支持 WireGuard VPN 配置")
		return nil, 0, false
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid task id")
		return nil, 0, false
	}
	return t, id, true
}

func (s *Server) ctfVPNGet(w http.ResponseWriter, r *http.Request) {
	_, taskID, ok := s.requireCTFTask(w, r)
	if !ok {
		return
	}
	cfg, hash, filename, err := s.m.pg.TaskCTFVPN(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if hash == "" || strings.TrimSpace(cfg) == "" {
		writeJSON(w, 200, ctfrunner.VPNSummary{Enabled: false})
		return
	}
	prof, err := ctfrunner.ParseWireGuardConfig(cfg)
	if err != nil {
		writeErr(w, 500, "已保存的 WireGuard 配置损坏："+err.Error())
		return
	}
	summary := prof.Summary(filename)
	svc := s.ctfService()
	if svc.Runner != nil && svc.Runner.Configured() {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		st, probeErr := svc.Runner.ProbeTaskVPN(ctx, taskID)
		cancel()
		if probeErr != nil {
			st.Error = probeErr.Error()
		}
		summary.Sidecar = &st
	}
	writeJSON(w, 200, summary)
}

func readVPNUploadPayload(w http.ResponseWriter, r *http.Request) (content, filename string, err error) {
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(ct, "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, ctfrunner.MaxVPNConfigBytes+64*1024)
		if err := r.ParseMultipartForm(ctfrunner.MaxVPNConfigBytes + 32*1024); err != nil {
			return "", "", errors.New("上传表单无效或配置文件过大（上限 64 KiB）")
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			return "", "", errors.New("缺少上传文件字段 file")
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, ctfrunner.MaxVPNConfigBytes+1))
		if err != nil {
			return "", "", errors.New("读取配置文件失败")
		}
		if len(raw) > ctfrunner.MaxVPNConfigBytes {
			return "", "", errors.New("WireGuard 配置文件过大（上限 64 KiB）")
		}
		name := ""
		if hdr != nil {
			name = hdr.Filename
		}
		return string(raw), sanitizeVPNFilename(name), nil
	}

	var req struct {
		Filename string `json:"filename"`
		Content  string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, ctfrunner.MaxVPNConfigBytes+8192)).Decode(&req); err != nil {
		return "", "", errors.New("请求体无效或超过大小限制")
	}
	return req.Content, sanitizeVPNFilename(req.Filename), nil
}

func (s *Server) ctfVPNPut(w http.ResponseWriter, r *http.Request) {
	t, taskID, ok := s.requireCTFTask(w, r)
	if !ok {
		return
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		writeErr(w, 409, "已结束任务不可修改 VPN 配置")
		return
	}
	raw, filename, err := readVPNUploadPayload(w, r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	prof, err := ctfrunner.ParseWireGuardConfig(raw)
	if err != nil {
		writeErr(w, 400, "WireGuard 配置无效："+err.Error())
		return
	}
	if err := s.m.pg.SetTaskCTFVPN(r.Context(), taskID, prof.RawSanitized, prof.Hash, filename); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.updateLifecycle(func(state *taskLifecycleState) {
		state.CTFVPNEnabled = true
		state.CTFVPNFilename = filename
		state.CTFVPNHash = prof.Hash
	})

	summary := prof.Summary(filename)
	svc := s.ctfService()
	if svc.Runner != nil && svc.Runner.Configured() {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		st, syncErr := svc.Runner.SyncTaskVPN(ctx, taskID, prof.Hash, prof.RawSanitized)
		cancel()
		if syncErr != nil {
			st = ctfrunner.VPNStatus{TaskID: taskID, Error: syncErr.Error()}
		}
		summary.Sidecar = &st
	}
	writeJSON(w, 200, summary)
}

func (s *Server) ctfVPNCheck(w http.ResponseWriter, r *http.Request) {
	_, taskID, ok := s.requireCTFTask(w, r)
	if !ok {
		return
	}
	cfg, hash, filename, err := s.m.pg.TaskCTFVPN(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if hash == "" || strings.TrimSpace(cfg) == "" {
		writeErr(w, 400, "当前任务尚未配置 WireGuard VPN")
		return
	}
	prof, err := ctfrunner.ParseWireGuardConfig(cfg)
	if err != nil {
		writeErr(w, 500, "已保存的 WireGuard 配置损坏："+err.Error())
		return
	}
	summary := prof.Summary(filename)
	svc := s.ctfService()
	if svc.Runner == nil || !svc.Runner.Configured() {
		summary.Sidecar = &ctfrunner.VPNStatus{TaskID: taskID, Error: "CTF 执行器未配置（ARTEX_CTF_RUNNER_URL）"}
		writeJSON(w, 200, summary)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	st, syncErr := svc.Runner.SyncTaskVPN(ctx, taskID, prof.Hash, prof.RawSanitized)
	cancel()
	if syncErr != nil {
		st = ctfrunner.VPNStatus{TaskID: taskID, Error: syncErr.Error()}
	}
	summary.Sidecar = &st
	writeJSON(w, 200, summary)
}

func (s *Server) ctfVPNDelete(w http.ResponseWriter, r *http.Request) {
	t, taskID, ok := s.requireCTFTask(w, r)
	if !ok {
		return
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		writeErr(w, 409, "已结束任务不可清除 VPN 配置")
		return
	}
	if err := s.m.pg.SetTaskCTFVPN(r.Context(), taskID, "", "", ""); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.updateLifecycle(func(state *taskLifecycleState) {
		state.CTFVPNEnabled = false
		state.CTFVPNFilename = ""
		state.CTFVPNHash = ""
	})
	svc := s.ctfService()
	if svc.Runner != nil && svc.Runner.Configured() {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		if err := svc.Runner.DeleteTaskVPN(ctx, taskID); err != nil {
			log.Printf("[ctf-vpn] 删除任务 #%s WireGuard Sidecar 失败：%v", t.ID, err)
		}
		cancel()
	}
	writeJSON(w, 200, ctfrunner.VPNSummary{Enabled: false})
}
