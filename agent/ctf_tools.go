package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/ctf"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type ctfRunKey struct{}

// CTF runs cannot acquire a second, application-host shell through MCP or the
// configurable shell_* catalog. Network and traffic tools in base remain usable.
func ctfBase(ctx context.Context, root string, ts *db.ExplorationStore, task, intent int64, base []actool.CoreTool) (context.Context, []actool.CoreTool) {
	if ts == nil {
		return ctx, base
	}
	mode, _, _, err := ts.TaskInputMetadata()
	if err != nil || mode != "ctf" {
		return ctx, base
	}
	service := ctf.New(root, ts.Database())
	out := []actool.CoreTool{}
	for _, t := range base {
		switch t.Name() {
		case "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS":
			continue
		case "report_finding", "update_finding_report":
			continue // CTF answers use their own evidence/WP flow, not vulnerability reports.
		}
		out = append(out, t)
	}
	out = append(out, ctfTools(service, task, intent)...)
	return context.WithValue(ctx, ctfRunKey{}, true), out
}

var ctfExecutionTools = []string{"Bash", "Write", "Edit", "ctf_http", "ctf_binary_info", "ctf_gdb", "ctf_python", "ctf_decompile", "ctf_radare2", "Read", "LS", "ctf_tools", "ctf_run_background", "ctf_job_status", "ctf_job_stop", "ctf_probe_target", "ctf_session_start", "ctf_session_send", "ctf_session_read", "ctf_session_close"}

func ctfCatalogTools() []actool.CoreTool {
	out := []actool.CoreTool{}
	for _, t := range ctfTools(nil, 0, 0) {
		if strings.HasPrefix(t.Name(), "ctf_") {
			out = append(out, t)
		}
	}
	return out
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func ctfTools(s *ctf.Service, task, intent int64) []actool.CoreTool {
	run := func(ctx context.Context, command string, timeout int) (actool.Result, error) {
		if s == nil {
			return actool.Errorf("CTF 工具仅在 CTF 任务上下文可用"), nil
		}
		e, err := s.Execute(ctx, task, intent, command, timeout)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		b, _ := json.Marshal(e)
		return actool.Text(string(b)), nil
	}
	commandTool := func(name, desc string, schema map[string]any, build func(map[string]json.RawMessage) (string, int, error)) actool.CoreTool {
		return writeTool(name, desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cmd, timeout, err := build(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return run(ctx, cmd, timeout)
		})
	}
	text := func(a map[string]json.RawMessage, k string) string {
		var v string
		_ = json.Unmarshal(a[k], &v)
		return v
	}
	num := func(a map[string]json.RawMessage, k string, def int) int {
		var v int
		if json.Unmarshal(a[k], &v) != nil || v <= 0 {
			return def
		}
		return v
	}
	file := func(a map[string]json.RawMessage) (string, error) {
		v := text(a, "file_path")
		if v == "" {
			v = text(a, "path")
		}
		if v == "" {
			return "", fmt.Errorf("缺少文件路径")
		}
		return v, nil
	}
	tools := []actool.CoreTool{
		commandTool("ctf_http", "在本题独立容器中请求 HTTP/HTTPS 题目，保存响应头、正文、状态码及实际执行 ID。响应中的 Flag 自动成为待确认候选。支持 GET/POST、URL 编码 query/form、请求头和意图内 Cookie；默认不跟随重定向，响应上限 8 MiB。Web 题优先使用此工具保留可复现证据。", obj(map[string]any{
			"url": str("用户提供的完整题目 URL"), "method": str("GET、POST、HEAD、PUT、PATCH、DELETE 或 OPTIONS；有正文时默认 POST"),
			"headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "请求头名称与值"},
			"query":   map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "自动 URL 编码的查询参数；需要特殊原始编码时直接写入 URL"},
			"form":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "自动编码的表单字段，不能与 body 同时提供"},
			"body":    str("原始请求正文，最多 64 KiB"), "timeout_seconds": intp("超时秒数，默认 30，最多 120"),
			"follow_redirects": map[string]any{"type": "boolean", "description": "仅当重定向仍属于题目范围时设为 true，最多 3 次"},
			"use_cookies":      map[string]any{"type": "boolean", "description": "保留本意图的 Cookie，默认 true"},
		}, "url"), ctfHTTPCommand),
		commandTool("Bash", "在本题专属 Pwn/RE 容器 /work 中执行 Bash。具备 GDB、pwntools、Ghidra、radare2、angr 等；日志和脚本自动进入 WP。无法访问 ARTEX 的配置、密钥或 Docker。超时会终止该容器的进程。", obj(map[string]any{"command": str("命令；附件路径见输入清单"), "timeout": intp("超时毫秒，最多 300000")}, "command"), func(a map[string]json.RawMessage) (string, int, error) {
			return text(a, "command"), min(num(a, "timeout", 120000)/1000, 300), nil
		}),
		commandTool("ctf_binary_info", "真实检查 ELF/PE 架构、依赖、符号及保护；不执行样本。", obj(map[string]any{"path": str("二进制路径")}, "path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			return "file -- " + quote(p) + "; readelf -h -l -d -s -- " + quote(p) + "; /opt/ctf/pwn/bin/pwn checksec " + quote(p), 60, err
		}),
		commandTool("ctf_gdb", "以 GDB batch 运行实际调试脚本，可设断点、运行、查看寄存器/栈/反汇编。保留 .gdb 脚本及输出。", obj(map[string]any{"path": str("样本路径，原始附件先复制到 /work 并 chmod +x"), "commands": str("多行 GDB 命令"), "timeout_seconds": intp("最多 300 秒")}, "path", "commands"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			script := "set pagination off\nset confirm off\n" + text(a, "commands") + "\n"
			return "printf %s " + quote(base64.StdEncoding.EncodeToString([]byte(script))) + " | base64 -d > debug.gdb\ngdb -q -nx -batch -x debug.gdb -- " + quote(p), num(a, "timeout_seconds", 120), err
		}),
		commandTool("ctf_python", "运行并留存实际 Python 求解脚本。pwn 使用 pwntools/ROP；reverse 使用 angr 10（from angr import claripy）、Z3、Unicorn、Keystone。", obj(map[string]any{"script": str("Python 源码"), "profile": str("pwn 或 reverse"), "filename": str("脚本文件名，默认 solve.py"), "timeout_seconds": intp("最多 300 秒")}, "script"), func(a map[string]json.RawMessage) (string, int, error) {
			name := text(a, "filename")
			if name == "" {
				name = "solve.py"
			}
			if path.Base(name) != name || !strings.HasSuffix(name, ".py") {
				return "", 0, fmt.Errorf("请使用简单的 .py 文件名")
			}
			python := "/opt/ctf/pwn/bin/python"
			if text(a, "profile") == "reverse" {
				python = "/opt/ctf/re/bin/python"
			}
			return "printf %s " + quote(base64.StdEncoding.EncodeToString([]byte(text(a, "script")))) + " | base64 -d > " + quote(name) + "\n" + python + " " + quote(name), num(a, "timeout_seconds", 120), nil
		}),
		commandTool("ctf_decompile", "使用 Ghidra headless 实际分析并反编译指定函数，自动启用持久分析缓存以加速后续调用。函数名为空时取前 5 个函数。", obj(map[string]any{"path": str("二进制路径"), "function": str("函数名，可为空"), "limit": intp("最多 20 个函数")}, "path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			limit := min(num(a, "limit", 5), 20)
			fn := text(a, "function")
			cmd := fmt.Sprintf(`h=$(sha256sum -- %s 2>/dev/null | cut -c1-12); [ -z "$h" ] && h="default"; pdir="/tmp/ghidra_$h"; bname=$(basename -- %s); if [ -f "$pdir/proj.gpr" ]; then analyzeHeadless "$pdir" proj -process "$bname" -noanalysis -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java %s %d; else mkdir -p "$pdir"; analyzeHeadless "$pdir" proj -import %s -analysisTimeoutPerFile 180 -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java %s %d; fi`,
				quote(p), quote(p), quote(fn), limit, quote(p), quote(fn), limit)
			return cmd, 300, err
		}),
		commandTool("ctf_radare2", "使用 radare2 执行实际静态分析命令，如 aaa;afl 或 pdf @ main。", obj(map[string]any{"path": str("二进制路径"), "commands": str("radare2 命令")}, "path", "commands"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := file(a)
			return "r2 -q -e scr.color=0 -c " + quote(text(a, "commands")) + " -c q -- " + quote(p), 120, err
		}),
		readTool("ctf_tools", "检查当前独立执行环境中工具的实际版本及 Python 导入状态。未就绪时返回原因。", obj(nil), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			v, err := s.Runner.Health(probeCtx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(v)
			return actool.Text(string(b)), nil
		}),
		readTool("ctf_status", "读取本题当前输入版本、执行次数和答案状态。候选仍需用户确认；已确认答案不等于任意自定义目标均已完成。返回最近 20 条候选。", obj(nil), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			progress, err := s.Progress(ctx, task)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(progress.Candidates) > 20 {
				progress.Candidates = progress.Candidates[:20]
			}
			b, _ := json.Marshal(progress)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_submit_flag", "将实际执行输出中的答案登记为候选，供用户在 WP 页面确认。不能将模型回复直接作为已验证答案。", obj(map[string]any{"execution_id": str("真实执行 ID"), "value": str("必须出现在该执行 stdout/stderr 中的答案")}, "execution_id", "value"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			id, err := s.Submit(ctx, task, text(a, "execution_id"), text(a, "value"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("候选 #%d 已登记；尚未确认，请保留脚本与复现步骤。", id)), nil
		}),
		writeTool("ctf_run_background", "在独立容器中启动后台长任务（如耗时暴破、深度 Ghidra 反编译、长时间 fuzz 或解题计算），不受 300 秒单次执行超时限制。返回 job_id，后续可通过 ctf_job_status 轮询进展与日志，通过 ctf_job_stop 终止。", obj(map[string]any{
			"command": str("要在后台运行的 Bash 命令"),
			"job_id":  str("任务自定义英文标识（可选，如 crack_zip、ghidra_deep）"),
		}, "command"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			cmd := text(a, "command")
			if strings.TrimSpace(cmd) == "" {
				return actool.Errorf("command 不能为空"), nil
			}
			jobID := text(a, "job_id")
			info, err := s.StartJob(ctx, task, intent, cmd, jobID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(info)
			return actool.Text(string(b)), nil
		}),
		readTool("ctf_job_status", "查询后台长任务状态（running / finished / failed / terminated）、退出码及最新输出日志。输出中的 Flag 同样会自动捕获登记为候选。job_id 为空时列出全部后台任务。", obj(map[string]any{
			"job_id":     str("任务标识；若为空则返回所有后台任务列表"),
			"tail_lines": intp("读取日志尾部行数，默认 100，最多 1000"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			jobID := text(a, "job_id")
			if strings.TrimSpace(jobID) == "" {
				list, err := s.ListJobs(ctx, task, intent)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				b, _ := json.Marshal(list)
				return actool.Text(string(b)), nil
			}
			tail := num(a, "tail_lines", 100)
			status, err := s.JobStatus(ctx, task, intent, jobID, tail)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(status)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_job_stop", "终止正在运行的后台长任务。", obj(map[string]any{
			"job_id": str("任务标识"),
		}, "job_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			jobID := text(a, "job_id")
			if strings.TrimSpace(jobID) == "" {
				return actool.Errorf("缺少 job_id"), nil
			}
			err := s.StopJob(ctx, task, intent, jobID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("后台任务 %s 已终止", jobID)), nil
		}),
		readTool("ctf_probe_target", "对远程靶机进行网络与协议探测（连通性测试、延迟测定、Banner 抓取、TLS/HTTP 协议识别、Proof-of-Work 挑战检测及交互菜单识别）。支持 'nc 1.2.3.4 9999'、'1.2.3.4:9999'、'http://...' 等格式。连接远程靶机前建议先探测。", obj(map[string]any{
			"target":          str("靶机目标，如 10.10.10.1:9999、nc 10.10.10.1 9999 或 http://10.10.10.1:8080/"),
			"timeout_seconds": intp("探测超时秒数，默认 10，最多 30"),
		}, "target"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			target := text(a, "target")
			if strings.TrimSpace(target) == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			timeout := min(num(a, "timeout_seconds", 10), 30)
			cmd := fmt.Sprintf("if [ -f /opt/ctf/scripts/probe_target.py ]; then python3 /opt/ctf/scripts/probe_target.py %s --json --timeout=%d; else python3 -c %s %s --timeout=%d; fi",
				quote(target), timeout, quote(ctf.ProbeTargetScript), quote(target), timeout)
			e, err := s.Execute(ctx, task, intent, cmd, timeout+10)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if e.ExitCode != 0 && e.Error != "" {
				return actool.Errorf(fmt.Sprintf("%s: %s", e.Error, e.StderrExcerpt)), nil
			}
			return actool.Text(e.StdoutExcerpt), nil
		}),
		writeTool("ctf_session_start", "启动持久交互终端会话（PTY 伪终端模式），适用于需要多轮交互的 CTF 题目（如 nc 远程靶机、带菜单的本地 Pwn 程序、gdb 交互等）。启动后使用 ctf_session_send 发送输入，使用 ctf_session_read 接收输出。", obj(map[string]any{
			"command":    str("启动命令，如 'nc 10.10.10.1 9999' 或 './vuln'"),
			"session_id": str("会话标识（可选，如 pty1、remote_nc）"),
		}, "command"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			cmd := text(a, "command")
			if strings.TrimSpace(cmd) == "" {
				return actool.Errorf("command 不能为空"), nil
			}
			sid := text(a, "session_id")
			info, err := s.StartInteractive(ctx, task, intent, cmd, sid)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(info)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_session_send", "向正在运行的持久交互会话发送输入数据（如菜单选择编号、用户名、ROP payload 等）。", obj(map[string]any{
			"session_id":   str("会话标识"),
			"data":         str("要发送的数据文本（若为二进制 payload 请设 encoding 为 base64）"),
			"encoding":     str("编码格式：'utf-8' 或 'base64'，默认 utf-8"),
			"auto_newline": map[string]any{"type": "boolean", "description": "是否自动在末尾追加回车换行符 \\n，默认 true"},
		}, "session_id", "data"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			sid := text(a, "session_id")
			data := text(a, "data")
			encoding := text(a, "encoding")
			if encoding == "" {
				encoding = "utf-8"
			}
			autoNL := true
			if v, ok := a["auto_newline"]; ok {
				_ = json.Unmarshal(v, &autoNL)
			}
			res, err := s.WriteInteractive(ctx, task, intent, sid, data, encoding, autoNL)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		}),
		readTool("ctf_session_read", "读取持久交互会话的增量输出内容。输出中的 Flag 会自动捕获登记为候选。session_id 为空时列出所有交互会话。", obj(map[string]any{
			"session_id": str("会话标识；为空时列出所有活跃会话"),
			"offset":     intp("从输出日志的字节偏移量开始读取，默认 0；多轮读取时请传入上一次返回的 offset 以获取增量"),
			"wait_ms":    intp("等待输出的最长毫秒数（100~10000），默认 1000"),
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			sid := text(a, "session_id")
			if strings.TrimSpace(sid) == "" {
				list, err := s.ListInteractive(ctx, task, intent)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				b, _ := json.Marshal(list)
				return actool.Text(string(b)), nil
			}
			offset := int64(num(a, "offset", 0))
			waitMs := num(a, "wait_ms", 1000)
			res, err := s.ReadInteractive(ctx, task, intent, sid, offset, waitMs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			b, _ := json.Marshal(res)
			return actool.Text(string(b)), nil
		}),
		writeTool("ctf_session_close", "终止并关闭指定的持久交互会话。", obj(map[string]any{
			"session_id": str("要关闭的会话标识"),
		}, "session_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil {
				return actool.Errorf("需要 CTF 上下文"), nil
			}
			var a map[string]json.RawMessage
			_ = json.Unmarshal(in, &a)
			sid := text(a, "session_id")
			if strings.TrimSpace(sid) == "" {
				return actool.Errorf("缺少 session_id"), nil
			}
			err := s.CloseInteractive(ctx, task, intent, sid)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("交互会话 %s 已关闭", sid)), nil
		}),
	}
	// File tools use the same container and evidence recorder as Bash. No local
	// application file reader is exposed, including on resumed conversations.
	scopedPath := func(a map[string]json.RawMessage) (string, error) {
		p, err := file(a)
		if err != nil {
			return "", err
		}
		if !path.IsAbs(p) {
			p = path.Join("/work", p)
		}
		if p != "/work" && !strings.HasPrefix(path.Clean(p), "/work/") {
			return "", fmt.Errorf("文件工具仅允许 /work 工作区与 /work/.inputs 附件")
		}
		return path.Clean(p), nil
	}
	tools = append(tools,
		commandTool("Read", "读取本题 /work 下的文本文件或附件，二进制请用 Bash xxd/readelf。", obj(map[string]any{"file_path": str("/work 内路径"), "offset": intp("起始行，默认 1"), "limit": intp("最多 500 行")}, "file_path"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := scopedPath(a)
			start := num(a, "offset", 1)
			return fmt.Sprintf("sed -n '%d,%dp' -- %s", start, start+min(num(a, "limit", 200), 500)-1, quote(p)), 30, err
		}),
		commandTool("Write", "将文本写入本题 /work 工作区，脚本自动纳入 WP 证据。", obj(map[string]any{"file_path": str("/work 内路径"), "content": str("文本")}, "file_path", "content"), func(a map[string]json.RawMessage) (string, int, error) {
			p, err := scopedPath(a)
			if strings.HasPrefix(p, "/work/.inputs") {
				err = fmt.Errorf("原始附件只读，请复制到工作区")
			}
			return "mkdir -p -- " + quote(path.Dir(p)) + "; printf %s " + quote(base64.StdEncoding.EncodeToString([]byte(text(a, "content")))) + " | base64 -d > " + quote(p), 30, err
		}),
		commandTool("LS", "列出本题 /work 工作区文件。", obj(map[string]any{"path": str("/work 内目录，默认 /work")}), func(a map[string]json.RawMessage) (string, int, error) {
			if text(a, "path") == "" {
				a["path"] = json.RawMessage(`"/work"`)
			}
			p, err := scopedPath(a)
			return "ls -lah -- " + quote(p), 30, err
		}),
	)
	return tools
}

// Legacy run-directory instructions are superseded by the CTF execution scope.
func ctfPrompt(root string, task, intent int64) string {
	return fmt.Sprintf(`

【CTF 专用流程：取得候选 → 交给用户提交验证】
Bash 和文件工具只在独立容器 /work 执行；脚本写在 /work。应用目录 %s 仅为归档路径。
Web 优先 ctf_http；Pwn/RE 按需选择静态分析、调试或求解脚本。仅工具缺失或异常时使用 ctf_tools 体检，不要每轮重复检查环境。
远程靶机访问：在连接远程靶机（如 nc 1.2.3.4 9999 或 http 端口）前，先使用 ctf_probe_target 探测连通性、RTT、初始 Banner、TLS 以及是否有 Proof-of-Work (PoW) 校验。
多轮交互挑战：对于需要交互菜单选择、多轮 stdin 输入或动态交互的靶机/本地程序，请使用 ctf_session_start 启动持久 PTY 会话，使用 ctf_session_send 发送多轮输入，使用 ctf_session_read 接收输出（输出中的 Flag 同样会自动提取并登记候选），结束时调用 ctf_session_close。
长耗时任务（如大型程序 Ghidra 反编译、密码字典暴破、全路径符号执行等预计超过 2 分钟的任务）请使用 ctf_run_background 后台运行，并用 ctf_job_status 轮询结果与日志，避免单个命令超时。
执行自动保存命令、输出、脚本及 execution_id，常见 Flag 自动登记候选；非标准答案才需 ctf_submit_flag，且必须来自真实执行输出。
一旦出现候选，立即停止探测、重复 payload、资产扩展、漏洞报告和目标证明；只交付候选值、来源执行和一句解法摘要，等待用户提交题目平台验证。WP 无需额外模型整理。
候选不是正确答案：用户确认后才引用已确认记录证明对应最终目标；用户否定后按反馈继续，避免再次提交同一被否定答案。
分析步骤不拆成必须验收的目标；多 Flag 或额外交付只按用户明确要求处理。`, filepath.Join(root, "tasks", fmt.Sprint(task), fmt.Sprintf("i%d", intent)))
}
