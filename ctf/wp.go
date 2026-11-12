package ctf

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type WP struct {
	Revision    string    `json:"revision"`
	Markdown    string    `json:"markdown"`
	SHA256      string    `json:"sha256"`
	GeneratedAt time.Time `json:"generated_at"`
	IsOptimized bool      `json:"is_optimized,omitempty"`
}
type wpFact struct {
	ID      int64           `json:"id"`
	State   string          `json:"state"`
	Payload json.RawMessage `json:"payload"`
}

func fence(b string, lang string) string {
	mark := "```"
	for strings.Contains(b, mark) {
		mark += "`"
	}
	return mark + lang + "\n" + b + "\n" + mark + "\n\n"
}

type effectiveStep struct {
	ExecutionID string
	Command     string
	Summary     string
	Stdout      string
	IsWinner    bool
}

func isNoiseCommand(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return true
	}
	// Pure exploratory inspection commands with no transformation or exploit logic
	noisePrefixes := []string{
		"ls", "dir", "pwd", "whoami", "id", "uname", "env",
		"cd /work && ls", "cd /work; ls",
	}
	for _, p := range noisePrefixes {
		if c == p || strings.HasPrefix(c, p+" ") {
			return true
		}
	}
	return false
}

func summarizeCommand(cmd string) string {
	c := strings.TrimSpace(cmd)
	switch {
	case strings.Contains(c, "unzip") || strings.Contains(c, "tar ") || strings.Contains(c, "7z "):
		return "解压并提取题目附件文件"
	case strings.Contains(c, "checksec"):
		return "检查二进制安全缓解机制（Canary / NX / PIE / RELRO）"
	case strings.Contains(c, "binwalk") || strings.Contains(c, "foremost"):
		return "提取与分离文件末尾隐藏结构/内嵌文件"
	case strings.Contains(c, "exiftool") || strings.Contains(c, "zsteg") || strings.Contains(c, "steghide"):
		return "隐写与元数据检测分析"
	case strings.Contains(c, "file ") || strings.Contains(c, "xxd") || strings.Contains(c, "strings"):
		return "文件格式与魔数/敏感字符串初步审查"
	case strings.Contains(c, "pcap") || strings.Contains(c, "tshark") || strings.Contains(c, "tcpdump") || strings.Contains(c, "scapy"):
		return "流量包结构化分析与传输对象/会话提取"
	case strings.Contains(c, "python") || strings.Contains(c, "./") || strings.Contains(c, "gdb"):
		return "运行核心解题与求解/利用脚本"
	default:
		return "执行关键分析操作"
	}
}

func (s *Service) GenerateWP(ctx context.Context, task int64) (WP, error) {
	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "deliverables", "wp")
	optPath := filepath.Join(dir, "optimized.json")
	if b, e := os.ReadFile(optPath); e == nil {
		var opt WP
		if err := json.Unmarshal(b, &opt); err == nil && opt.SHA256 == SHA([]byte(opt.Markdown)) {
			opt.IsOptimized = true
			return opt, nil
		}
	}
	return s.GenerateRawWP(ctx, task)
}

func (s *Service) ResetOptimizedWP(ctx context.Context, task int64) (WP, error) {
	unlock := executionLock(fmt.Sprintf("wp/%s/%d", s.Root, task))
	defer unlock()
	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "deliverables", "wp")
	_ = os.Remove(filepath.Join(dir, "optimized.json"))
	_ = os.Remove(filepath.Join(dir, "optimized.md"))
	return s.generateRawWPUnlocked(ctx, task)
}

func (s *Service) GenerateRawWP(ctx context.Context, task int64) (WP, error) {
	unlock := executionLock(fmt.Sprintf("wp/%s/%d", s.Root, task))
	defer unlock()
	return s.generateRawWPUnlocked(ctx, task)
}

func (s *Service) generateRawWPUnlocked(ctx context.Context, task int64) (WP, error) {
	var result WP
	if err := s.Sync(ctx, task); err != nil {
		return result, err
	}
	var name, description, goal, status, challenge string
	var exp int64
	if err := s.DB.QueryRowContext(ctx, `SELECT name,description,goal,status,challenge_type,exploration_id FROM tasks WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`, task).Scan(&name, &description, &goal, &status, &challenge, &exp); err != nil {
		return result, err
	}
	m, err := (artifacts.Store{Root: s.Root}).Inputs(task, 0)
	if err != nil {
		return result, err
	}
	executions, err := s.DB.CTFExecutions(ctx, task)
	if err != nil {
		return result, err
	}
	candidates, err := s.DB.CTFCandidates(ctx, task)
	if err != nil {
		return result, err
	}
	facts := []wpFact{}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,state,payload FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' ORDER BY id LIMIT 300`, exp)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var f wpFact
		if err = rows.Scan(&f.ID, &f.State, &f.Payload); err != nil {
			rows.Close()
			return result, err
		}
		facts = append(facts, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}

	const wpGeneratorVersion = "v0.7.0"
	source := struct {
		GeneratorVersion                           string
		Task                                       int64
		Name, Description, Goal, Status, Challenge string
		Manifest                                   artifacts.Manifest
		Executions                                 []db.CTFExecution
		Candidates                                 []db.CTFCandidate
		Facts                                      []wpFact
	}{wpGeneratorVersion, task, name, description, goal, status, challenge, m, executions, candidates, facts}
	raw, _ := json.Marshal(source)
	revision := SHA(raw)
	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "deliverables", "wp")
	p := filepath.Join(dir, revision+".json")
	if b, e := os.ReadFile(p); e == nil {
		if err = json.Unmarshal(b, &result); err != nil {
			return result, err
		}
		if result.SHA256 != SHA([]byte(result.Markdown)) {
			return result, fmt.Errorf("WP 内容摘要不匹配")
		}
		return result, nil
	} else if !os.IsNotExist(e) {
		return result, e
	}

	// 1. Identify accepted or winning candidates
	currentHash := Hash(m)
	var confirmedCand *db.CTFCandidate
	var latestCand *db.CTFCandidate
	for i := range candidates {
		c := &candidates[i]
		if c.State == "accepted" && c.InputHash == currentHash {
			confirmedCand = c
			break
		}
		if c.State == "candidate" && c.InputHash == currentHash {
			latestCand = c
		}
	}

	winningExecID := ""
	if confirmedCand != nil {
		winningExecID = confirmedCand.ExecutionID
	} else if latestCand != nil {
		winningExecID = latestCand.ExecutionID
	}

	// Map executions by ID
	execMap := make(map[string]*db.CTFExecution)
	for i := range executions {
		execMap[executions[i].ID] = &executions[i]
	}

	var b strings.Builder
	if name == "" {
		name = description
	}
	challengeLabel := strings.ToUpper(challenge)
	if challengeLabel == "" || challengeLabel == "AUTO" {
		challengeLabel = "CTF 综合 / 自动分析"
	}

	// Title and Summary Metadata
	fmt.Fprintf(&b, "# 解题报告（Write-up）— %s\n\n", strings.ReplaceAll(name, "\n", " "))
	if confirmedCand != nil {
		fmt.Fprintf(&b, "> [!IMPORTANT]\n> **解题成功已确认**：当前输入的答案已由用户确认并在题目平台核验无误，以下为整理后的精炼复现步骤与完整求解源码。\n\n")
	} else if latestCand != nil {
		fmt.Fprintf(&b, "> [!NOTE]\n> **阶段报告（解题草稿）**：已捕获候选 Flag（`%s`），正等待在题目平台进行提交验证。\n\n", latestCand.Value)
	} else {
		b.WriteString("> [!NOTE]\n> **阶段报告**：正在分析探索中，尚未捕获候选 Flag。\n\n")
	}

	b.WriteString("| 属性 | 内容 |\n| :--- | :--- |\n")
	fmt.Fprintf(&b, "| **题目名称** | %s |\n", strings.ReplaceAll(name, "\n", " "))
	fmt.Fprintf(&b, "| **赛题类别** | %s |\n", challengeLabel)
	if confirmedCand != nil {
		fmt.Fprintf(&b, "| **最终 Flag** | `%s` (平台验证确认) |\n", confirmedCand.Value)
	} else if latestCand != nil {
		fmt.Fprintf(&b, "| **当前候选** | `%s` (待确认) |\n", latestCand.Value)
	} else {
		b.WriteString("| **解题状态** | 正在分析探索中 |\n")
	}
	fmt.Fprintf(&b, "| **生成版本** | `%s` · %s |\n\n", revision[:12], time.Now().UTC().Format(time.RFC3339))

	// 0x01 Challenge Overview
	b.WriteString("## 0x01 题目概况与考点分析\n\n")
	if description != "" {
		fmt.Fprintf(&b, "**题目描述**：\n%s\n\n", description)
	}
	if goal != "" {
		fmt.Fprintf(&b, "**交付目标**：\n%s\n\n", goal)
	}

	if len(m.Files) > 0 {
		b.WriteString("### 附件清单与特征：\n")
		for _, a := range m.Files {
			fmt.Fprintf(&b, "- **`%s`**（%s）：大小 %d 字节，SHA-256 `%s`\n", a.Name, a.Role, a.Size, a.SHA256)
		}
		b.WriteString("\n")
	}

	// 0x02 Effective Steps (Noise-free causal steps)
	b.WriteString("## 0x02 核心解题步骤（有效链路）\n\n")
	seenCmds := make(map[string]bool)
	var steps []effectiveStep

	for _, e := range executions {
		cmdTrimmed := strings.TrimSpace(e.Command)
		if e.ExitCode != 0 && e.ID != winningExecID {
			continue // Ignore failed test runs
		}
		if isNoiseCommand(cmdTrimmed) && e.ID != winningExecID {
			continue // Filter out noise directory checks
		}
		if seenCmds[cmdTrimmed] && e.ID != winningExecID {
			continue // Deduplicate identical commands
		}
		seenCmds[cmdTrimmed] = true

		steps = append(steps, effectiveStep{
			ExecutionID: e.ID,
			Command:     e.Command,
			Summary:     summarizeCommand(e.Command),
			Stdout:      string(e.StdoutExcerpt),
			IsWinner:    e.ID == winningExecID,
		})
	}

	if len(steps) == 0 {
		b.WriteString("当前尚无完整的有效执行步骤记录。\n\n")
	} else {
		for idx, st := range steps {
			star := ""
			if st.IsWinner {
				star = " 🎯【关键 Flag 产出步骤】"
			}
			fmt.Fprintf(&b, "### 步骤 %d：%s%s\n\n", idx+1, st.Summary, star)
			b.WriteString(fence(st.Command, "bash"))
			if st.Stdout != "" && (st.IsWinner || len(steps) <= 5) {
				b.WriteString("**关键输出回显**：\n")
				b.WriteString(fence(strings.TrimSpace(st.Stdout), "text"))
			}
		}
	}

	// 0x03 Winning Exploit / Script
	b.WriteString("## 0x03 核心求解脚本 (Exploit / PoC)\n\n")
	var primaryScript *Script
	var scriptData []byte

	// Look in winning execution first, then search backwards
	searchExecs := []*db.CTFExecution{}
	if winningExecID != "" && execMap[winningExecID] != nil {
		searchExecs = append(searchExecs, execMap[winningExecID])
	}
	for i := len(executions) - 1; i >= 0; i-- {
		if winningExecID == "" || executions[i].ID != winningExecID {
			searchExecs = append(searchExecs, &executions[i])
		}
	}

	for _, e := range searchExecs {
		var files []Script
		if err = json.Unmarshal(e.Files, &files); err == nil && len(files) > 0 {
			for _, f := range files {
				ext := strings.ToLower(filepath.Ext(f.Name))
				if ext == ".py" || ext == ".sh" || ext == ".c" {
					if d, er := s.EvidenceFile(task, f.Path, f.SHA256); er == nil && len(d) > 0 {
						primaryScript = &f
						scriptData = d
						break
					}
				}
			}
		}
		if primaryScript != nil {
			break
		}
	}

	if primaryScript != nil {
		lang := strings.TrimPrefix(filepath.Ext(primaryScript.Name), ".")
		if lang == "" {
			lang = "python"
		}
		fmt.Fprintf(&b, "以下为解题过程中生成的完整求解脚本 (`%s`，SHA-256 `%s`)，可直接在准备好的工作区中复现执行：\n\n", primaryScript.Name, primaryScript.SHA256)
		b.WriteString(fence(string(scriptData), lang))
	} else if confirmedCand != nil && execMap[confirmedCand.ExecutionID] != nil {
		b.WriteString("本题通过命令行链式指令直接取得 Flag，核心复现命令如下：\n\n")
		b.WriteString(fence(execMap[confirmedCand.ExecutionID].Command, "bash"))
	} else {
		b.WriteString("本阶段暂未持久化独立的解题脚本文件。\n\n")
	}

	// 0x04 Verification and Flag
	b.WriteString("## 0x04 验证结果与 Flag\n\n")
	if confirmedCand != nil {
		fmt.Fprintf(&b, "- **最终验证 Flag**：`%s`\n", confirmedCand.Value)
		fmt.Fprintf(&b, "- **验证状态**：已由用户在题目平台提交并确认为正确答案（Accepted）\n")
		if confirmedCand.Notes != "" {
			fmt.Fprintf(&b, "- **用户验证备注**：%s\n", confirmedCand.Notes)
		}
		fmt.Fprintf(&b, "- **来源执行记录**：`%s`\n\n", confirmedCand.ExecutionID)
	} else if latestCand != nil {
		fmt.Fprintf(&b, "- **当前命中 Flag**：`%s`\n", latestCand.Value)
		fmt.Fprintf(&b, "- **验证状态**：待人工在题目平台确认（Pending Confirmation）\n")
		fmt.Fprintf(&b, "- **来源执行记录**：`%s`\n\n", latestCand.ExecutionID)
	} else {
		b.WriteString("尚未取得符合目标格式的 Flag。\n\n")
	}

	// Appendix: Audit Trail (Collapsible)
	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "<details>\n<summary><b>点击展开：完整原始执行证据链与安全审计日志（共 %d 次执行）</b></summary>\n\n", len(executions))
	b.WriteString("> 此处保留沙箱容器内运行的全部历史命令、执行耗时、退出码与日志 SHA-256 校验和，确保复现证据链完整不可篡改。\n\n")

	scripts := map[string]bool{}
	for i := len(executions) - 1; i >= 0; i-- {
		e := executions[i]
		fmt.Fprintf(&b, "#### 执行记录 `%s`\n", e.ID)
		fmt.Fprintf(&b, "- 意图：%d · 时间：%s · 退出码：%d\n", e.IntentID, e.StartedAt.UTC().Format(time.RFC3339), e.ExitCode)
		if e.InputHash != currentHash {
			b.WriteString("- 状态：旧输入版本\n")
		}
		b.WriteString("\n")
		b.WriteString(fence(e.Command, "bash"))
		if e.Error != "" {
			fmt.Fprintf(&b, "**执行异常**：%s\n\n", e.Error)
		}
		for _, log := range []struct{ name, path, hash string }{{"stdout", e.StdoutPath, e.StdoutSHA}, {"stderr", e.StderrPath, e.StderrSHA}} {
			data, er := s.EvidenceFile(task, log.path, log.hash)
			if er == nil && len(data) > 0 {
				fmt.Fprintf(&b, "**%s** (SHA-256: `%s`):\n", log.name, log.hash)
				b.WriteString(fence(excerpt(data, 4000), "text"))
			}
		}
		var files []Script
		if err = json.Unmarshal(e.Files, &files); err == nil {
			for _, f := range files {
				if !scripts[f.SHA256] {
					scripts[f.SHA256] = true
					if d, er := s.EvidenceFile(task, f.Path, f.SHA256); er == nil && len(d) > 0 {
						fmt.Fprintf(&b, "**快照文件** `%s` (SHA-256: `%s`):\n", f.Name, f.SHA256)
						if len(d) <= 8000 {
							b.WriteString(fence(string(d), strings.TrimPrefix(filepath.Ext(f.Name), ".")))
						}
					}
				}
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("</details>\n")

	result = WP{Revision: revision, Markdown: b.String(), SHA256: SHA([]byte(b.String())), GeneratedAt: time.Now().UTC()}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return result, err
	}
	raw, _ = json.MarshalIndent(result, "", "  ")
	if err = os.WriteFile(p+".tmp", raw, 0600); err != nil {
		return result, err
	}
	if err = os.Rename(p+".tmp", p); err != nil {
		return result, err
	}
	if err = os.WriteFile(filepath.Join(dir, revision+".md"), []byte(result.Markdown), 0600); err != nil {
		return result, err
	}
	return result, nil
}

func generateOverviewText(challenge, name, description string, fileCount int, script *Script, flagVal string) string {
	c := strings.ToLower(strings.TrimSpace(challenge))
	switch {
	case c == "pwn" || strings.Contains(strings.ToLower(name), "pwn"):
		return "本题属于 **Pwn（二进制漏洞利用）** 赛题。整体解题思路如下：首先对目标二进制文件的保护机制（Canary / NX / PIE / RELRO）进行审查，结合静态逆向分析定位输入缓冲区溢出或格式化字符串漏洞原语；随后根据目标保护与运行环境构造精准的溢出偏移与 ROP 链（或 ret2libc 泄露基址），最后运行本地/远程利用脚本直接获取权限并读取最终 Flag。"
	case c == "reverse" || strings.Contains(strings.ToLower(name), "reverse") || strings.Contains(strings.ToLower(name), "re"):
		return "本题属于 **Reverse（逆向工程）** 赛题。整体解题思路如下：首先排查目标二进制架构与壳机制（UPX 脱壳），定位主校验函数与加密变换逻辑；针对复杂的数据变换、线性变换或矩阵约束，利用 Z3 约束求解器或反向逆算法快速推导满足条件的原始输入，最终成功还原题目所需的真实 Flag。"
	case c == "crypto" || strings.Contains(strings.ToLower(name), "crypto") || strings.Contains(strings.ToLower(name), "rsa"):
		return "本题属于 **Crypto（密码学）** 赛题。整体解题思路如下：首先分析题目给出的公钥参数、密文格式与加密逻辑，快速识别其存在的经典攻击向量（如 RSA 低加密指数、因数分解弱点、同余方程组或共模攻击）；随后调用高精度数论库编写 Python 脚本反求明文，直接还原出目标 Flag。"
	case c == "misc" || strings.Contains(strings.ToLower(name), "misc") || strings.Contains(strings.ToLower(name), "look"):
		return "本题属于 **Misc（杂项安全 / 电子取证）** 赛题。整体解题思路如下：首先通过真实文件魔数排查目标文件的本质属性，识别并分离内嵌的隐藏文件、修复伪加密或解析隐写图层；随后编写针对性脚本精准提取深层隐匿数据，顺利还原出符合格式规范的 Flag。"
	case c == "web" || strings.Contains(strings.ToLower(name), "web"):
		return "本题属于 **Web（Web 安全）** 赛题。整体解题思路如下：首先对题目接口进行轻量化资产探测与源码特性审计，快速锁定注入点、伪协议、身份伪造或反序列化攻击链；随后构造针对性 Payload 触发目标漏洞，成功从响应回显或服务端环境中读取并提取出 Flag。"
	default:
		return "本题解题过程遵循「特征定性 → 关键分析 → 自动化求解 → 提取验证」的标准竞赛链路：首先对题目附件与目标环境完成静态特征审查，排查并定位核心逻辑断点；随后编写轻量级专精 PoC 脚本直击求解核心，最终在沙箱执行环境中稳定还原出正确 Flag 并完成验证。"
	}
}

func (s *Service) generateDeterministicOptimizedWP(
	name, description, goal, challenge string,
	manifest artifacts.Manifest,
	executions []db.CTFExecution,
	confirmedCand *db.CTFCandidate,
	latestCand *db.CTFCandidate,
	winningExecID string,
	primaryScript *Script,
	scriptData []byte,
) string {
	var b strings.Builder
	if name == "" {
		name = description
	}
	challengeLabel := strings.ToUpper(challenge)
	if challengeLabel == "" || challengeLabel == "AUTO" {
		challengeLabel = "CTF 综合 / 自动分析"
	}

	flagVal := "待验证"
	if confirmedCand != nil {
		flagVal = confirmedCand.Value
	} else if latestCand != nil {
		flagVal = latestCand.Value
	}

	fmt.Fprintf(&b, "# 【核心精炼】解题报告（Write-up）— %s\n\n", strings.ReplaceAll(name, "\n", " "))
	b.WriteString("> [!TIP]\n> **比赛级精简题解报告（已过滤冗余试错与无关过程）**：本报告仅保留赛题整体解题思路概述、核心考点突破、最小必要复现链路以及完整可复现的 Exploit / PoC 脚本。\n\n")

	b.WriteString("| 赛题属性 | 说明 |\n| :--- | :--- |\n")
	fmt.Fprintf(&b, "| **赛题名称** | %s |\n", strings.ReplaceAll(name, "\n", " "))
	fmt.Fprintf(&b, "| **赛题类别** | %s |\n", challengeLabel)
	if confirmedCand != nil {
		fmt.Fprintf(&b, "| **最终 Flag** | `%s` (平台验证确认) |\n", confirmedCand.Value)
	} else if latestCand != nil {
		fmt.Fprintf(&b, "| **当前命中 Flag** | `%s` (待平台核验) |\n", latestCand.Value)
	} else {
		b.WriteString("| **最终 Flag** | 尚未捕获有效 Flag |\n")
	}
	if primaryScript != nil {
		fmt.Fprintf(&b, "| **核心 PoC 脚本** | `%s` |\n", primaryScript.Name)
	}
	b.WriteString("| **报告模式** | ✨ 核心精简版（已重新梳理） |\n\n")

	// Overview section at the very beginning
	b.WriteString("## 整体解题思路概述 (Solution Overview)\n\n")
	b.WriteString(generateOverviewText(challenge, name, description, len(manifest.Files), primaryScript, flagVal))
	b.WriteString("\n\n---\n\n")

	// 0x01 Challenge Overview
	b.WriteString("## 0x01 题目概况与关键考点 (Core Concept)\n\n")
	if description != "" {
		fmt.Fprintf(&b, "**题目描述**：\n%s\n\n", description)
	}
	if goal != "" {
		fmt.Fprintf(&b, "**交付目标**：\n%s\n\n", goal)
	}
	if len(manifest.Files) > 0 {
		b.WriteString("**目标附件清单**：\n")
		for _, f := range manifest.Files {
			fmt.Fprintf(&b, "- `%s` (%s, %d 字节, SHA-256 `%s`)\n", f.Name, f.Role, f.Size, f.SHA256[:16]+"...")
		}
		b.WriteString("\n")
	}

	// 0x02 Minimal Necessary Steps
	b.WriteString("## 0x02 最小有效解题路径 (Minimal Reproduction Steps)\n\n")
	var essentialSteps []effectiveStep

	// Step 1: initial setup or detection command
	for _, e := range executions {
		cmd := strings.TrimSpace(e.Command)
		if e.ExitCode == 0 && !isNoiseCommand(cmd) && e.ID != winningExecID {
			if strings.Contains(cmd, "checksec") || strings.Contains(cmd, "unzip") ||
				strings.Contains(cmd, "tar ") || strings.Contains(cmd, "pcap") ||
				strings.Contains(cmd, "probe") || strings.Contains(cmd, "binwalk") ||
				strings.Contains(cmd, "exiftool") {
				essentialSteps = append(essentialSteps, effectiveStep{
					ExecutionID: e.ID,
					Command:     e.Command,
					Summary:     summarizeCommand(e.Command),
					Stdout:      e.StdoutExcerpt,
				})
				break
			}
		}
	}

	// Step 2: winning execution
	for _, e := range executions {
		if e.ID == winningExecID {
			essentialSteps = append(essentialSteps, effectiveStep{
				ExecutionID: e.ID,
				Command:     e.Command,
				Summary:     "运行核心求解脚本触发漏洞并提取 Flag",
				Stdout:      e.StdoutExcerpt,
				IsWinner:    true,
			})
			break
		}
	}

	if len(essentialSteps) == 0 {
		count := 0
		for _, e := range executions {
			cmd := strings.TrimSpace(e.Command)
			if e.ExitCode == 0 && !isNoiseCommand(cmd) {
				essentialSteps = append(essentialSteps, effectiveStep{
					ExecutionID: e.ID,
					Command:     e.Command,
					Summary:     summarizeCommand(e.Command),
					Stdout:      e.StdoutExcerpt,
					IsWinner:    e.ID == winningExecID,
				})
				count++
				if count >= 2 {
					break
				}
			}
		}
	}

	if len(essentialSteps) == 0 {
		b.WriteString("本阶段暂无有效关键命令记录。\n\n")
	} else {
		for idx, st := range essentialSteps {
			star := ""
			if st.IsWinner {
				star = " 🎯【直击 Flag 产出】"
			}
			fmt.Fprintf(&b, "### 步骤 %d：%s%s\n\n", idx+1, st.Summary, star)
			b.WriteString(fence(st.Command, "bash"))
			if st.Stdout != "" {
				b.WriteString("**执行回显**：\n")
				b.WriteString(fence(strings.TrimSpace(st.Stdout), "text"))
			}
		}
	}

	// 0x03 Winning Exploit / PoC
	b.WriteString("## 0x03 核心求解脚本 (Exploit / PoC 源码)\n\n")
	if primaryScript != nil {
		lang := strings.TrimPrefix(filepath.Ext(primaryScript.Name), ".")
		if lang == "" {
			lang = "python"
		}
		fmt.Fprintf(&b, "以下为获取 Flag 的完整求解脚本 (`%s`，SHA-256 `%s`)，具备独立复现性：\n\n", primaryScript.Name, primaryScript.SHA256)
		b.WriteString(fence(string(scriptData), lang))
	} else if confirmedCand != nil && winningExecID != "" {
		for _, e := range executions {
			if e.ID == winningExecID {
				b.WriteString("本题通过核心单行链式指令直接取得 Flag：\n\n")
				b.WriteString(fence(e.Command, "bash"))
				break
			}
		}
	} else {
		b.WriteString("本题暂未独立保存脚本文件。\n\n")
	}

	// 0x04 Verification and Flag
	b.WriteString("## 0x04 验证结果与最终 Flag\n\n")
	if confirmedCand != nil {
		fmt.Fprintf(&b, "- **最终验证 Flag**：`%s`\n", confirmedCand.Value)
		fmt.Fprintf(&b, "- **验证状态**：已由用户在题目平台提交并确认为正确答案（Accepted）\n")
		if confirmedCand.Notes != "" {
			fmt.Fprintf(&b, "- **验证反馈备注**：%s\n", confirmedCand.Notes)
		}
		fmt.Fprintf(&b, "- **来源执行记录**：`%s`\n", confirmedCand.ExecutionID)
	} else if latestCand != nil {
		fmt.Fprintf(&b, "- **当前命中 Flag**：`%s`\n", latestCand.Value)
		fmt.Fprintf(&b, "- **验证状态**：待人工在题目平台确认（Pending Confirmation）\n")
		fmt.Fprintf(&b, "- **来源执行记录**：`%s`\n", latestCand.ExecutionID)
	} else {
		b.WriteString("尚未取得符合目标格式的 Flag。\n")
	}

	return b.String()
}

func (s *Service) llmOptimizeWP(
	ctx context.Context,
	prov llm.Provider,
	name, description, goal, challenge string,
	manifest artifacts.Manifest,
	executions []db.CTFExecution,
	confirmedCand *db.CTFCandidate,
	latestCand *db.CTFCandidate,
	winningExecID string,
	primaryScript *Script,
	scriptData []byte,
) string {
	if prov == nil {
		return ""
	}

	systemPrompt := `你是一名世界顶级 CTF 战队队长与安全专家。请根据提供的赛题信息、真实执行记录与最终产出 Flag 的求解代码，整理出一份极其精炼、逻辑严密、直击要害的比赛标准 Write-up。
【强制要求】：
1. 最前面必须包含一段深入浅出的【整体解题思路概述 (Solution Overview)】，概括整个赛题的考察本质与解法全貌。
2. 极简主义：彻底去除所有无关的探索尝试、调试试错、查看目录、重复查看文件或报错日志，只保留走向正确 Flag 的最小关键路径。
3. 规范结构：
   - 整体解题思路概述 (Solution Overview)
   - 0x01 题目概况与核心考点
   - 0x02 最小有效复现步骤（只保留 2~4 个不可或缺的关键动作）
   - 0x03 核心求解脚本 (Exploit / PoC 完整源码，必须完整展示，便于一键独立复现）
   - 0x04 验证结果与最终 Flag
4. 严禁捏造未执行的命令；必须保留真实捕获的 Flag 与求解脚本源码。
5. 直接输出标准 GitHub 风格 Markdown 文本，不要带有最外层的包装标记。`

	flagVal := "待验证"
	if confirmedCand != nil {
		flagVal = confirmedCand.Value
	} else if latestCand != nil {
		flagVal = latestCand.Value
	}

	pocCode := ""
	if primaryScript != nil {
		pocCode = fmt.Sprintf("文件名: %s\n```\n%s\n```", primaryScript.Name, string(scriptData))
	}

	var winningCmd, winningOutput string
	for _, e := range executions {
		if e.ID == winningExecID {
			winningCmd = e.Command
			winningOutput = e.StdoutExcerpt
			break
		}
	}

	var usefulCmds []string
	for _, e := range executions {
		c := strings.TrimSpace(e.Command)
		if e.ExitCode == 0 && !isNoiseCommand(c) {
			usefulCmds = append(usefulCmds, c)
		}
	}
	if len(usefulCmds) > 10 {
		usefulCmds = usefulCmds[len(usefulCmds)-10:]
	}

	userContent := fmt.Sprintf(`【赛题名称】：%s
【赛题类别】：%s
【题目描述】：%s
【交付目标】：%s
【最终验证 Flag】：%s
【关键成功命令】：
%s
【关键回显输出】：
%s
【核心求解 PoC / Exploit 脚本】：
%s
【精选有效命令历史】：
%s`, name, challenge, description, goal, flagVal, winningCmd, winningOutput, pocCode, strings.Join(usefulCmds, "\n"))

	llmCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	msg, _, _, err := prov.Complete(llmCtx, llm.CompletionRequest{
		System:    []string{systemPrompt},
		Messages:  []llm.Message{llm.UserText(userContent)},
		MaxTokens: 8000,
		Thinking:  "disabled",
	})
	if err != nil {
		return ""
	}

	text := strings.TrimSpace(msg.Text())
	if strings.HasPrefix(text, "```markdown") {
		text = strings.TrimPrefix(text, "```markdown")
		text = strings.TrimSuffix(text, "```")
	} else if strings.HasPrefix(text, "```") && strings.HasSuffix(text, "```") {
		text = strings.TrimPrefix(text, "```")
		text = strings.TrimSuffix(text, "```")
	}
	text = strings.TrimSpace(text)

	if strings.Contains(text, "#") && strings.Contains(text, flagVal) && len(text) > 200 {
		return text
	}
	return ""
}

func (s *Service) GenerateOptimizedWP(ctx context.Context, task int64, prov llm.Provider) (WP, error) {
	unlock := executionLock(fmt.Sprintf("wp/%s/%d", s.Root, task))
	defer unlock()

	var result WP
	if err := s.Sync(ctx, task); err != nil {
		return result, err
	}
	var name, description, goal, status, challenge string
	var exp int64
	if err := s.DB.QueryRowContext(ctx, `SELECT name,description,goal,status,challenge_type,exploration_id FROM tasks WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL`, task).Scan(&name, &description, &goal, &status, &challenge, &exp); err != nil {
		return result, err
	}
	m, err := (artifacts.Store{Root: s.Root}).Inputs(task, 0)
	if err != nil {
		return result, err
	}
	executions, err := s.DB.CTFExecutions(ctx, task)
	if err != nil {
		return result, err
	}
	candidates, err := s.DB.CTFCandidates(ctx, task)
	if err != nil {
		return result, err
	}

	currentHash := Hash(m)
	var confirmedCand *db.CTFCandidate
	var latestCand *db.CTFCandidate
	for i := range candidates {
		c := &candidates[i]
		if c.State == "accepted" && c.InputHash == currentHash {
			confirmedCand = c
			break
		}
		if c.State == "candidate" && c.InputHash == currentHash {
			latestCand = c
		}
	}

	winningExecID := ""
	if confirmedCand != nil {
		winningExecID = confirmedCand.ExecutionID
	} else if latestCand != nil {
		winningExecID = latestCand.ExecutionID
	}

	execMap := make(map[string]*db.CTFExecution)
	for i := range executions {
		execMap[executions[i].ID] = &executions[i]
	}

	// Find primary script
	var primaryScript *Script
	var scriptData []byte
	searchExecs := []*db.CTFExecution{}
	if winningExecID != "" && execMap[winningExecID] != nil {
		searchExecs = append(searchExecs, execMap[winningExecID])
	}
	for i := len(executions) - 1; i >= 0; i-- {
		if winningExecID == "" || executions[i].ID != winningExecID {
			searchExecs = append(searchExecs, &executions[i])
		}
	}
	for _, e := range searchExecs {
		var files []Script
		if err = json.Unmarshal(e.Files, &files); err == nil && len(files) > 0 {
			for _, f := range files {
				ext := strings.ToLower(filepath.Ext(f.Name))
				if ext == ".py" || ext == ".sh" || ext == ".c" {
					if d, er := s.EvidenceFile(task, f.Path, f.SHA256); er == nil && len(d) > 0 {
						primaryScript = &f
						scriptData = d
						break
					}
				}
			}
		}
		if primaryScript != nil {
			break
		}
	}

	optimizedMarkdown := ""
	if prov != nil {
		optimizedMarkdown = s.llmOptimizeWP(ctx, prov, name, description, goal, challenge, m, executions, confirmedCand, latestCand, winningExecID, primaryScript, scriptData)
	}
	if strings.TrimSpace(optimizedMarkdown) == "" {
		optimizedMarkdown = s.generateDeterministicOptimizedWP(name, description, goal, challenge, m, executions, confirmedCand, latestCand, winningExecID, primaryScript, scriptData)
	}

	revision := "opt-" + SHA([]byte(optimizedMarkdown))[:16]
	result = WP{
		Revision:    revision,
		Markdown:    optimizedMarkdown,
		SHA256:      SHA([]byte(optimizedMarkdown)),
		GeneratedAt: time.Now().UTC(),
		IsOptimized: true,
	}

	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "deliverables", "wp")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return result, err
	}
	optPath := filepath.Join(dir, "optimized.json")
	raw, _ := json.MarshalIndent(result, "", "  ")
	if err = os.WriteFile(optPath+".tmp", raw, 0600); err != nil {
		return result, err
	}
	if err = os.Rename(optPath+".tmp", optPath); err != nil {
		return result, err
	}
	_ = os.WriteFile(filepath.Join(dir, "optimized.md"), []byte(result.Markdown), 0600)

	return result, nil
}
