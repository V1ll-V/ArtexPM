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

func extractUsefulFacts(facts []wpFact) []string {
	seen := make(map[string]bool)
	var out []string
	for _, f := range facts {
		if f.State == "origin" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			continue
		}
		if sub, _ := m["subtype"].(string); sub == "ctf_answer" || sub == "ctf_completion" {
			continue
		}
		summary, _ := m["summary"].(string)
		summary = strings.TrimSpace(summary)
		if summary == "" {
			if txt, _ := m["text"].(string); strings.TrimSpace(txt) != "" {
				summary = strings.TrimSpace(txt)
			}
		}
		if summary == "" || seen[summary] {
			continue
		}
		seen[summary] = true
		detail, _ := m["detail"].(string)
		detail = strings.TrimSpace(detail)
		if detail != "" && detail != summary && len([]rune(detail)) <= 240 {
			out = append(out, fmt.Sprintf("%s（%s）", summary, detail))
		} else {
			out = append(out, summary)
		}
		if len(out) >= 10 {
			break
		}
	}
	return out
}

func isNoiseCommand(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return true
	}
	noiseExact := []string{
		"ls", "ls -la", "ls -al", "ls -la /work", "dir", "pwd", "whoami", "id", "uname", "uname -a", "env",
		"cd /work && ls", "cd /work && ls -la", "cd /work; ls",
	}
	for _, e := range noiseExact {
		if c == e {
			return true
		}
	}
	noisePrefixes := []string{
		"ls ", "dir ", "pwd ", "whoami ", "uname ", "env ",
		"which ", "command -v ", "type ", "cat /etc/", "getent ",
		"cd /work && ls", "cd /work; ls", "find . -maxdepth",
	}
	for _, p := range noisePrefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func summarizeCommand(cmd string) string {
	c := strings.ToLower(strings.TrimSpace(cmd))
	switch {
	case strings.Contains(c, "unzip") || strings.Contains(c, "tar ") || strings.Contains(c, "7z "):
		return "解压题目附件并整理工作区文件"
	case strings.Contains(c, "checksec") || strings.Contains(c, "readelf") || strings.Contains(c, "objdump"):
		return "分析二进制保护机制与程序结构"
	case strings.Contains(c, "binwalk") || strings.Contains(c, "foremost") || strings.Contains(c, "dd "):
		return "扫描并分离隐藏数据或内嵌文件"
	case strings.Contains(c, "exiftool") || strings.Contains(c, "zsteg") || strings.Contains(c, "steghide") || strings.Contains(c, "stegseek"):
		return "检测文件元数据与隐写通道"
	case strings.Contains(c, "pcap") || strings.Contains(c, "tshark") || strings.Contains(c, "tcpdump") || strings.Contains(c, "scapy") || strings.Contains(c, "pyshark"):
		return "解析流量数据包并重组关键会话"
	case strings.Contains(c, "curl ") || strings.Contains(c, "sqlmap") || strings.Contains(c, "requests"):
		return "探测 Web 接口并验证漏洞利用路径"
	case strings.Contains(c, "file ") || strings.Contains(c, "xxd") || strings.Contains(c, "strings "):
		return "识别文件类型与关键特征字符串"
	case strings.Contains(c, "python") || strings.Contains(c, "sage") || strings.Contains(c, "./") || strings.Contains(c, "gdb"):
		return "编写并运行自动化求解 / 利用脚本"
	default:
		return "执行关键分析与验证步骤"
	}
}

func (s *Service) GenerateWP(ctx context.Context, task int64) (WP, error) {
	dir := filepath.Join(s.Root, "tasks", fmt.Sprint(task), "deliverables", "wp")
	optPath := filepath.Join(dir, "optimized.json")
	if b, e := os.ReadFile(optPath); e == nil {
		var opt WP
		if err := json.Unmarshal(b, &opt); err == nil && opt.SHA256 == SHA([]byte(opt.Markdown)) && strings.HasPrefix(opt.Revision, "opt-v2-") {
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

	const wpGeneratorVersion = "v0.8.0-clean-wp"
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

	acceptedCands, confirmedCand, latestCand, winningExecID := classifyWPCandidates(candidates, Hash(m))
	primaryScript, scriptData := s.findPrimaryScript(task, executions, winningExecID)
	markdown := renderStandardChineseWP(name, description, goal, challenge, m, facts, executions, acceptedCands, confirmedCand, latestCand, winningExecID, primaryScript, scriptData)

	result = WP{Revision: revision, Markdown: markdown, SHA256: SHA([]byte(markdown)), GeneratedAt: time.Now().UTC()}
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

func (s *Service) loadWPFacts(ctx context.Context, exp int64) []wpFact {
	facts := []wpFact{}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,state,payload FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' ORDER BY id LIMIT 300`, exp)
	if err != nil {
		return facts
	}
	defer rows.Close()
	for rows.Next() {
		var f wpFact
		if err := rows.Scan(&f.ID, &f.State, &f.Payload); err == nil {
			facts = append(facts, f)
		}
	}
	return facts
}

func classifyWPCandidates(candidates []db.CTFCandidate, currentHash string) ([]*db.CTFCandidate, *db.CTFCandidate, *db.CTFCandidate, string) {
	var acceptedCands []*db.CTFCandidate
	var latestCand *db.CTFCandidate
	for i := range candidates {
		c := &candidates[i]
		if c.InputHash != currentHash {
			continue
		}
		if c.State == "accepted" {
			acceptedCands = append(acceptedCands, c)
		} else if c.State == "candidate" && latestCand == nil {
			latestCand = c
		}
	}
	var confirmedCand *db.CTFCandidate
	if len(acceptedCands) > 0 {
		confirmedCand = acceptedCands[0]
	}
	winningExecID := ""
	if confirmedCand != nil {
		winningExecID = confirmedCand.ExecutionID
	} else if latestCand != nil {
		winningExecID = latestCand.ExecutionID
	}
	return acceptedCands, confirmedCand, latestCand, winningExecID
}

func (s *Service) findPrimaryScript(task int64, executions []db.CTFExecution, winningExecID string) (*Script, []byte) {
	execMap := make(map[string]*db.CTFExecution, len(executions))
	for i := range executions {
		execMap[executions[i].ID] = &executions[i]
	}
	searchExecs := make([]*db.CTFExecution, 0, len(executions))
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
		if err := json.Unmarshal(e.Files, &files); err == nil && len(files) > 0 {
			for _, f := range files {
				ext := strings.ToLower(filepath.Ext(f.Name))
				if ext == ".py" || ext == ".sh" || ext == ".c" {
					if d, er := s.EvidenceFile(task, f.Path, f.SHA256); er == nil && len(d) > 0 {
						fCopy := f
						return &fCopy, d
					}
				}
			}
		}
	}
	return nil, nil
}

func pickEssentialSteps(executions []db.CTFExecution, winningExecID string, maxSteps int) []effectiveStep {
	if maxSteps <= 0 {
		maxSteps = 4
	}
	var filtered []db.CTFExecution
	seen := make(map[string]bool)
	for _, e := range executions {
		cmd := strings.TrimSpace(e.Command)
		if cmd == "" {
			continue
		}
		if e.ExitCode != 0 && e.ID != winningExecID {
			continue
		}
		if isNoiseCommand(cmd) && e.ID != winningExecID {
			continue
		}
		if seen[cmd] && e.ID != winningExecID {
			continue
		}
		seen[cmd] = true
		filtered = append(filtered, e)
	}
	if len(filtered) == 0 {
		return nil
	}

	var picked []db.CTFExecution
	pickedIDs := make(map[string]bool)
	// First pick up to 1 reconnaissance/analysis command before winning step
	for _, e := range filtered {
		if e.ID == winningExecID {
			continue
		}
		low := strings.ToLower(e.Command)
		if strings.Contains(low, "checksec") || strings.Contains(low, "unzip") ||
			strings.Contains(low, "tar ") || strings.Contains(low, "tshark") ||
			strings.Contains(low, "pcap") || strings.Contains(low, "binwalk") ||
			strings.Contains(low, "exiftool") || strings.Contains(low, "strings ") ||
			strings.Contains(low, "file ") || strings.Contains(low, "curl ") {
			picked = append(picked, e)
			pickedIDs[e.ID] = true
			break
		}
	}
	// Fill trailing non-winning steps up to maxSteps-1 so recent analytical scripts appear
	var middle []db.CTFExecution
	for _, e := range filtered {
		if e.ID == winningExecID || pickedIDs[e.ID] {
			continue
		}
		middle = append(middle, e)
	}
	room := maxSteps - len(picked)
	if winningExecID != "" {
		room--
	}
	if room > 0 && len(middle) > 0 {
		start := len(middle) - room
		if start < 0 {
			start = 0
		}
		for _, e := range middle[start:] {
			picked = append(picked, e)
			pickedIDs[e.ID] = true
		}
	}
	// Append winning execution last
	if winningExecID != "" {
		for _, e := range filtered {
			if e.ID == winningExecID {
				picked = append(picked, e)
				break
			}
		}
	}

	steps := make([]effectiveStep, 0, len(picked))
	for _, e := range picked {
		summary := summarizeCommand(e.Command)
		if e.ID == winningExecID {
			summary = "运行核心求解脚本提取 Flag"
		}
		steps = append(steps, effectiveStep{
			ExecutionID: e.ID,
			Command:     e.Command,
			Summary:     summary,
			Stdout:      string(e.StdoutExcerpt),
			IsWinner:    e.ID == winningExecID,
		})
	}
	return steps
}

func renderStandardChineseWP(
	name, description, goal, challenge string,
	manifest artifacts.Manifest,
	facts []wpFact,
	executions []db.CTFExecution,
	acceptedCands []*db.CTFCandidate,
	confirmedCand *db.CTFCandidate,
	latestCand *db.CTFCandidate,
	winningExecID string,
	primaryScript *Script,
	scriptData []byte,
) string {
	var b strings.Builder
	title := strings.TrimSpace(name)
	if title == "" {
		title = strings.TrimSpace(description)
	}
	if title == "" {
		title = "CTF 赛题"
	}
	title = strings.ReplaceAll(title, "\n", " ")

	challengeLabel := strings.ToUpper(strings.TrimSpace(challenge))
	if challengeLabel == "" || challengeLabel == "AUTO" {
		challengeLabel = "CTF 综合"
	}

	statusSummary := "分析探索中（暂未捕获候选 Flag）"
	if len(acceptedCands) > 1 {
		statusSummary = fmt.Sprintf("已验证确认 %d 个 Flag", len(acceptedCands))
	} else if confirmedCand != nil {
		statusSummary = fmt.Sprintf("已验证通过（`%s`）", confirmedCand.Value)
	} else if latestCand != nil {
		statusSummary = fmt.Sprintf("待人工确认（候选 `%s`）", latestCand.Value)
	}

	fmt.Fprintf(&b, "# Write-up — %s\n\n", title)

	// 一、题目信息
	b.WriteString("## 一、题目信息\n\n")
	b.WriteString("| 项目 | 内容 |\n| :--- | :--- |\n")
	fmt.Fprintf(&b, "| **题目名称** | %s |\n", title)
	fmt.Fprintf(&b, "| **赛题类别** | %s |\n", challengeLabel)
	fmt.Fprintf(&b, "| **当前状态** | %s |\n", statusSummary)
	if len(manifest.Files) > 0 {
		var fileNames []string
		for _, f := range manifest.Files {
			fileNames = append(fileNames, fmt.Sprintf("`%s` (%d B)", f.Name, f.Size))
		}
		fmt.Fprintf(&b, "| **题目附件** | %s |\n", strings.Join(fileNames, "、"))
	}
	b.WriteString("\n")
	if strings.TrimSpace(description) != "" {
		fmt.Fprintf(&b, "**题目描述**：%s\n\n", strings.TrimSpace(description))
	}
	if strings.TrimSpace(goal) != "" && strings.TrimSpace(goal) != strings.TrimSpace(description) {
		fmt.Fprintf(&b, "**解题目标**：%s\n\n", strings.TrimSpace(goal))
	}

	// 二、解题思路
	b.WriteString("## 二、解题思路\n\n")
	b.WriteString(generateOverviewText(challenge, name, description, len(manifest.Files), primaryScript, statusSummary))
	b.WriteString("\n\n")
	if usefulFacts := extractUsefulFacts(facts); len(usefulFacts) > 0 {
		b.WriteString("**关键分析发现**：\n")
		for _, uf := range usefulFacts {
			fmt.Fprintf(&b, "- %s\n", uf)
		}
		b.WriteString("\n")
	}

	// 三、关键步骤
	b.WriteString("## 三、关键步骤\n\n")
	steps := pickEssentialSteps(executions, winningExecID, 4)
	if len(steps) == 0 {
		b.WriteString("暂未记录可复现的关键命令步骤。\n\n")
	} else {
		for idx, st := range steps {
			tag := ""
			if st.IsWinner {
				tag = "（命中 Flag）"
			}
			fmt.Fprintf(&b, "### %d. %s%s\n\n", idx+1, st.Summary, tag)
			b.WriteString(fence(strings.TrimSpace(st.Command), "bash"))
			if st.IsWinner && strings.TrimSpace(st.Stdout) != "" {
				b.WriteString("**关键输出**：\n")
				b.WriteString(fence(excerpt([]byte(strings.TrimSpace(st.Stdout)), 600), "text"))
			}
		}
	}

	// 四、核心 PoC / 利用脚本
	b.WriteString("## 四、核心 PoC / 利用脚本\n\n")
	if primaryScript != nil {
		lang := strings.TrimPrefix(filepath.Ext(primaryScript.Name), ".")
		if lang == "" {
			lang = "python"
		}
		fmt.Fprintf(&b, "核心求解脚本 `%s`：\n\n", primaryScript.Name)
		b.WriteString(fence(strings.TrimSpace(string(scriptData)), lang))
	} else {
		var winCmd string
		for _, e := range executions {
			if e.ID == winningExecID {
				winCmd = strings.TrimSpace(e.Command)
				break
			}
		}
		if winCmd != "" {
			b.WriteString("核心复现命令：\n\n")
			b.WriteString(fence(winCmd, "bash"))
		} else {
			b.WriteString("暂未持久化独立求解脚本，详见上述关键步骤。\n\n")
		}
	}

	// 五、获取 Flag
	b.WriteString("## 五、获取 Flag\n\n")
	if len(acceptedCands) > 1 {
		fmt.Fprintf(&b, "本题共确认 **%d 个有效 Flag**：\n\n", len(acceptedCands))
		b.WriteString("| 序号 | 场景 / 备注 | Flag |\n| :---: | :--- | :--- |\n")
		for idx, ac := range acceptedCands {
			note := strings.TrimSpace(ac.Notes)
			if note == "" {
				note = fmt.Sprintf("Flag %d", idx+1)
			}
			fmt.Fprintf(&b, "| %d | %s | `%s` |\n", idx+1, strings.ReplaceAll(note, "|", "-"), ac.Value)
		}
		b.WriteString("\n")
	} else if confirmedCand != nil {
		fmt.Fprintf(&b, "- **最终 Flag**：`%s`\n", confirmedCand.Value)
		if strings.TrimSpace(confirmedCand.Notes) != "" {
			fmt.Fprintf(&b, "- **验证说明**：%s\n", strings.TrimSpace(confirmedCand.Notes))
		}
		b.WriteString("\n")
	} else if latestCand != nil {
		fmt.Fprintf(&b, "- **候选 Flag**：`%s`（待平台核验）\n\n", latestCand.Value)
	} else {
		b.WriteString("尚未获取最终 Flag。\n\n")
	}

	return b.String()
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
	facts []wpFact,
	executions []db.CTFExecution,
	acceptedCands []*db.CTFCandidate,
	confirmedCand *db.CTFCandidate,
	latestCand *db.CTFCandidate,
	winningExecID string,
	primaryScript *Script,
	scriptData []byte,
) string {
	return renderStandardChineseWP(
		name, description, goal, challenge,
		manifest, facts, executions,
		acceptedCands, confirmedCand, latestCand,
		winningExecID, primaryScript, scriptData,
	)
}

func (s *Service) llmOptimizeWP(
	ctx context.Context,
	prov llm.Provider,
	name, description, goal, challenge string,
	manifest artifacts.Manifest,
	facts []wpFact,
	executions []db.CTFExecution,
	acceptedCands []*db.CTFCandidate,
	confirmedCand *db.CTFCandidate,
	latestCand *db.CTFCandidate,
	winningExecID string,
	primaryScript *Script,
	scriptData []byte,
) string {
	if prov == nil {
		return ""
	}

	systemPrompt := `你是一名国内顶级 CTF 战队队长与安全研究员。请根据提供的赛题信息、关键分析结论（Facts）、核心命令与求解脚本，整理出一份符合国内标准竞赛风格、重点突出、简洁易读的中文 Write-up。

【强制结构】（严格使用以下 5 个二级标题，不要增删主结构）：
# Write-up — <题目名称>
## 一、题目信息
（简要列出题目名称、类别、附件/环境信息与核心考察点）
## 二、解题思路
（先用一段话概括整体解法与突破口，再用 2~4 条简洁的中文要点讲清楚分析推理逻辑）
## 三、关键步骤
（只保留 2~4 个真正推进解题的最小关键动作：每步用一句中文小标题 + 核心命令或关键发现说明）
## 四、核心 PoC / 利用脚本
（完整贴出最终用于获取 Flag 的 PoC 脚本源码或一键复现命令，不要截断或省略核心逻辑）
## 五、获取 Flag
（若只有一个 Flag 直接给出；若存在多个已确认 Flag，使用简洁的 Markdown 表格列出全部场景备注与 Flag）

【严格禁忌】：
1. 绝对禁止输出 <details>、<summary> 等 HTML 标签，也禁止输出 > [!TIP]、> [!NOTE]、> [!IMPORTANT] 等 GitHub Alert 语法。
2. 绝对禁止出现任何 UUID / execution_id / intent_id、SHA-256 哈希值、RFC3339 时间戳或退出码审计流水账。
3. 彻底过滤所有 ls/pwd/which 等目录探测和失败试错记录。
4. 严禁捏造未实际出现的命令、文件或 Flag，必须原样保留真实捕获的 Flag 与核心源码。
5. 直接输出纯 Markdown 文本，不要最外层代码块包裹。`

	flagVal := "待验证"
	if len(acceptedCands) > 1 {
		flagVal = fmt.Sprintf("累计 %d 个已确认 Flag", len(acceptedCands))
	} else if confirmedCand != nil {
		flagVal = confirmedCand.Value
	} else if latestCand != nil {
		flagVal = latestCand.Value
	}

	var attachmentList []string
	for _, f := range manifest.Files {
		attachmentList = append(attachmentList, fmt.Sprintf("%s (%d B)", f.Name, f.Size))
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
	if len(usefulCmds) > 8 {
		usefulCmds = usefulCmds[len(usefulCmds)-8:]
	}

	factsSection := "无额外结构化结论"
	if usefulFacts := extractUsefulFacts(facts); len(usefulFacts) > 0 {
		factsSection = "- " + strings.Join(usefulFacts, "\n- ")
	}

	multiFlagSection := ""
	if len(acceptedCands) > 1 {
		multiFlagSection = fmt.Sprintf("【已确认有效 Flag 清单（共 %d 个）】：\n", len(acceptedCands))
		for i, ac := range acceptedCands {
			note := strings.TrimSpace(ac.Notes)
			if note == "" {
				note = fmt.Sprintf("Flag %d", i+1)
			}
			multiFlagSection += fmt.Sprintf("- [%d] 场景/备注：%s | Flag：%s\n", i+1, note, ac.Value)
		}
		multiFlagSection += "\n请在「五、获取 Flag」章节中用表格完整列出这些 Flag 与场景备注。\n\n"
	}

	userContent := fmt.Sprintf(`【赛题名称】：%s
【赛题类别】：%s
【题目附件】：%s
【题目描述】：%s
【交付目标】：%s
【最终 Flag】：%s
%s【关键分析结论（Facts）】：
%s
【命中 Flag 的关键命令】：
%s
【关键回显输出】：
%s
【核心求解 PoC / Exploit 脚本】：
%s
【精选关键命令历史】：
%s`, name, challenge, strings.Join(attachmentList, "、"), description, goal, flagVal, multiFlagSection, factsSection, winningCmd, winningOutput, pocCode, strings.Join(usefulCmds, "\n"))

	llmCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	msg, _, _, err := prov.Complete(llmCtx, llm.CompletionRequest{
		System:    []string{systemPrompt},
		Messages:  []llm.Message{llm.UserText(userContent)},
		MaxTokens: 6000,
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

	if strings.Contains(text, "#") && len(text) > 200 {
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
	facts := s.loadWPFacts(ctx, exp)

	acceptedCands, confirmedCand, latestCand, winningExecID := classifyWPCandidates(candidates, Hash(m))
	primaryScript, scriptData := s.findPrimaryScript(task, executions, winningExecID)

	optimizedMarkdown := ""
	if prov != nil {
		optimizedMarkdown = s.llmOptimizeWP(ctx, prov, name, description, goal, challenge, m, facts, executions, acceptedCands, confirmedCand, latestCand, winningExecID, primaryScript, scriptData)
	}
	if strings.TrimSpace(optimizedMarkdown) == "" {
		optimizedMarkdown = s.generateDeterministicOptimizedWP(name, description, goal, challenge, m, facts, executions, acceptedCands, confirmedCand, latestCand, winningExecID, primaryScript, scriptData)
	}

	revision := "opt-v2-" + SHA([]byte(optimizedMarkdown))[:16]
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
