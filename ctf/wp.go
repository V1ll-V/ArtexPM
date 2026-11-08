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
)

type WP struct {
	Revision    string    `json:"revision"`
	Markdown    string    `json:"markdown"`
	SHA256      string    `json:"sha256"`
	GeneratedAt time.Time `json:"generated_at"`
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
func (s *Service) GenerateWP(ctx context.Context, task int64) (WP, error) {
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
	source := struct {
		Task                                       int64
		Name, Description, Goal, Status, Challenge string
		Manifest                                   artifacts.Manifest
		Executions                                 []db.CTFExecution
		Candidates                                 []db.CTFCandidate
		Facts                                      []wpFact
	}{task, name, description, goal, status, challenge, m, executions, candidates, facts}
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
	var b strings.Builder
	if name == "" {
		name = description
	}
	fmt.Fprintf(&b, "# 解题报告（WP）— %s\n\n", strings.ReplaceAll(name, "\n", " "))
	currentHash := Hash(m)
	accepted := []db.CTFCandidate{}
	for _, c := range candidates {
		if c.State == "accepted" && c.InputHash == currentHash {
			accepted = append(accepted, c)
		}
	}
	state := "分析中 / 尚无已确认答案"
	if len(accepted) > 0 {
		state = "当前输入的答案已由用户确认"
	}
	if status == "failed" || status == "timeout" {
		state += "；任务已停止，保留阶段结果"
	}
	fmt.Fprintf(&b, "- 任务：%d · 题型：%s · 任务状态：%s\n- 解题状态：%s\n- 输入 SHA-256：`%s`\n- WP 版本：`%s`\n\n## 题目与目标\n\n%s\n\n%s\n\n", task, challenge, status, state, currentHash, revision, description, goal)
	b.WriteString("## 附件与静态信息\n\n")
	if len(m.Files) == 0 {
		b.WriteString("本任务没有上传附件。\n\n")
	}
	for _, a := range m.Files {
		fmt.Fprintf(&b, "### %s\n\n- 角色：%s · 大小：%d 字节\n- SHA-256：`%s`\n- 执行路径：`%s`\n\n", strings.ReplaceAll(a.Name, "\n", " "), a.Role, a.Size, a.SHA256, s.LogicalPath(a))
		v, _ := json.MarshalIndent(a.Analysis, "", "  ")
		b.WriteString(fence(string(v), "json"))
	}
	b.WriteString("## 分析结论与解题思路\n\n以下为任务事实记录；模型写回的结论仍需结合后面的执行证据核对。\n\n")
	if len(facts) == 0 {
		b.WriteString("尚无写回的分析结论。\n\n")
	}
	for _, f := range facts {
		fmt.Fprintf(&b, "### 事实 #%d（%s）\n\n", f.ID, f.State)
		var fields map[string]any
		_ = json.Unmarshal(f.Payload, &fields)
		for _, k := range []string{"summary", "detail", "evidence", "reason", "verification"} {
			if v, ok := fields[k]; ok {
				fmt.Fprintf(&b, "%v\n\n", v)
			}
		}
	}
	b.WriteString("## 实际执行与复现步骤\n\n命令、退出码和输出取自独立执行器；输出中的 Flag 格式匹配只产生候选。最多展示最近 100 次执行，完整执行日志可在任务中下载。\n\n")
	if len(executions) == 0 {
		b.WriteString("尚无执行记录，不能据此声称已完成求解。\n\n")
	}
	scripts := map[string]bool{}
	for i := len(executions) - 1; i >= 0; i-- {
		e := executions[i]
		fmt.Fprintf(&b, "### 执行 %s\n\n- 意图：%d · 时间：%s · 退出码：%d\n- 输入：`%s`", e.ID, e.IntentID, e.StartedAt.UTC().Format(time.RFC3339), e.ExitCode, e.InputHash)
		if e.InputHash != currentHash {
			b.WriteString("（旧输入版本）")
		}
		b.WriteString("\n\n")
		b.WriteString(fence(e.Command, "bash"))
		if e.Error != "" {
			fmt.Fprintf(&b, "执行/同步异常：%s\n\n", e.Error)
		}
		if e.Truncated {
			b.WriteString("输出超过限制，已截断；该记录不能声称保留了完整输出。\n\n")
		}
		for _, log := range []struct{ name, path, hash string }{{"stdout", e.StdoutPath, e.StdoutSHA}, {"stderr", e.StderrPath, e.StderrSHA}} {
			data, er := s.EvidenceFile(task, log.path, log.hash)
			if er != nil {
				return result, fmt.Errorf("执行 %s %s：%w", e.ID, log.name, er)
			}
			fmt.Fprintf(&b, "%s SHA-256：`%s`\n\n", log.name, log.hash)
			if len(data) > 0 {
				b.WriteString(fence(excerpt(data, 12000), "text"))
			}
		}
		var files []Script
		if err = json.Unmarshal(e.Files, &files); err != nil {
			return result, err
		}
		for _, f := range files {
			if scripts[f.SHA256] {
				continue
			}
			scripts[f.SHA256] = true
			data, er := s.EvidenceFile(task, f.Path, f.SHA256)
			if er != nil {
				return result, er
			}
			fmt.Fprintf(&b, "求解文件 `%s` · SHA-256 `%s`\n\n", f.Name, f.SHA256)
			if len(data) <= 24000 {
				b.WriteString(fence(string(data), strings.TrimPrefix(filepath.Ext(f.Name), ".")))
			} else {
				b.WriteString("文件较长，已留存在本次执行的产物快照中。\n\n")
			}
		}
	}
	b.WriteString("## 答案与验证\n\n")
	if len(candidates) == 0 {
		b.WriteString("尚未从实际输出登记候选答案。\n\n")
	}
	for _, c := range candidates {
		fmt.Fprintf(&b, "- 候选 #%d：%s；来源执行 `%s`；状态 **%s**。\n", c.ID, strings.ReplaceAll(c.Value, "\n", " "), c.ExecutionID, c.State)
		if c.Notes != "" {
			fmt.Fprintf(&b, "  用户备注：%s\n", c.Notes)
		}
	}
	b.WriteString("\n")
	if len(accepted) == 0 {
		b.WriteString("当前输入版本尚无用户确认的答案。本 WP 为阶段报告，任务不能仅凭模型判断或正则匹配宣告成功。请复现脚本并按题目要求验证候选答案。\n\n")
	}
	b.WriteString("## 环境与限制\n\nPwn/RE 命令在任务独立容器中执行，应用配置与密钥不挂载进去。工具页可查询实际安装与导入状态；缺失依赖、调试失败、超时与非零退出码均保留在执行记录中。自动生成的 WP 只汇总已有资料，不补造未执行步骤。\n")
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
