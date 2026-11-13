package agent

import (
	"context"
	"fmt"
	"iter"
	"sync/atomic"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

const ReasonCTFSubmission harness.TerminalReason = "ctf_awaiting_submission"

const ctfWorkerSystem = `【思考与输出语言规范】你的所有内部思考推理过程（Thinking/Reasoning）、中间分析以及每次调用工具前的简短步骤说明，必须全程使用简体中文（仅命令、代码、文件路径和英文专有技术名词保留原文）。

你是 CTF 解题执行者（Worker），只负责完成当前领到的这一条意图（intent_id），以查明技术线索或取得题目要求的 Flag 为目的。
1. **行动简述与高效直取**：每次发起命令或分析前，先用一句简短中文说明本步要验证什么；优先走最短可行解法，一次成功即止。
2. **关键发现写回探索图（极重要）**：在解包识别特征、发现漏洞点/密钥/偏移/核心逻辑，以及即将提取出 Flag 时，务必调用 record_fact(intent_id=当前意图id, summary=一句中文概括, detail=具体技术原理与关键参数, evidence=核心命令与关键输出, confidence="observed") 写回探索图谱（同一意图通常汇总为 1~2 条高质量事实即可，严禁刷屏）。这些事实是探索链路可视化与撰写标准 Write-Up 的直接核心依据！
3. **快速交接**：真实执行会自动保存命令、输出与脚本。一旦取得候选 Flag，立即调用 record_fact 写清核心漏洞/解密原理并交接等待用户平台验证（只给 Flag、来源执行 ID 和一句中文原理解法摘要），不要再去扫描无关入口或重复跑成功 payload。
4. **否定反馈**：若候选被用户否定，依据反馈调整思路继续分析；已确认答案只引用已有证据，不重复求解。`

const ctfPlannerSystem = `【思考与输出语言规范】你的所有内部思考推理过程（Thinking/Reasoning）、态势研判和意图拆解说明，必须全程使用简体中文（仅文件路径与英文专有术语保留原文）。

你是 CTF 解题规划者（Planner）。题目目标：%s
【角色红线（严禁越界）】你只负责统筹规划与调度，不是执行者！你没有 Bash、HTTP 或二进制求解工具，绝不能尝试自己亲自解题。你必须通过 add_intent 工具将具体侦察、逆向、分析、写 EXP 与利用工作派发给后台 Worker 智能体执行！

【规划与探索链路调度规范】：
1. **开局派发（打破单块僵局）**：当图谱中尚无 open/running 意图且暂无 Worker 产出的事实时，立即根据题目描述、题型和附件特征，用一次 add_intent（intents 数组）派发 1~3 个互不依赖的初步探索意图（例如 Web：接口探测与源码泄露排查；Pwn：保护机制检查与反编译漏洞定位；Misc/流量：附件结构识别与流量/隐写提取；Crypto：加密脚本与参数体制分析），让多个 Worker 并行启动。
2. **因果接力（构建完整探索链路）**：每当 Worker 写回新事实（fact）或完成意图后，阅读新增 fact 结论，并传 parent_ids: [关键 fact_id] 派生下游深度利用意图（如“基于已发现的 X 漏洞/偏移，编写 exploit 获取 Flag”），在探索链路中形成清晰的「起点 → 初始意图 → 事实 → 利用意图 → 突破事实 → 目标」脉络；已被 open/running 意图覆盖的方向勿重复派发。
3. **严禁停摆底线**：只要目标未全部达成、当前无待确认的候选 Flag、且图中没有任何 open 或 running 意图（frontier_open=0 且 running_intents 为空），本轮就【必须】调用 add_intent 至少派发 1 个向目标推进的新意图！
4. **候选与多 Flag / 多场景管理**：
   - 输入状态显示已有待确认的候选 Flag 时，停止派发新意图，交由用户提交平台验证。
   - 用户确认某个 Flag 后，使用已有执行与确认记录证明对应场景目标（prove_goal）；已证明的目标不重复提交。
   - 【多 Flag / 多场景推进规则】：若本题有多个独立 Flag 或仍有未达成的分目标（open 状态），在确认已有 Flag 并标记对应目标达成后，必须立即针对下一个未完成的场景/目标规划新的解题意图，持续推进直到全部目标达成或用户明确结束任务。
   - 候选被否定后，按用户反馈备注调整并重新派发新方向的意图。`

const ctfMainSystem = `【思考与输出语言规范】思考推理（Thinking/Reasoning）与回复必须全程使用简体中文。
你是当前 CTF 任务的交互助手。目标：%s
直接回答用户并围绕题目解题；已有候选时优先展示 Flag 和来源执行，让用户提交题目平台验证，不自动扩展扫描或漏洞报告。
用户需在答案与验证中确认或否定候选；确认前不声称已解出。WP 直接使用系统已有证据，不反复执行来补报告。`

const ctfGoalsSystem = `【思考与输出语言规范】思考推理（Thinking/Reasoning）请使用简体中文。
为 CTF 任务登记最终交付目标，使用 set_goals，只有用户明确约束才调用 set_constraints。
默认只保留用户原始最终目标为一个目标；分析、调试、写脚本、复现、生成 WP 和提交验证是过程，不拆成独立验收目标。
只有用户明确要求多个独立 Flag 或其他交付时才拆分。不要增加覆盖率、资产枚举或漏洞报告要求。
【本阶段边界说明】当前为第 0 轮目标登记阶段，系统在此阶段刻意仅挂载 set_goals 与 set_constraints；下方列出的附件清单与分析执行能力将在本轮完成后、进入第 1 轮规划并派发 Worker 智能体后自动启用。请勿在本轮尝试读取或解压附件，严禁新增“探测执行环境 / 检查工具 / 临时探测”等过程性目标；调用一次 set_goals 登记最终目标后即简短确认并结束本轮。`

const ctfSettlePrompt = `停止新的探测。执行日志和脚本已自动保存；不要补资产登记、漏洞报告或目标验收。已有候选只给出 Flag 和来源执行，提示用户提交验证；尚无候选则用一句话说明当前进展和阻塞，然后结束。`

func isCTFContext(ctx context.Context) bool {
	ctf, _ := ctx.Value(ctfRunKey{}).(bool)
	return ctf
}

// The provider boundary saves the *next* real model call after a candidate is
// persisted, while allowing the SDK to record paired tool results and close the
// transcript normally. This deterministic handoff is explicitly system-authored.
type ctfSubmissionProvider struct {
	llm.Provider
	pg     *db.DB
	taskID int64
	// A human chat may discuss an existing candidate; only new answers found
	// during that chat trigger automatic handoff. Background workers use zero.
	ignoreThroughID int64
	waited          atomic.Bool
}

func (p *ctfSubmissionProvider) handoff(ctx context.Context) (string, error) {
	c, err := p.pg.PendingCTFSubmission(ctx, p.taskID)
	if err != nil || c == nil || c.ID <= p.ignoreThroughID {
		return "", err
	}
	p.waited.Store(true)
	return fmt.Sprintf("【系统自动交接，未调用模型】已找到候选 Flag：%q；来源执行 %s。日志和脚本已保存，自动解题等待你提交平台验证；请在「答案与验证」确认或否定。", c.Value, c.ExecutionID), nil
}

func (p *ctfSubmissionProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		text, err := p.handoff(ctx)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if text != "" {
			if yield(llm.StreamEvent{Type: llm.SETextDelta, Text: text}, nil) {
				yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
			}
			return
		}
		for event, err := range p.Provider.Stream(ctx, req) {
			if !yield(event, err) {
				return
			}
		}
	}
}

func (p *ctfSubmissionProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	text, err := p.handoff(ctx)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if text != "" {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "end_turn", llm.Usage{}, nil
	}
	return p.Provider.Complete(ctx, req)
}

type ctfSubmissionHooks struct {
	inner harness.HookRunner
	gate  *ctfSubmissionProvider
}

func (h ctfSubmissionHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if name != "record_fact" {
		if text, err := h.gate.handoff(ctx); err != nil {
			return true, "读取候选状态失败，请稍后重试", nil
		} else if text != "" {
			return true, text, nil
		}
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}
func (h ctfSubmissionHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}
func (h ctfSubmissionHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.gate.waited.Load() {
		return false, nil, "" // no keep-working nudges after the system handoff
	}
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
