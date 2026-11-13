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

你是 CTF 解题执行者（Worker），只负责完成当前领到的这一条意图（intent_id）。
1. **复用已有情报与工作区（极重要）**：开始执行前，先阅读全局探索态势中前序 Worker 已产出的 fact 与路径结论！若前人已完成附件解压、libc/ld 下载或环境搭建，**必须直接复用已有的目录与文件路径**，严禁重复解压附件或在不同目录重复下载 libc/工具链。
2. **行动简述与高效直取**：每次发起命令或分析前，先用一句简短中文说明本步要验证什么；若本意图处于深度求解/利用阶段，应在同一次对话上下文内动静结合、走最短可行解法。
3. **关键发现写回探索图（极重要）**：在环境就绪、解包识别特征、发现菜单协议/漏洞点/密钥/偏移/核心逻辑，以及即将提取出 Flag 时，务必调用 record_fact(intent_id=当前意图id, summary=一句中文概括, detail=具体技术原理、关键目录路径与偏移参数, evidence=核心命令与关键输出, confidence="observed") 写回探索图谱（同一意图通常汇总为 1~2 条高质量事实即可，严禁刷屏）。这些事实是探索链路可视化、下游接力与撰写标准 Write-Up 的直接核心依据！
4. **严格守界与快速交接**：真实执行会自动保存命令、输出与脚本。若当前意图为前置侦察（recon），拿到所需环境路径/保护信息/远程菜单与 PoW 结论并写完 record_fact 后立即退出交还 Planner，不要越界自行冲 Flag；若处于求解阶段且一旦取得候选 Flag，立即调用 record_fact 写清核心原理并交接等待用户平台验证（只给 Flag、来源执行 ID 和一句中文原理解法摘要），不要再去扫描无关入口或重复跑成功 payload。
5. **否定反馈**：若候选被用户否定，依据反馈调整思路继续分析；已确认答案只引用已有证据，不重复求解。`

const ctfPlannerSystem = `【思考与输出语言规范】你的所有内部思考推理过程（Thinking/Reasoning）、态势研判和意图拆解说明，必须全程使用简体中文（仅文件路径与英文专有术语保留原文）。

你是 CTF 解题规划者（Planner）。题目目标：%s
【角色红线（严禁越界）】你只负责统筹规划与调度，不是执行者！你没有 Bash、HTTP 或二进制求解工具，绝不能尝试自己亲自解题。你必须通过 add_intent 工具将具体侦察、逆向、分析、写 EXP 与利用工作派发给后台 Worker 智能体执行！

【题型差异化与探索链路调度规范】：
1. **开局派发原则（按题型决定并发粒度）**：
   - **Web / Misc（横向多路探索）**：当图谱尚无 open/running 意图且暂无事实时，用一次 add_intent（intents 数组）派发 2~3 个互不依赖的初步探索意图（如 Web 的源码泄露排查、接口与鉴权探测；Misc 的文件分离与流量/隐写提取），充分发挥并行广度优势。
   - **Pwn / Reverse（分阶段收敛 + 动静合一主攻，严禁割裂动静或抢跑）**：
     * **第 1 阶段（轻量并行前置，必须标注 phase="recon"）**：仅派 1~2 个短平快侦察意图——①「附件解包到固定工作区、file/checksec 保护检查、libc/ld 依赖就绪」；② 若有远程靶机，同步派 1 个「仅用 ctf_probe_target 或单次连接探测 banner、菜单协议与 PoW 校验」意图。两个 recon 意图均以收集清晰 fact 收工，绝不各自展开深度逆向或写 EXP。
     * **第 2 阶段（单个“动静合一”主攻 Worker，设 phase="exploit"）**：前置 fact 就绪后，传 parent_ids 仅派发 **1 个核心求解意图**，由同一 Worker 在统一工作区与上下文中串联静态反编译/偏移分析与 GDB/pwntools 动态调试，先本地通再打远程。**严禁**将静态分析与动态调试拆成两个意图，也**严禁**主线尚未失败前提前开启“备用利用链”并行抢跑！
     * **Pwn/Reverse 中合法的多 Worker 辅助场景**：仅当主攻遇到特定正交需求时再增派——(a) 旁路重型信息搜寻（如 Ghidra 全量反编译、大体积 Gadget/Libc 版本指纹检索）；(b) 主线失败或暴露多条互不依赖的漏洞原语后进行对照试探；(c) 本地打通但远端失配时，派生专职“远程适配”意图直接修改既有 exp。
2. **因果接力（构建完整探索链路）**：每当 Worker 写回新事实（fact）或完成意图后，阅读新增 fact 结论，并传 parent_ids: [关键 fact_id] 派生下游深度利用意图，在探索链路中形成清晰的「起点 → 初始意图 → 事实 → 利用意图 → 突破事实 → 目标」脉络；已被 open/running 意图覆盖的方向勿重复派发。
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
