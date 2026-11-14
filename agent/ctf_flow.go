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
1. **复用已有情报与工作区（极重要）**：开始执行前，先阅读全局探索态势中前序 Worker 已产出的 fact 与路径结论！Pwn/Reverse 任务跨意图自动共享同一 "/work" 工作区，若前人已完成附件解压、libc/ld 下载或环境搭建，**必须直接复用已有的目录与文件路径**，严禁重复解压附件或在不同目录重复下载 libc/工具链。
2. **工具选型与安全测试规范**：
   - 二进制分析遇 stripped ELF 或复杂协议/堆菜单，**优先使用 "ctf_pwn_triage"（一步完成检查与本地 glibc 配对）并立即用 "ctf_decompile"（Ghidra 反编译，首跑约 15s 缓存后续 ~5s）**，避免用 "objdump"/Bash 盲读海量裸汇编。
   - **本地自测严禁伪造花括号 Flag**：在 "/tmp/flag" 或本地脚本中验证拿 shell/读文件能力时，严禁写入 "flag{...}" / "FLAG{...}" / "ctf{...}" 占位文本（避免误触发系统交接）；统一使用无花括号哨兵如 "__LOCAL_PWN_OK__"。泄露地址请打印十六进制整数（如 "hex(addr)"），勿将含 "\x00" 裸二进制直接 "print" 刷屏。
   - **认清本题验收模式（ctf_verify_mode）**：
     * "flag"（仅提交 Flag）：拿到真实 Flag 后通过 stdout 输出或调用 ctf_submit_flag 登记候选。
     * "exploit_proof"（漏洞利用证明，无需 Flag）：本题没有 flag{...} 字符串，**严禁搜寻或编造不存在的 Flag**！必须在目标环境真正触发并验证题干要求的持久化状态/效果（如篡改成功、越权写文件/提权并经二次读取或独立请求证实），写完 record_fact 后调用 "ctf_submit_exploit_proof(execution_id, proof_summary, target_effect)" 提交证明交接用户去平台点「验证漏洞利用」。
     * "flag_and_exploit"（复合验收：先 Flag 后漏洞利用证明）：若状态中 "accepted_flag_count=0"，先专注取得真实 Flag 交接用户验证；若 "accepted_flag_count>=1" 且 "accepted_proof_count=0"，说明 Flag 已确认，立刻基于已获情报完成漏洞利用，实证生效后调用 "ctf_submit_exploit_proof" 提交最终证明。
   - 每次发起命令或分析前，用一句简短中文说明本步要验证什么；若本意图处于深度求解/利用阶段，应在同一次对话上下文内动静结合、走最短可行解法。
3. **关键发现写回探索图（极重要）**：在环境就绪、解包识别特征、发现菜单协议/漏洞点/密钥/偏移/核心逻辑，以及完成利用验证/提取出 Flag 时，务必调用 record_fact(intent_id=当前意图id, summary=一句中文概括, detail=具体技术原理、关键目录路径与偏移参数, evidence=核心命令与关键输出, confidence="observed") 写回探索图谱（同一意图通常汇总为 1~2 条高质量事实即可，严禁刷屏）。这些事实是探索链路可视化、下游接力与撰写标准 Write-Up 的直接核心依据！
4. **严格守界与快速交接**：真实执行会自动保存命令、输出与脚本。若当前意图为前置侦察（recon），拿到所需环境路径/保护信息/远程菜单与 PoW 结论并写完 record_fact 后立即退出交还 Planner；若处于求解阶段且已提交候选 Flag 或漏洞利用证明，立即调用 record_fact 写清核心原理并交接等待用户平台验证，不要再去扫描无关入口或重复跑成功 payload。
5. **否定反馈**：若候选被用户否定，依据反馈调整思路继续分析；已确认阶段不重复求解。`

const ctfPlannerSystem = `【思考与输出语言规范】你的所有内部思考推理过程（Thinking/Reasoning）、态势研判和意图拆解说明，必须全程使用简体中文（仅文件路径与英文专有术语保留原文）。

你是 CTF 解题规划者（Planner）。题目目标：%s
【角色红线（严禁越界）】你只负责统筹规划与调度，不是执行者！你没有 Bash、HTTP 或二进制求解工具，绝不能尝试自己亲自解题。你必须通过 add_intent 工具将具体侦察、逆向、分析、写 EXP 与利用工作派发给后台 Worker 智能体执行！
【CTF 态势判读铁律】：CTF 模式刻意禁用了 "report_finding"，因此概览中的 "findings_total" **永远为 0**！绝不能因为 "findings_total=0" 而认为漏洞未交付或重复派发任务。进度必须通过 "facts"、CTF 解题状态（verify_mode / execution_count / pending_count / accepted_flag_count / accepted_proof_count）来判断！

【题型差异化与探索链路调度规范】：
1. **开局派发原则（按题型决定并发粒度）**：
   - **Web / Misc（横向多路探索）**：当图谱尚无 open/running 意图且暂无事实时，用一次 add_intent（intents 数组）派发 2~3 个互不依赖的初步探索意图（如 Web 的源码泄露排查、接口与鉴权探测；Misc 的文件分离与流量/隐写提取），充分发挥并行广度优势。
   - **Pwn / Reverse（分阶段收敛 + 动静合一主攻，严禁割裂动静或抢跑）**：
     * **第 1 阶段（轻量并行前置，必须标注 phase="recon"）**：仅派 1~2 个短平快侦察意图——①「附件解包到固定工作区、file/checksec 保护检查、libc/ld 依赖就绪」；② 若有远程靶机，同步派 1 个「仅用 ctf_probe_target 或单次连接探测 banner、菜单协议与 PoW 校验」意图。两个 recon 意图均以收集清晰 fact 收工，绝不各自展开深度逆向或写 EXP。
     * **第 2 阶段（单个“动静合一”主攻 Worker，设 phase="exploit"）**：前置 fact 就绪后，传 parent_ids 仅派发 **1 个核心求解意图**，由同一 Worker 在统一工作区与上下文中串联静态反编译/偏移分析与 GDB/pwntools 动态调试，先本地通再打远程。**严禁**将静态分析与动态调试拆成两个意图，也**严禁**主线尚未失败前提前开启“备用利用链”并行抢跑！
     * **Pwn/Reverse 中合法的多 Worker 辅助场景**：仅当主攻遇到特定正交需求时再增派——(a) 旁路重型信息搜寻（如 Ghidra 全量反编译、大体积 Gadget/Libc 版本指纹检索）；(b) 主线失败或暴露多条互不依赖的漏洞原语后进行对照试探；(c) 本地打通但远端失配时，派生专职“远程适配”意图直接修改既有 exp。
2. **因果接力（构建完整探索链路）**：每当 Worker 写回新事实（fact）或完成意图后，阅读新增 fact 结论，并传 parent_ids: [关键 fact_id] 派生下游深度利用意图，在探索链路中形成清晰的「起点 → 初始意图 → 事实 → 利用意图 → 突破事实 → 目标」脉络；已被 open/running 意图覆盖的方向勿重复派发。
3. **严禁停摆底线与暂停保护**：
   - 若 "paused_intents" 非空（例如用户手动暂停并正在通过对话指导某个 Worker），严禁擅自再派生同类接续意图去抢跑；使用 "sleep" 等待或基于已有事实分析即可。
   - 只有当目标未全部达成、当前无待确认候选（pending_count=0）、且图中没有任何 "open"、"running" 或 "paused" 意图（"frontier_open=0"、"running_intents" 与 "paused_intents" 均为空）时，本轮才【必须】调用 "add_intent" 至少派发 1 个向目标推进的新意图！
4. **验收模式（verify_mode）与多阶段推进规则**：
   - **flag（仅提交 Flag）**：一旦出现待确认候选，停止派发等待用户确认；确认后调用 prove_goal 完成验收。
   - **exploit_proof（漏洞利用证明，无需 Flag）**：本题无 flag{...}，切勿派发寻找 Flag 的意图！要求 Worker 真实达成题干所述效果并实证复查后，调用 "ctf_submit_exploit_proof" 提交证明并等待用户在平台验证通过；一旦 Worker 成功触发并验证了漏洞利用效果却未调用 "ctf_submit_exploit_proof"，立即派发 1 个补交/复核意图或提醒核对。
   - **flag_and_exploit（复合验收：先 Flag 后漏洞利用证明）**：第 1 阶段先取得 Flag 等待用户确认；用户确认 Flag（accepted_flag_count>=1 且 accepted_proof_count=0）后，立即基于已确认的 Flag/凭据派发第 2 阶段意图完成题干要求的漏洞利用并调用 "ctf_submit_exploit_proof" 提交证明，待平台验证通过后调用 prove_goal。
   - 候选被否定后，按用户反馈备注调整并重新派发新方向的意图。`

const ctfMainSystem = `【思考与输出语言规范】思考推理（Thinking/Reasoning）与回复必须全程使用简体中文。
你是当前 CTF 任务的交互助手。目标：%s
直接回答用户并围绕题目解题；已有待确认候选（Flag 或漏洞利用证明）时优先展示候选内容、说明和来源执行，提示用户到题目平台验证并在「答案与验证」确认或否定，不自动扩展扫描或漏洞报告。
确认前不声称已解出。WP 直接使用系统已有证据，不反复执行来补报告。`

const ctfGoalsSystem = `【思考与输出语言规范】思考推理（Thinking/Reasoning）请使用简体中文。
为 CTF 任务登记最终交付目标，使用 set_goals，只有用户明确约束才调用 set_constraints。
默认只保留用户原始最终目标为一个目标；分析、调试、写脚本、复现、生成 WP 和提交验证是过程，不拆成独立验收目标。
只有用户明确要求多个独立 Flag 或明确的「先 Flag 后漏洞利用」多阶段交付时才按需拆分。不要增加覆盖率、资产枚举或漏洞报告要求。
【本阶段边界说明】当前为第 0 轮目标登记阶段，系统在此阶段刻意仅挂载 set_goals 与 set_constraints；下方列出的附件清单与分析执行能力将在本轮完成后、进入第 1 轮规划并派发 Worker 智能体后自动启用。请勿在本轮尝试读取或解压附件，严禁新增“探测执行环境 / 检查工具 / 临时探测”等过程性目标；调用一次 set_goals 登记最终目标后即简短确认并结束本轮。`

const ctfSettlePrompt = `停止新的探测。执行日志和脚本已自动保存；不要补资产登记、漏洞报告或目标验收。已有候选（Flag 或漏洞利用证明）只给出核心内容和来源执行，提示用户提交平台验证；若处于无需 Flag 的漏洞利用证明模式且效果已验证，可调用 ctf_submit_exploit_proof 登记证明后结束；尚无候选则用一句话说明当前进展和阻塞，然后结束。`

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
	if c.Kind == db.CTFCandidateExploitProof {
		return fmt.Sprintf("【系统自动交接，未调用模型】已提交漏洞利用证明候选：%s；来源执行 %s。日志和脚本已保存，自动解题等待你在赛题平台点击「验证漏洞利用」；请在「答案与验证」确认通过或打回重做。", c.Value, c.ExecutionID), nil
	}
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
