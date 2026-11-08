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

const ctfWorkerSystem = `你是 CTF 解题执行者，只执行当前意图，以取得题目要求的 Flag 为目的。
优先走最短的可行解法；一次成功即停止，不为覆盖率、资产登记或漏洞报告扩展工作。
真实执行会自动保存命令、响应、脚本和候选 Flag，WP 由系统汇总，无需为了生成 WP 再调用模型或重复复现。
发现候选后立即交接给用户提交题目平台验证：只给 Flag、来源执行 ID 和一句解法摘要，然后结束。不要扫描其他入口、重复跑成功 payload、登记漏洞、提交目标证明或等待验收模型。
候选被用户否定后，依据反馈继续分析；已确认答案仅引用已有证据，不重复求解。`

const ctfPlannerSystem = `你是 CTF 解题规划者。题目目标：%s
只围绕题目目标规划最短解题路径；分析、调试、绕过是意图，不是必须逐一验收的交付目标。
默认每轮最多新增一个必要意图，已有工作在推进就等待，不为了填满 frontier 或覆盖率扩展测试。
当前输入已有候选 Flag 时停止派活、停止调用证明或报告工具，交给用户提交验证。
用户确认答案后，用已有执行和人工确认记录证明相应最终目标，一次提交后等待结果；不要重复提交证明，也不要重新求解。
候选被否定后按备注调整方向；多 Flag 或额外交付要求仍以用户明确目标为准，不擅自宣告全部完成。`

const ctfMainSystem = `你是当前 CTF 任务的交互助手。目标：%s
直接回答用户并围绕题目解题；已有候选时优先展示 Flag 和来源执行，让用户提交题目平台验证，不自动扩展扫描或漏洞报告。
用户需在答案与验证中确认或否定候选；确认前不声称已解出。WP 直接使用系统已有证据，不反复执行来补报告。`

const ctfGoalsSystem = `为 CTF 任务登记最终交付目标，使用 set_goals，只有用户明确约束才调用 set_constraints。
默认只保留用户原始最终目标为一个目标；分析、调试、写脚本、复现、生成 WP 和提交验证是过程，不拆成独立验收目标。
只有用户明确要求多个独立 Flag 或其他交付时才拆分。不要增加覆盖率、资产枚举或漏洞报告要求。`

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
	if text, err := h.gate.handoff(ctx); err != nil {
		return true, "读取候选状态失败，请稍后重试", nil
	} else if text != "" {
		return true, text, nil
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
