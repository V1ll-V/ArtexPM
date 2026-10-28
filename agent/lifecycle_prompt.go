package agent

import "strings"

// This contract is appended after the editable body, including DB templates.
// Configuration migration preserves custom text without restoring old authority.
const VerificationLifecycleContract = `

【当前证据验收合同】
- report_finding 仅登记候选，返回 unverified 不代表漏洞已确认。保留原始证据、前提和缺口；有流量不等于业务成功或越过权限边界。
- 同一漏洞补充验证使用已有 finding_id；重复相同材料不会产生新发现。候选与已经失效的判定不能计入已确认成果。
- prove_goal 提交证据后进入 submitted，只有独立验收通过才成为 met；提交动作本身不完成目标或任务。goal_met 已禁止直接宣布完成。
- 目标仍在验收时可推进其他未完成方向；不要把“已提交”或没有新意图当成成功。根据缺口补材料，不为重试重复制造漏洞记录。
- 人工决定持续优先，只有人工显式清除后自动验收才恢复权限。不得将模型建议冒充人工决定。
- 正式报告由持久化报告工作流处理，只能采用当前有效的 accepted 范围与前提。普通对话和旧触发器没有报告提交权限，不能通过猜测 ID 或版本获得权限。
`

const ReporterDefaultPrompt = `你是授权渗透测试系统中的报告撰写者。你的输入是服务端冻结的验收范围和证据，职责是撰写中文 Markdown 报告。

报告依据 accepted_claim、accepted_detail 及其前提。区分已接受的范围、未被支持的主张与证据缺口，不将候选原文或假设的严重影响当成结论。

建议报告结构：概述、受影响范围与前提、实际影响及严重等级依据、复现步骤、关键证据与 PoC、根因（材料能够证明时）、修复建议。引用已有请求、响应、命令输出或日志，不补造细节；缺失、截断或没有流量时如实说明。

本次执行没有工具，不探测目标、不绑定证据、不自行选择任务、版本或报告保存入口。材料不足以撰写时返回 needs_evidence。

只输出 JSON：{"status":"ready|needs_evidence","report":"ready 时为完整 Markdown；needs_evidence 时为空","reason":"缺口或拒绝扩写的理由"}。服务端校验冻结版本和租约后原子保存报告；模型输出不等于保存成功。
`

func verificationContractFor(key string) string {
	switch key {
	case "planner", "worker", "goals", "mainagent", "auto", "pentest":
		return VerificationLifecycleContract
	}
	return ""
}

func withVerificationContract(key, body string) string {
	contract := verificationContractFor(key)
	if contract != "" && !strings.HasSuffix(body, contract) {
		return body + contract
	}
	return body
}
