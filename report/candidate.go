package report

import (
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"strings"
)

// CandidateReport is a deterministic material inventory, never a supported
// verdict or a formal report. It does not call a model or read arbitrary paths.
func CandidateReport(f *db.DBFinding) string {
	if f == nil || f.Projection().Effective {
		return ""
	}
	p := f.Projection()
	var b strings.Builder
	fmt.Fprintf(&b, "# 候选材料报告：%s\n\n> 未通过当前独立验收，不是确认漏洞报告，不能用于目标达成证明。原始主张和材料可能有误。\n\n", findingTitle(f))
	fmt.Fprintf(&b, "## 候选主张（尚未确认）\n\n%s\n\n- 候选等级：%s（未经独立确认）\n- 技术判定：%s\n- 输入版本：%d\n\n", p.ProposedClaim, f.Severity, p.TechnicalVerdict, p.InputRevision)
	b.WriteString("## 复现材料与 PoC 原文\n\n以下仅收录已登记材料，不自动补造步骤、账号、请求或成功结果。本地文件路径不等于已向验收器提供文件内容。\n\n")
	if strings.TrimSpace(f.Evidence) == "" {
		b.WriteString("尚未登记复现材料。\n\n")
	} else {
		fence := "```"
		for strings.Contains(f.Evidence, fence) {
			fence += "`"
		}
		fmt.Fprintf(&b, "%stext\n%s\n%s\n\n", fence, f.Evidence, fence)
	}
	b.WriteString("## 验收缺口与未支持的影响\n\n")
	var detail struct {
		MissingEvidence   []string `json:"missing_evidence"`
		UnsupportedClaims []string `json:"unsupported_claims"`
	}
	_ = json.Unmarshal(p.VerdictDetail, &detail)
	for _, s := range detail.MissingEvidence {
		fmt.Fprintf(&b, "- 待补证据：%s\n", s)
	}
	for _, s := range detail.UnsupportedClaims {
		fmt.Fprintf(&b, "- 未支持主张：%s\n", s)
	}
	if len(detail.MissingEvidence)+len(detail.UnsupportedClaims) == 0 {
		b.WriteString("尚无可展示的验收缺口；不代表验收通过。\n")
	}
	b.WriteString("\n## 影响、根因与修复\n\n以证据和有效验收结论为准；当前不补写未经证明的影响、根因或修复承诺。补齐关键材料并通过验收后，由报告队列自动生成正式详细报告。\n")
	return b.String()
}
