package agent

import (
	"github.com/Autumn-27/artex/db"
)

// ============================================================================
// V1:技术判定的统一读取路径。
//
// 整个 agent 包只允许通过本文件的 splitEffectiveFindings 判断"某个 finding
// 现在能不能算确认漏洞"。禁止在别处另拼过滤条件——那正是 #30/#36/#42/#43
// 被人工标误报后仍然参与计数与目标证明的成因。
// ============================================================================

// findingVerdictStates 批量读取 finding 节点的技术判定状态(按节点 id 索引)。
// 读取失败时返回空表:调用方据此把全部 finding 视为未验证(保守失败),
// 而不是退回"全部算确认"。
func (t *ToolSet) findingVerdictStates(nodes []*db.Node) map[int64]db.VerdictState {
	out := map[int64]db.VerdictState{}
	if t.ts == nil {
		return out
	}
	ids := make([]int64, 0, len(nodes))
	for _, n := range nodes {
		if n != nil && n.Kind == db.KindFinding {
			ids = append(ids, n.ID)
		}
	}
	if len(ids) == 0 {
		return out
	}
	states, err := t.ts.FindingVerdictStates(ids)
	if err != nil {
		return out
	}
	return states
}

func (t *ToolSet) findingProjections(nodes []*db.Node) map[int64]db.FindingProjection {
	ids := make([]int64, 0, len(nodes))
	for _, n := range nodes {
		if n != nil && n.Kind == db.KindFinding {
			ids = append(ids, n.ID)
		}
	}
	p, err := t.ts.FindingProjections(ids)
	if err != nil {
		return map[int64]db.FindingProjection{}
	}
	return p
}

func applyFindingProjection(m map[string]any, p db.FindingProjection, ok bool) {
	if !ok {
		m["technical_verdict"], m["effective"] = "unverified", false
		return
	}
	m["summary"], m["verification"], m["effective"], m["technical_verdict"] = p.DisplayClaim, p, p.Effective, p.TechnicalVerdict
	if p.VerdictStale && p.TechnicalVerdict == db.VerdictSupported {
		m["technical_verdict"] = "stale"
	}
	if p.DisplaySeverity != "" {
		m["severity"] = p.DisplaySeverity
	} else if p.Effective {
		m["severity"] = "ungraded"
	}
}

// splitEffectiveFindings 把 finding 节点拆成"当前有效确认"与"候选/待验收/已否定"。
//
// 判据只有 db.FindingVerdictEffective 一处实现;这里只做分组。
func splitEffectiveFindings(nodes []*db.Node, states map[int64]db.VerdictState) (effective, pending []*db.Node) {
	for _, n := range nodes {
		if n == nil || n.Kind != db.KindFinding {
			continue
		}
		if db.FindingVerdictEffective(states[n.ID]) {
			effective = append(effective, n)
			continue
		}
		pending = append(pending, n)
	}
	return effective, pending
}

// findingVerdictLabel 返回用于展示的判定标签。refuted / needs_review 必须
// 如实表达,不能统一显示成"待验收"。
func findingVerdictLabel(st db.VerdictState) string {
	switch st.TechnicalVerdict {
	case db.VerdictSupported:
		if db.FindingVerdictEffective(st) {
			return "supported"
		}
		// 技术判定曾是 supported,但输入已经变化 → 判定过期,必须重新验收。
		return "stale"
	case db.VerdictRefuted:
		return "refuted"
	case db.VerdictNeedsReview:
		return "needs_review"
	default:
		return "unverified"
	}
}
