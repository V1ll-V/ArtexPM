package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestIntentFinalStateOnClosing 锁定"取消原因决定终态"这条约定。
//
// 旧实现只要 isSettling 为真就把被取消的意图记为 exhausted,于是"目标已达成"
// 也会被描述成"预算耗尽",与事实不符;而 deadline 收尾又确实是预算掐断。
func TestIntentFinalStateOnClosing(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{db.ClosingGoalSatisfied, "stopped"},
		{db.ClosingDeadline, "exhausted"},
		{db.ClosingBudgetExhausted, "exhausted"},
		{db.ClosingAllBlocked, "exhausted"},
		{"", "exhausted"},
	}
	for _, c := range cases {
		if got := intentFinalStateOnClosing(c.reason); got != c.want {
			t.Fatalf("reason=%q: got %q, want %q", c.reason, got, c.want)
		}
	}
}

// TestClosingEnterResultConstants 保证收尾结果类别稳定:调用方靠它们区分
// "已进入""已收尾""代次过期""终态",不能混用。
func TestClosingEnterResultConstants(t *testing.T) {
	all := []string{db.ClosingEntered, db.ClosingAlready, db.ClosingStaleRun, db.ClosingTerminal}
	seen := map[string]bool{}
	for _, v := range all {
		if v == "" {
			t.Fatal("收尾结果类别不能为空")
		}
		if seen[v] {
			t.Fatalf("收尾结果类别重复: %q", v)
		}
		seen[v] = true
	}
}
