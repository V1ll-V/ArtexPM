"use client";

import * as React from "react";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { http } from "@/lib/api";

type Readiness = {
  configuration?: { items: { kind: string; key: string; state: string; reason?: string }[] };
  work?: Record<string, number>;
  enabled: boolean;
  ready_for_enable: boolean;
  ready_for_production: boolean;
  checks: { key: string; ready: boolean; reason?: string }[];
};
const labels: Record<string, string> = {
  schema: "数据库结构",
  legacy_migration: "历史数据迁移",
  configuration: "提示词、工具及触发器",
  critical_tools: "关键工具启用状态",
  verifier: "验收模型",
  reporter: "报告模型",
  evidence_storage: "证据存储",
  runtime: "服务状态",
  database: "数据库连接",
};

export default function VerificationPage() {
  const [state, setState] = React.useState<Readiness | null>(null);
  const [busy, setBusy] = React.useState(false);
  const refresh = React.useCallback(async () => {
    try {
      setState(await http<Readiness>("/verification/readiness"));
    } catch (e) {
      toast.error((e as Error).message);
    }
  }, []);
  React.useEffect(() => {
    void refresh();
  }, [refresh]);
  async function toggle() {
    if (!state) return;
    setBusy(true);
    try {
      setState(
        await http<Readiness>("/verification/lifecycle", {
          method: "POST",
          body: JSON.stringify({ enabled: !state.enabled }),
        }),
      );
      toast.success(state.enabled ? "已停止接收新的自主执行，已开始的工作会完成收尾" : "候选验收与有界收尾已联动启用");
    } catch (e) {
      toast.error((e as Error).message);
      await refresh();
    } finally {
      setBusy(false);
    }
  }
  async function retryMigration() {
    setBusy(true);
    try {
      await http("/verification/config-migration/retry", { method: "POST" });
      await refresh();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="mx-auto w-full max-w-3xl space-y-4 p-6">
      <Card>
        <CardHeader>
          <CardTitle>候选验收与任务收尾</CardTitle>
          <CardDescription>
            默认关闭。检查通过后，同时启用候选独立验收、可靠报告及有界收尾。候选不会直接成为确认漏洞。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Badge variant={state?.ready_for_production ? "default" : "outline"}>
            {state?.enabled ? (state.ready_for_enable ? "已启用" : "已配置启用，当前存在阻断") : "未启用"}
          </Badge>
          <p className="text-muted-foreground text-sm">
            这些检查确认运行条件。首次使用请先在授权的小范围任务中核对验收结论及报告范围，再扩大使用范围。停用会阻止新工作进入，已开始的执行仍按版本与租约校验提交。
          </p>
          {state?.checks.map((c) => (
            <div key={c.key} className="flex items-start justify-between gap-4 border-b py-2 text-sm">
              <div>
                <p>{labels[c.key] || c.key}</p>
                {c.reason ? <p className="text-muted-foreground">{c.reason}</p> : null}
              </div>
              <Badge variant={c.ready ? "secondary" : "outline"}>{c.ready ? "通过" : "待处理"}</Badge>
            </div>
          ))}
          {state?.work ? (
            <p className="text-muted-foreground text-sm">
              验收排队 {state.work.verification_queued ?? 0} · 验收失败 {state.work.verification_failed ?? 0} · 报告排队{" "}
              {state.work.reports_queued ?? 0} · 报告失败 {state.work.reports_failed ?? 0}
            </p>
          ) : null}
          {state?.configuration?.items
            .filter((item) => item.state === "needs_review")
            .map((item) => (
              <div key={`${item.kind}-${item.key}`} className="rounded-md border p-3 text-sm">
                <p>
                  {item.kind} · {item.key}
                </p>
                <p className="text-muted-foreground">{item.reason}</p>
              </div>
            ))}
          <div className="flex flex-wrap gap-2">
            <Button disabled={!state || busy || (!state.enabled && !state.ready_for_enable)} onClick={toggle}>
              {state?.enabled ? "停用联动流程" : "启用联动流程"}
            </Button>
            <Button variant="outline" disabled={busy} onClick={() => void refresh()}>
              重新检查
            </Button>
            <Button variant="outline" disabled={busy} onClick={retryMigration}>
              重试配置迁移
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
