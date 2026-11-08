"use client";

import * as React from "react";
import Link from "next/link";

import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, http } from "@/lib/api";
import type { LLMProfile } from "@/lib/types";

type Readiness = {
  configuration?: { items: { kind: string; key: string; state: string; reason?: string }[] };
  work?: Record<string, number>;
  enabled: boolean;
  ready_for_enable: boolean;
  ready_for_production: boolean;
  checks: { key: string; ready: boolean; reason?: string }[];
  models: { verifier_profile_id: number | null; reporter_profile_id: number | null; reporter_enabled: boolean };
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
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [verifierModel, setVerifierModel] = React.useState("default");
  const [reporterModel, setReporterModel] = React.useState("default");
  const applyState = React.useCallback((next: Readiness) => {
    setState(next);
    setVerifierModel(String(next.models?.verifier_profile_id ?? "default"));
    setReporterModel(String(next.models?.reporter_profile_id ?? "default"));
  }, []);
  const refresh = React.useCallback(async () => {
    try {
      const [next, models] = await Promise.all([http<Readiness>("/verification/readiness"), api.llmProfiles()]);
      applyState(next);
      setProfiles(models);
    } catch (e) {
      toast.error((e as Error).message);
    }
  }, [applyState]);
  React.useEffect(() => {
    void refresh();
  }, [refresh]);
  async function toggle() {
    if (!state) return;
    setBusy(true);
    try {
      applyState(
        await http<Readiness>("/verification/lifecycle", {
          method: "POST",
          body: JSON.stringify({ enabled: !state.enabled }),
        }),
      );
      toast.success(state.enabled ? "自动候选验收与报告已停用，任务执行继续独立运行" : "自动候选验收已启用；报告模型就绪后生成漏洞报告");
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
  async function saveModels() {
    setBusy(true);
    try {
      const next = await http<Readiness>("/verification/models", {
        method: "PUT",
        body: JSON.stringify({
          verifier_profile_id: verifierModel === "default" ? null : Number(verifierModel),
          reporter_profile_id: reporterModel === "default" ? null : Number(reporterModel),
        }),
      });
      applyState(next);
      toast.success("模型分工已保存，无需另建多套 API 配置");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const modelDirty = verifierModel !== String(state?.models?.verifier_profile_id ?? "default") || reporterModel !== String(state?.models?.reporter_profile_id ?? "default");
  const defaultProfile = profiles.find((p) => p.is_default);
  function modelOptions(selected: string) {
    return <>
      <option value="default">跟随默认配置{defaultProfile ? `（${defaultProfile.name}）` : "（尚未设置默认模型）"}</option>
      {selected !== "default" && !profiles.some((p) => p.id === selected) && <option value={selected} disabled>原模型已不可用，请重新选择</option>}
      {profiles.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
    </>;
  }
  return (
    <div className="mx-auto w-full max-w-3xl space-y-4 p-6">
      <Card>
        <CardHeader>
          <CardTitle>任务执行独立运行</CardTitle>
          <CardDescription>配置默认模型或任务模型后即可启动任务。下方可选的漏洞验收与自动报告开关不会阻止任务执行、暂停或继续。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">目标完成仍需证据判定；CTF 答案仍需人工确认。CTF 的 WP 直接汇总执行证据，不依赖漏洞报告模型。</p>
          <div className="flex flex-wrap gap-2">
            <Button asChild variant="outline"><Link href="/system/llm">打开模型配置</Link></Button>
            <Button asChild variant="outline"><Link href="/function/tasks">返回任务列表</Link></Button>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>验收与报告模型配置</CardTitle>
          <CardDescription>直接选择已经保存的模型即可，两种职责可以共用同一个模型和 API Key。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="verifier-model" className="text-sm font-medium">验收模型</label>
            <select id="verifier-model" value={verifierModel} disabled={busy || !state} onChange={(e) => setVerifierModel(e.target.value)} className="w-full rounded-md border bg-background p-2 text-sm">{modelOptions(verifierModel)}</select>
            <p className="text-xs text-muted-foreground">默认：目标验收复用任务模型，漏洞候选验收复用系统默认模型。单独指定后，两者使用所选模型。</p>
          </div>
          <div className="space-y-2">
            <label htmlFor="reporter-model" className="text-sm font-medium">漏洞报告模型</label>
            <select id="reporter-model" value={reporterModel} disabled={busy || !state} onChange={(e) => setReporterModel(e.target.value)} className="w-full rounded-md border bg-background p-2 text-sm">{modelOptions(reporterModel)}</select>
            <p className="text-xs text-muted-foreground">默认复用系统模型，仅用于整理通过验收的漏洞报告。模型未就绪时报告等待，不影响任务求解或候选验收。</p>
          </div>
          {state?.models?.reporter_enabled === false && <p className="text-sm text-amber-600">Reporter Agent 当前已停用。可前往 <Link className="underline" href="/system/agents/detail?key=reporter">报告 Agent 设置</Link> 启用自动报告。</p>}
          <Button disabled={busy || !state || !modelDirty} onClick={saveModels}>保存模型分工</Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>自动漏洞验收与报告（可选）</CardTitle>
          <CardDescription>
            默认关闭，仅控制漏洞候选的自动验收和报告队列。任务执行与有界收尾始终独立运行，候选不会直接成为确认漏洞。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Badge variant={state?.ready_for_production ? "default" : "outline"}>
            {state?.enabled ? (state.ready_for_production ? "自动验收与报告已就绪" : state.ready_for_enable ? "自动验收已就绪，报告等待配置" : "已启用，自动化存在待处理项") : "未启用，不影响任务执行"}
          </Badge>
          <p className="text-muted-foreground text-sm">
            以下检查仅针对可选的自动验收与报告。停用后漏洞候选保留在队列，任务继续执行，逐目标证据判定仍然处理。
          </p>
          {state?.checks.map((c) => (
            <div key={c.key} className="flex items-start justify-between gap-4 border-b py-2 text-sm">
              <div>
                <p>{labels[c.key] || c.key}</p>
                {c.reason ? <p className="text-muted-foreground">{c.reason}</p> : null}
              </div>
              <Badge variant={c.ready ? "secondary" : "outline"}>{c.ready ? "通过" : c.key === "reporter" ? "报告等待" : "待处理"}</Badge>
            </div>
          ))}
          {state?.work ? (
            <p className="text-muted-foreground text-sm">
              目标判定待处理 {state.work.goals_queued ?? 0} · 漏洞验收排队 {state.work.findings_queued ?? 0} · 验收失败 {state.work.verification_failed ?? 0} · 报告排队{" "}
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
            <Button disabled={!state || busy || modelDirty || (!state.enabled && !state.ready_for_enable)} onClick={toggle}>
              {state?.enabled ? "停用自动验收与报告" : "启用自动验收"}
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
