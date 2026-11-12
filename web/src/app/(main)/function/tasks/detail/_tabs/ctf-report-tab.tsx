"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, DownloadIcon, RefreshCwIcon, RotateCcwIcon, SparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { CTFCandidate, CTFExecution, CTFProgress, CTFWriteup } from "@/lib/types";
import { copyText } from "@/lib/utils";

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const labels = { candidate: "待确认", accepted: "已确认", rejected: "已否定", stale: "旧输入，已过期" };
const phases: Record<CTFProgress["phase"], string> = {
  not_started: "等待执行", solving: "正在解题", awaiting_confirmation: "等待提交验证",
  confirmed: "答案已确认", paused: "已暂停", stopped: "已停止",
};
function Candidate({
  candidate: c,
  busy,
  decide,
  completed,
}: {
  candidate: CTFCandidate;
  busy: boolean;
  completed: boolean;
  decide: (c: CTFCandidate, state: "accepted" | "rejected", notes: string, completeTask?: boolean) => Promise<void>;
}) {
  const [notes, setNotes] = React.useState(c.notes);
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <code className="break-all text-sm">{c.value}</code>
        <Button size="sm" variant="outline" onClick={async () => { if (await copyText(c.value)) toast.success("Flag 已复制，可提交题目平台验证"); }}>
          <CopyIcon />复制 Flag
        </Button>
        <span className={c.state === "accepted" ? "text-xs text-emerald-600" : "text-xs text-muted-foreground"}>
          {labels[c.state]}
        </span>
      </div>
      <p className="break-all font-mono text-xs text-muted-foreground">
        执行 {c.execution_id} · 输入 {c.input_hash.slice(0, 12)}
      </p>
      {c.state !== "stale" && (
        <>
          <Textarea
            aria-label={`候选 ${c.id} 验证备注`}
            placeholder="填写复现结果或平台验证反馈"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
          />
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={busy || completed} onClick={() => decide(c, "accepted", notes, true)}>
              <CheckIcon />
              {completed ? "任务已完成" : c.state === "accepted" ? "完成解题任务" : "验证正确并完成任务"}
            </Button>
            {!completed && c.state !== "accepted" && <Button size="sm" variant="outline" disabled={busy} onClick={() => decide(c, "accepted", notes, false)}>仅确认，保留其他目标</Button>}
            <Button
              size="sm"
              variant="outline"
              disabled={busy || c.state === "rejected"}
              onClick={() => decide(c, "rejected", notes)}
            >
              否定{c.state === "accepted" ? "并撤销确认" : "候选"}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

export function CTFReportTab({ taskId, onTaskUpdated }: { taskId: string; onTaskUpdated?: () => void }) {
  const [wp, setWP] = React.useState<CTFWriteup>();
  const [executions, setExecutions] = React.useState<CTFExecution[]>([]);
  const [candidates, setCandidates] = React.useState<CTFCandidate[]>([]);
  const [progress, setProgress] = React.useState<CTFProgress>();
  const [busy, setBusy] = React.useState(false);
  const [optimizing, setOptimizing] = React.useState(false);
  const [error, setError] = React.useState("");
  const request = React.useRef<AbortController | null>(null);
  const mutating = React.useRef<string | null>(null);
  const activeTask = React.useRef(taskId);
  const refresh = React.useCallback(async (quiet = false) => {
    if (activeTask.current !== taskId) return;
    if (quiet && (request.current || mutating.current === taskId)) return;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    if (!quiet) setBusy(true);
    try {
      const [report, evidence] = await Promise.all([api.ctfWP(taskId, controller.signal), api.ctfEvidence(taskId, controller.signal)]);
      if (controller.signal.aborted) return;
      setWP(report);
      setExecutions(evidence.executions);
      setCandidates(evidence.candidates);
      setProgress(evidence.progress);
      setError("");
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "加载失败");
    } finally {
      if (request.current === controller) {
        request.current = null;
        if (!controller.signal.aborted && mutating.current !== taskId) setBusy(false);
      }
    }
  }, [taskId]);
  React.useEffect(() => {
    activeTask.current = taskId;
    setWP(undefined);
    setExecutions([]);
    setCandidates([]);
    setProgress(undefined);
    void refresh();
    const poll = () => { if (document.visibilityState === "visible") void refresh(true); };
    const timer = window.setInterval(poll, 5000);
    document.addEventListener("visibilitychange", poll);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", poll);
      request.current?.abort();
      request.current = null;
      activeTask.current = "";
    };
  }, [refresh, taskId]);
  async function decide(c: CTFCandidate, state: "accepted" | "rejected", notes: string, completeTask = false) {
    mutating.current = taskId;
    request.current?.abort();
    request.current = null;
    setBusy(true);
    try {
      await api.decideCTFFlag(taskId, c, state, notes, completeTask);
      if (activeTask.current !== taskId) return;
      toast.success(state === "accepted" ? completeTask ? "Flag 已确认，解题任务已完成" : "已确认 Flag，其他目标仍保留" : c.state === "accepted" ? "已撤销确认；若任务曾完成，现已重新打开并暂停，请按需继续" : "已否定候选；处理完其他候选后，未手动暂停的任务会继续解题");
      onTaskUpdated?.();
      await refresh();
    } catch (e) {
      if (activeTask.current === taskId) toast.error(e instanceof Error ? e.message : "操作失败");
    } finally {
      if (mutating.current === taskId) mutating.current = null;
      if (activeTask.current === taskId) setBusy(false);
    }
  }
  async function log(e: CTFExecution, stream: "stdout" | "stderr") {
    try {
      download(await api.ctfLog(taskId, e.id, stream), `${e.id}-${stream}.log`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "下载失败");
    }
  }

  async function handleOptimizeWP() {
    setOptimizing(true);
    try {
      const res = await api.optimizeCTFWP(taskId);
      setWP(res);
      toast.success("已完成 WP 提炼优化（去噪并生成整体思路概述）");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "优化 WP 失败");
    } finally {
      setOptimizing(false);
    }
  }

  async function handleResetWP() {
    setOptimizing(true);
    try {
      const res = await api.resetCTFWP(taskId);
      setWP(res);
      toast.success("已恢复原始完整过程 WP");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "恢复 WP 失败");
    } finally {
      setOptimizing(false);
    }
  }
  return (
    <div className="space-y-4">
      {progress && (
        <Card>
          <CardContent className="space-y-3 pt-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="font-medium" aria-live="polite">{progress.task_status === "done" ? "解题任务已完成" : phases[progress.phase]}{progress.paused && progress.phase !== "paused" ? " · 任务已暂停" : ""}</p>
              <span className="text-xs text-muted-foreground">页面可见时每 5 秒自动更新</span>
            </div>
            <div className="grid grid-cols-3 gap-3 text-sm">
              <div>实际执行 <strong>{progress.execution_count}</strong> 次</div>
              <div>待确认 <strong>{progress.pending_count}</strong> 个</div>
              <div>已确认 <strong>{progress.accepted_count}</strong> 个</div>
            </div>
            {progress.phase === "awaiting_confirmation" && <p className="text-sm text-muted-foreground">已找到候选 Flag，自动解题正在等待，不再继续派活或请求模型。复制下方 Flag 提交题目平台，再记录验证正确或否定候选。日志、脚本与 WP 已自动保留。</p>}
            {progress.phase === "confirmed" && <p className="text-sm text-muted-foreground">{progress.task_status === "done" ? "当前 Flag 已确认，任务已结束，可下载 WP。" : "Flag 已确认。如本题已完成，点击「完成解题任务」；如仍有其他 Flag 或交付目标，可继续保留任务。"}</p>}
            {progress.phase === "stopped" && <p className="text-sm text-muted-foreground">本次执行已停止，当前输入尚无已确认答案；已有日志与阶段 WP 会保留。</p>}
            <p className="break-all font-mono text-xs text-muted-foreground">输入版本 {progress.input_hash.slice(0, 16)}</p>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">答案与验证</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            核对平台结果后，单题可直接「验证正确并完成任务」。多 Flag 或仍有其他交付时，选择「仅确认，保留其他目标」。完成任务会停止剩余自动意图，并将未继续执行的目标注明为放弃；旧输入候选不能确认。
          </p>
          {candidates.length ? (
            candidates.map((c) => <Candidate key={`${c.id}-${c.revision}`} candidate={c} busy={busy} decide={decide} completed={progress?.task_status === "done"} />)
          ) : (
            <p className="text-sm text-muted-foreground">尚无候选答案。可以先查看阶段 WP 和执行记录。</p>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-sm">解题报告（WP）</CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant={wp?.is_optimized ? "outline" : "default"}
              className={wp?.is_optimized ? "border-amber-500/40 text-amber-600 dark:text-amber-400" : "bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 text-white shadow-sm"}
              disabled={busy || optimizing}
              onClick={handleOptimizeWP}
            >
              <SparklesIcon className={`size-3.5 ${optimizing ? "animate-spin" : ""}`} />
              {optimizing ? "正在提炼优化…" : "优化 WP"}
            </Button>
            {wp?.is_optimized && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy || optimizing}
                onClick={handleResetWP}
              >
                <RotateCcwIcon className="size-3.5" />
                恢复完整版
              </Button>
            )}
            <Button size="sm" variant="outline" disabled={busy || optimizing} onClick={() => void refresh()}>
              <RefreshCwIcon className={busy ? "animate-spin" : ""} />
              刷新 WP
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!wp || optimizing}
              onClick={async () => {
                if (wp && (await copyText(wp.markdown))) toast.success("已复制 WP");
              }}
            >
              <CopyIcon />
              复制
            </Button>
            <Button
              size="sm"
              disabled={!wp || optimizing}
              onClick={() =>
                wp && download(new Blob([wp.markdown], { type: "text/markdown;charset=utf-8" }), `ctf-${taskId}-wp.md`)
              }
            >
              <DownloadIcon />
              下载 Markdown
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          {wp && (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-mono text-xs text-muted-foreground">
                版本 {wp.revision.slice(0, 12)} · {new Date(wp.generated_at).toLocaleString()}
              </p>
              {wp.is_optimized ? (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-xs font-medium text-amber-600 dark:text-amber-400 border border-amber-500/20">
                  <SparklesIcon className="size-3" />
                  已优化：核心思路精简版（已去噪，含整体解题思路概述）
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-0.5 text-xs text-muted-foreground">
                  完整审计过程版
                </span>
              )}
            </div>
          )}
          <div className="max-h-[70vh] overflow-auto rounded-md border bg-muted/20 p-4">
            {wp ? (
              <Markdown text={wp.markdown} />
            ) : (
              <p className="text-sm text-muted-foreground">{busy ? "正在整理已有证据…" : "暂无 WP"}</p>
            )}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">实际执行记录（最近 100 次）</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {executions.length === 0 && <p className="text-sm text-muted-foreground">尚无执行记录。</p>}
          {executions.map((e) => (
            <details className="rounded-md border p-3 text-xs" key={e.id}>
              <summary className="cursor-pointer">
                意图 #{e.intent_id} · {new Date(e.started_at).toLocaleString()} · exit {e.exit_code}{" "}
                {e.error && "· 异常"}
                {e.truncated && " · 输出已截断"}
                {progress && e.input_hash !== progress.input_hash && " · 旧输入版本"}
              </summary>
              <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all">{e.command}</pre>
              {e.error && <p className="mt-2 text-destructive">{e.error}</p>}
              <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all">
                {e.stdout}
                {e.stderr}
              </pre>
              <div className="mt-2 flex gap-2">
                <Button size="sm" variant="outline" onClick={() => log(e, "stdout")}>
                  下载 stdout
                </Button>
                <Button size="sm" variant="outline" onClick={() => log(e, "stderr")}>
                  下载 stderr
                </Button>
              </div>
            </details>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
