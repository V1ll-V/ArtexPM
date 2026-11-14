"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, DownloadIcon, RefreshCwIcon, RotateCcwIcon, SparklesIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
const verifyModeLabels: Record<NonNullable<CTFProgress["verify_mode"]>, string> = {
  flag: "提交 Flag",
  exploit_proof: "漏洞利用证明（无需 Flag）",
  flag_and_exploit: "复合验收（Flag + 漏洞利用证明）",
};

function Candidate({
  candidate: c,
  busy,
  decide,
  completed,
  isMultiGoal,
  verifyMode,
  proofConfirmedCount,
}: {
  candidate: CTFCandidate;
  busy: boolean;
  completed: boolean;
  decide: (c: CTFCandidate, state: "accepted" | "rejected", notes: string, completeTask?: boolean) => Promise<void>;
  isMultiGoal?: boolean;
  verifyMode?: CTFProgress["verify_mode"];
  proofConfirmedCount?: number;
}) {
  const [notes, setNotes] = React.useState(c.notes);
  React.useEffect(() => {
    setNotes(c.notes);
  }, [c.notes]);

  const isProof = c.kind === "exploit_proof";
  const needNextStageAfterFlag = !isProof && verifyMode === "flag_and_exploit" && (proofConfirmedCount ?? 0) === 0;

  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className={isProof ? "rounded-full bg-indigo-500/15 px-2 py-0.5 text-xs font-medium text-indigo-600 dark:text-indigo-400 border border-indigo-500/30" : "rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground"}>
            {isProof ? "漏洞利用证明" : "Flag"}
          </span>
          <code className="break-all text-sm font-semibold">{c.value}</code>
        </div>
        <div className="flex items-center gap-2">
          {!isProof && (
            <Button size="sm" variant="outline" onClick={async () => { if (await copyText(c.value)) toast.success("Flag 已复制，可提交题目平台验证"); }}>
              <CopyIcon />复制 Flag
            </Button>
          )}
          <span className={c.state === "accepted" ? "rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 px-2 py-0.5 text-xs font-medium border border-emerald-500/30" : "text-xs text-muted-foreground"}>
            {labels[c.state]}
          </span>
        </div>
      </div>
      <p className="break-all font-mono text-xs text-muted-foreground">
        执行 {c.execution_id} · 输入 {c.input_hash.slice(0, 12)}
      </p>
      {c.state !== "stale" && (
        <>
          <Textarea
            aria-label={`候选 ${c.id} 验证备注`}
            placeholder={isProof ? "可补充平台验证截图说明、裁判机返回值或持久化验证细节" : "填写对应场景或复现说明（例如：阶段 1 密钥泄露 / 场景 2 提权）"}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
          />
          <div className="flex flex-wrap gap-2">
            {c.state === "accepted" ? (
              <>
                {notes !== c.notes && (
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => decide(c, "accepted", notes, false)}>
                    保存备注修改
                  </Button>
                )}
                {!completed && (
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => decide(c, "accepted", notes, true)}>
                    {isProof ? "以此证明结束整题" : "提前以此 Flag 结束整题"}
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => decide(c, "rejected", notes)}
                >
                  撤销确认
                </Button>
              </>
            ) : needNextStageAfterFlag ? (
              <>
                <Button size="sm" disabled={busy || completed} onClick={() => decide(c, "accepted", notes, false)}>
                  <CheckIcon />
                  确认 Flag 正确，继续下一步（漏洞利用证明）
                </Button>
                <Button size="sm" variant="outline" disabled={busy || completed} onClick={() => decide(c, "accepted", notes, true)}>
                  直接以此完成整题
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy || c.state === "rejected"}
                  onClick={() => decide(c, "rejected", notes)}
                >
                  否定候选
                </Button>
              </>
            ) : isMultiGoal ? (
              <>
                <Button size="sm" disabled={busy || completed} onClick={() => decide(c, "accepted", notes, false)}>
                  <CheckIcon />
                  {isProof ? "确认通过，继续剩余目标" : "确认此 Flag，继续剩余目标"}
                </Button>
                <Button size="sm" variant="outline" disabled={busy || completed} onClick={() => decide(c, "accepted", notes, true)}>
                  验证通过并结束整题
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy || c.state === "rejected"}
                  onClick={() => decide(c, "rejected", notes)}
                >
                  {isProof ? "验证未通过，打回重做" : "否定候选"}
                </Button>
              </>
            ) : (
              <>
                <Button size="sm" disabled={busy || completed} onClick={() => decide(c, "accepted", notes, true)}>
                  <CheckIcon />
                  {completed ? "任务已完成" : isProof ? "平台验证通过并完成任务" : "验证正确并完成任务"}
                </Button>
                {!completed && (
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => decide(c, "accepted", notes, false)}>
                    仅确认，保留其他目标
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy || c.state === "rejected"}
                  onClick={() => decide(c, "rejected", notes)}
                >
                  {isProof ? "验证未通过，打回重做" : "否定候选"}
                </Button>
              </>
            )}
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
  const [changingMode, setChangingMode] = React.useState(false);
  const [proofSummary, setProofSummary] = React.useState("");
  const [proofNotes, setProofNotes] = React.useState("");
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
      const isProof = c.kind === "exploit_proof";
      toast.success(
        state === "accepted"
          ? completeTask
            ? isProof
              ? "漏洞利用验证已通过，解题任务已完成"
              : "Flag 已确认，解题任务已完成"
            : isProof
            ? "已确认漏洞利用通过，任务继续保持"
            : "已确认 Flag，将继续后续阶段或保留其他目标"
          : c.state === "accepted"
          ? "已撤销确认；若任务曾完成，现已重新打开并暂停，请按需继续"
          : isProof
          ? "已打回该漏洞利用证明；未手动暂停的任务将继续尝试"
          : "已否定候选；处理完其他候选后，未手动暂停的任务会继续解题",
      );
      onTaskUpdated?.();
      await refresh();
    } catch (e) {
      if (activeTask.current === taskId) toast.error(e instanceof Error ? e.message : "操作失败");
    } finally {
      if (mutating.current === taskId) mutating.current = null;
      if (activeTask.current === taskId) setBusy(false);
    }
  }
  async function handleVerifyModeChange(next: "flag" | "exploit_proof" | "flag_and_exploit") {
    setChangingMode(true);
    try {
      await api.setCTFVerifyMode(taskId, next);
      toast.success(`验收方式已切换为「${verifyModeLabels[next]}」`);
      onTaskUpdated?.();
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "切换验收方式失败");
    } finally {
      setChangingMode(false);
    }
  }
  async function handleCompleteExploit() {
    mutating.current = taskId;
    request.current?.abort();
    request.current = null;
    setBusy(true);
    try {
      await api.completeCTFExploit(taskId, {
        proof_summary: proofSummary.trim(),
        notes: proofNotes.trim(),
      });
      if (activeTask.current !== taskId) return;
      toast.success("已确认平台漏洞利用验证通过，任务已完成并生成 Write-up");
      onTaskUpdated?.();
      await refresh();
    } catch (e) {
      if (activeTask.current === taskId) toast.error(e instanceof Error ? e.message : "完成失败");
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
  const verifyMode = progress?.verify_mode ?? "flag";
  const terminal = progress?.task_status === "done" || progress?.task_status === "failed" || progress?.task_status === "timeout";
  const latestPendingCandidate = candidates.find((c) => c.state === "candidate");
  const hasPendingExploitProof = candidates.some((c) => c.kind === "exploit_proof" && c.state === "candidate");
  const showDirectExploitComplete =
    !!progress &&
    progress.task_status !== "done" &&
    !hasPendingExploitProof &&
    (verifyMode === "exploit_proof" || (verifyMode === "flag_and_exploit" && (progress.accepted_flag_count ?? 0) >= 1));

  return (
    <div className="space-y-4">
      {progress && (
        <Card>
          <CardContent className="space-y-3 pt-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="font-medium" aria-live="polite">
                {progress.task_status === "done"
                  ? "解题任务已完成"
                  : progress.phase === "solving" && progress.accepted_count > 0 && (progress.goals_total ?? 0) > 1
                  ? `正在解题（已确认 ${progress.accepted_count}/${progress.goals_total} 个场景）`
                  : phases[progress.phase]}
                {progress.paused && progress.phase !== "paused" ? " · 任务已暂停" : ""}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="ctf-verify-mode-switch" className="text-xs text-muted-foreground">
                  验收方式
                </label>
                <select
                  id="ctf-verify-mode-switch"
                  className="h-7 rounded border bg-background px-2 text-xs"
                  value={verifyMode}
                  disabled={changingMode || terminal}
                  onChange={(e) => void handleVerifyModeChange(e.target.value as "flag" | "exploit_proof" | "flag_and_exploit")}
                >
                  <option value="flag">提交 Flag</option>
                  <option value="exploit_proof">漏洞利用证明（无需 Flag）</option>
                  <option value="flag_and_exploit">复合验收（Flag + 漏洞利用）</option>
                </select>
                <span className="text-xs text-muted-foreground">页面可见时每 5 秒自动更新</span>
              </div>
            </div>
            <div className={`grid ${(progress.goals_total ?? 0) > 1 ? "grid-cols-4" : "grid-cols-3"} gap-3 text-sm`}>
              {(progress.goals_total ?? 0) > 1 && (
                <div>
                  总场景目标 <strong>{progress.goals_met ?? 0}/{progress.goals_total}</strong> 达成
                </div>
              )}
              <div>实际执行 <strong>{progress.execution_count}</strong> 次</div>
              <div>待确认 <strong>{progress.pending_count}</strong> 个</div>
              <div>已确认 <strong>{progress.accepted_count}</strong> 个</div>
            </div>
            {progress.phase === "awaiting_confirmation" && (
              <p className="text-sm text-amber-600 dark:text-amber-400 font-medium">
                {latestPendingCandidate?.kind === "exploit_proof"
                  ? "已提交漏洞利用证明，自动解题已暂停。请前往赛题平台点击「验证漏洞利用」，核对裁判结果后在下方确认或打回重做。"
                  : "已找到新候选 Flag，自动解题已暂停等待提交验证。核对后点击下方对应候选的确认按钮，未完成的阶段/场景将自动继续。"}
              </p>
            )}
            {verifyMode === "flag_and_exploit" && (progress.accepted_flag_count ?? 0) >= 1 && (progress.accepted_proof_count ?? 0) === 0 && progress.task_status !== "done" && (
              <p className="text-sm text-indigo-600 dark:text-indigo-400 font-medium">
                复合验收进度：阶段 1（Flag）已确认 ✓ · 当前进入阶段 2（漏洞利用证明，无需第二个 Flag）。
              </p>
            )}
            {progress.phase === "solving" && progress.accepted_count > 0 && (progress.goals_open ?? 0) > 0 && (
              <p className="text-sm text-emerald-600 dark:text-emerald-400 font-medium">
                已确认 {progress.accepted_count} 项结果。当前仍有 {progress.goals_open} 个场景/分目标正在继续自动解题中，后续进展会在此处更新。
              </p>
            )}
            {progress.phase === "confirmed" && (
              <p className="text-sm text-muted-foreground">
                {progress.task_status === "done"
                  ? "验收已通过，任务已结束，可下载 Write-up。"
                  : "已有已确认结果。若全部验收步骤都已在平台通过，可结束任务；否则请继续推进下一阶段。"}
              </p>
            )}
            {progress.phase === "stopped" && <p className="text-sm text-muted-foreground">本次执行已停止，当前输入尚无已确认验收结果；已有日志与阶段 WP 会保留。</p>}
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
            {verifyMode === "exploit_proof"
              ? "本题采用「漏洞利用证明（无需 Flag）」验收：当智能体完成目标漏洞利用（或你确认在赛题平台点击「验证漏洞利用」已通过）后，确认下方证明或直接一键完成任务即可，无需找不存在的 flag{...}。"
              : verifyMode === "flag_and_exploit"
              ? "本题采用「复合验收（先 Flag 后漏洞利用证明）」：先确认第 1 阶段 Flag 正确并继续第 2 阶段；完成第 2 阶段漏洞利用并在平台验证通过后，再结束整题。"
              : (progress?.goals_total ?? 0) > 1
              ? "多场景/多 Flag 题目：验证通过后请点击「确认此 Flag，继续剩余目标」，系统会自动锁定该场景 Flag 并继续攻关后续场景；仅在全部场景做完或准备收尾时才选择「结束整题」。"
              : "核对平台结果后，单题可直接「验证正确并完成任务」。多 Flag 或仍有其他交付时，选择「仅确认，保留其他目标」。完成任务会停止剩余自动意图，并将未继续执行的目标注明为放弃；旧输入候选不能确认。"}
          </p>
          {showDirectExploitComplete && (
            <div className="space-y-2.5 rounded-md border border-indigo-500/30 bg-indigo-500/5 p-3">
              <div className="space-y-1">
                <p className="text-sm font-medium">
                  {verifyMode === "flag_and_exploit" ? "阶段 2：平台漏洞利用验证收尾" : "平台漏洞利用验证通过，一键结束任务"}
                </p>
                <p className="text-xs text-muted-foreground">
                  若智能体已实质达成题干效果且你已在赛题平台点击「验证漏洞利用」通过，无需等待额外 Flag，可直接在此确认并生成完整 WP。
                </p>
              </div>
              <Textarea
                aria-label="漏洞利用证明摘要（可选）"
                placeholder="可选：简要说明已达成的利用效果（默认：已在赛题平台完成漏洞利用验证），例如：已越权写入 /data/pwned_proof.txt 并保留"
                value={proofSummary}
                onChange={(e) => setProofSummary(e.target.value)}
                rows={2}
              />
              <Textarea
                aria-label="平台验证备注（可选）"
                placeholder="可选：补充平台验证细节、响应截图说明或持久化确认记录"
                value={proofNotes}
                onChange={(e) => setProofNotes(e.target.value)}
                rows={2}
              />
              <Button size="sm" disabled={busy} onClick={() => void handleCompleteExploit()}>
                <CheckIcon />
                确认已在平台验证通过，完成任务并生成 WP
              </Button>
            </div>
          )}
          {candidates.length ? (
            candidates.map((c) => (
              <Candidate
                key={`${c.id}-${c.revision}`}
                candidate={c}
                busy={busy}
                decide={decide}
                completed={progress?.task_status === "done"}
                isMultiGoal={(progress?.goals_total ?? 0) > 1 && (progress?.goals_open ?? 0) > 0}
                verifyMode={verifyMode}
                proofConfirmedCount={progress?.accepted_proof_count ?? 0}
              />
            ))
          ) : !showDirectExploitComplete ? (
            <p className="text-sm text-muted-foreground">尚无候选答案。可以先查看阶段 WP 和执行记录。</p>
          ) : null}
        </CardContent>
      </Card>
      <Tabs defaultValue="wp" className="space-y-3">
        <TabsList>
          <TabsTrigger value="wp">解题报告（Write-up）</TabsTrigger>
          <TabsTrigger value="executions">原始执行记录 ({executions.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="wp">
          <Card>
            <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
              <CardTitle className="text-sm">解题报告（Write-up）</CardTitle>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  variant={wp?.is_optimized ? "outline" : "default"}
                  className={wp?.is_optimized ? "border-amber-500/40 text-amber-600 dark:text-amber-400" : "bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 text-white shadow-sm"}
                  disabled={busy || optimizing}
                  onClick={handleOptimizeWP}
                >
                  <SparklesIcon className={`size-3.5 ${optimizing ? "animate-spin" : ""}`} />
                  {optimizing ? "正在精炼梳理…" : "AI 精炼 WP"}
                </Button>
                {wp?.is_optimized && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy || optimizing}
                    onClick={handleResetWP}
                  >
                    <RotateCcwIcon className="size-3.5" />
                    恢复标准版
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
                      AI 精炼 Write-up
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-0.5 text-xs text-muted-foreground">
                      标准结构化 Write-up
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
        </TabsContent>
        <TabsContent value="executions">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">原始执行记录（最近 100 次）</CardTitle>
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
        </TabsContent>
      </Tabs>
    </div>
  );
}
