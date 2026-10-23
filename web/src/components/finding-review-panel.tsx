"use client";

import * as React from "react";

import Link from "next/link";

import { ScanSearchIcon } from "lucide-react";
import { toast } from "sonner";

import { FindingReviewDialog } from "@/components/finding-review-dialog";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  FindingRetest,
  FindingReviewConfidence,
  FindingReviewDecision,
  FindingReviewDecisionInfo,
  Severity,
} from "@/lib/types";

const runStatusLabels: Record<string, string> = {
  pending: "等待启动",
  running: "复核中",
  completed: "已完成",
  failed: "复核失败",
  stopped: "已停止",
};

const confidenceLabels: Record<FindingReviewConfidence, string> = {
  "": "",
  low: "低",
  medium: "中",
  high: "高",
};

const decisionOptions: { value: FindingReviewDecision; label: string }[] = [
  { value: "", label: "未复核" },
  { value: "confirmed", label: "成立" },
  { value: "false_positive", label: "误报" },
  { value: "exaggerated", label: "夸大" },
  { value: "inconclusive", label: "无法确认" },
];

const severityOptions: { value: Severity; label: string }[] = [
  { value: "critical", label: "严重" },
  { value: "high", label: "高危" },
  { value: "medium", label: "中危" },
  { value: "low", label: "低危" },
];

function activeRun(r: FindingRetest) {
  return r.status === "pending" || r.status === "running";
}

function fmtTime(ts?: string | null) {
  return ts ? new Date(ts).toLocaleString("zh-CN") : "";
}

export function FindingReviewPanel({
  findingId,
  findingName,
  inherited = false,
  onChanged,
}: {
  findingId: string;
  findingName?: string;
  inherited?: boolean;
  onChanged?: () => void;
}) {
  const [data, setData] = React.useState<{
    reviews: FindingRetest[];
    decision: FindingReviewDecisionInfo;
  } | null>(null);
  const [error, setError] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const [deciding, setDeciding] = React.useState(false);
  const [decision, setDecision] = React.useState<FindingReviewDecision>("");
  const [note, setNote] = React.useState("");
  const [applyStatus, setApplyStatus] = React.useState(false);
  const [severity, setSeverity] = React.useState<Severity>("medium");
  const [saving, setSaving] = React.useState(false);
  const requestSeq = React.useRef(0);

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const result = await api.findingReviews(findingId);
      if (seq !== requestSeq.current) return;
      setData(result);
      setError("");
    } catch (e) {
      if (seq === requestSeq.current) setError((e as Error).message);
    }
  }, [findingId]);

  React.useEffect(() => {
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const running = data?.reviews.find(activeRun);
  React.useEffect(() => {
    if (error || !running) return;
    const timer = setTimeout(() => void load(), 3000);
    return () => clearTimeout(timer);
  }, [error, running, load]);

  const decided = data?.decision.review_decision ?? "";
  const latest = data?.reviews.find((r) => r.status === "completed" && r.verdict);

  function openDecision() {
    const baseDecision = (decided || latest?.verdict || "") as FindingReviewDecision;
    setDecision(baseDecision);
    setNote(data?.decision.review_note || latest?.summary || "");
    setApplyStatus(baseDecision === "false_positive" || baseDecision === "confirmed");
    if (latest?.recommended_severity) setSeverity(latest.recommended_severity);
    setDeciding(true);
  }

  async function saveDecision() {
    if (saving) return;
    setSaving(true);
    try {
      await api.decideFindingReview(findingId, {
        decision,
        note: note.trim(),
        apply_status: applyStatus && (decision === "false_positive" || decision === "confirmed"),
        severity: decision === "exaggerated" ? severity : undefined,
        run_id: latest?.id,
      });
      toast.success("复核判定已保存");
      setDeciding(false);
      await load();
      onChanged?.();
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1.5">
          <CardTitle>人工复核</CardTitle>
          <CardDescription>
            人工审查后判断漏洞是否误报/夸大。复核 Agent 只给建议，状态与严重等级由你确认后手动保存。
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          {running?.conversation_id != null ? (
            <Button asChild variant="outline" size="sm">
              <Link href={`/chat?c=${running.conversation_id}`} title="查看正在进行的复核会话">
                <Spinner data-icon="inline-start" aria-hidden="true" />
                复核中
              </Link>
            </Button>
          ) : null}
          {!running && !inherited ? (
            <Button size="sm" onClick={() => setOpen(true)} disabled={data === null || !!error}>
              <ScanSearchIcon data-icon="inline-start" />
              发起复核
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>
              加载复核记录失败：{error}
              <Button variant="outline" size="sm" onClick={() => void load()}>
                重试
              </Button>
            </AlertDescription>
          </Alert>
        ) : null}
        {!error && data === null ? <Skeleton className="h-16 w-full" /> : null}

        {!error && data ? (
          <div className="flex flex-col gap-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium">人工判定</span>
              {decided ? (
                <StatusBadge domain="review" value={decided} dot />
              ) : (
                <span className="text-muted-foreground text-xs">尚未记录</span>
              )}
              {data.decision.reviewed_at ? (
                <span className="text-muted-foreground text-xs">{fmtTime(data.decision.reviewed_at)}</span>
              ) : null}
              {!inherited ? (
                <Button variant="ghost" size="sm" className="ml-auto" onClick={openDecision}>
                  {decided ? "修改判定" : "记录判定"}
                </Button>
              ) : null}
            </div>
            {decided && data.decision.review_note ? (
              <p className="whitespace-pre-wrap break-words text-sm">{data.decision.review_note}</p>
            ) : null}
            {deciding ? (
              <FieldGroup className="mt-1 border-t pt-3">
                <Field>
                  <FieldLabel>复核结论</FieldLabel>
                  <Select
                    value={decision || "none"}
                    onValueChange={(v) => setDecision(v === "none" ? "" : (v as FindingReviewDecision))}
                  >
                    <SelectTrigger size="sm" className="w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent position="popper">
                      <SelectGroup>
                        {decisionOptions.map((opt) => (
                          <SelectItem key={opt.value || "none"} value={opt.value || "none"}>
                            {opt.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>
                {decision === "exaggerated" ? (
                  <Field>
                    <FieldLabel>调整为严重等级</FieldLabel>
                    <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                      <SelectTrigger size="sm" className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent position="popper">
                        <SelectGroup>
                          {severityOptions.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>
                              {opt.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                ) : null}
                <Field>
                  <FieldLabel>备注</FieldLabel>
                  <Textarea
                    value={note}
                    rows={3}
                    maxLength={8000}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="写下你的判断依据，保存后会进入漏洞详情与导出报告。"
                  />
                </Field>
                {decision === "false_positive" || decision === "confirmed" ? (
                  <label htmlFor="review-apply-status" className="flex items-center gap-2 text-sm">
                    <Checkbox
                      id="review-apply-status"
                      checked={applyStatus}
                      onCheckedChange={(v) => setApplyStatus(v === true)}
                    />
                    同时把处置状态改为「{decision === "false_positive" ? "误报" : "已确认"}」
                  </label>
                ) : null}
                <div className="flex items-center gap-2">
                  <Button size="sm" disabled={saving} onClick={() => void saveDecision()}>
                    {saving ? <Spinner data-icon="inline-start" /> : null}
                    保存判定
                  </Button>
                  <Button size="sm" variant="ghost" disabled={saving} onClick={() => setDeciding(false)}>
                    取消
                  </Button>
                </div>
              </FieldGroup>
            ) : null}
          </div>
        ) : null}

        {!error && data && data.reviews.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>暂无复核记录</EmptyTitle>
              <EmptyDescription>发现误报或影响被夸大时，可发起复核并写明疑点。</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : null}

        {!error && data
          ? data.reviews.map((item) => (
              <div key={item.id} className="flex min-w-0 flex-col gap-2 rounded-lg border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  {item.status === "completed" && item.verdict ? (
                    <StatusBadge domain="review" value={item.verdict} dot />
                  ) : (
                    <span className="rounded-md border px-2 py-0.5 text-xs">{runStatusLabels[item.status]}</span>
                  )}
                  {item.status === "completed" && item.confidence ? (
                    <span className="text-muted-foreground text-xs">置信度：{confidenceLabels[item.confidence]}</span>
                  ) : null}
                  <span className="text-muted-foreground text-xs">
                    #{item.id} · {fmtTime(item.created_at)}
                  </span>
                  {item.conversation_id != null ? (
                    <Button asChild variant="ghost" size="sm" className="ml-auto">
                      <Link href={`/chat?c=${item.conversation_id}`}>查看会话</Link>
                    </Button>
                  ) : (
                    <span className="ml-auto text-muted-foreground text-xs">会话已删除</span>
                  )}
                </div>
                {item.feedback ? (
                  <p className="whitespace-pre-wrap break-words text-muted-foreground text-xs">
                    审查意见：{item.feedback}
                  </p>
                ) : null}
                {item.status === "completed" && item.summary ? (
                  <p className="whitespace-pre-wrap break-words text-sm">{item.summary}</p>
                ) : null}
                {item.recommended_severity || item.recommended_status ? (
                  <p className="text-xs">
                    建议：
                    {item.recommended_severity ? (
                      <StatusBadge domain="severity" value={item.recommended_severity} className="mx-1" />
                    ) : null}
                    {item.recommended_status ? (
                      <StatusBadge domain="finding" value={item.recommended_status} className="mx-1" />
                    ) : null}
                  </p>
                ) : null}
                {item.error ? (
                  <p className="whitespace-pre-wrap break-words text-destructive text-sm">{item.error}</p>
                ) : null}
                {item.status === "completed" && item.evidence ? (
                  <details className="min-w-0">
                    <summary className="cursor-pointer text-sm">复核证据</summary>
                    <div className="mt-3 overflow-x-auto">
                      <Markdown text={item.evidence} />
                    </div>
                  </details>
                ) : null}
                {item.status === "completed" && item.revised_report ? (
                  <details className="min-w-0">
                    <summary className="flex cursor-pointer flex-wrap items-center gap-2 text-sm">
                      修订后报告
                      <span className="text-muted-foreground text-xs">复核建议的完整修订版，未覆盖原报告</span>
                    </summary>
                    <div className="mt-3 overflow-x-auto rounded-md border bg-muted/30 p-3">
                      <Markdown text={item.revised_report} />
                    </div>
                  </details>
                ) : null}
              </div>
            ))
          : null}
      </CardContent>
      {open ? (
        <FindingReviewDialog
          findingId={findingId}
          findingName={findingName}
          onClose={() => setOpen(false)}
          onStarted={() => {
            setOpen(false);
            void load();
          }}
        />
      ) : null}
    </Card>
  );
}
