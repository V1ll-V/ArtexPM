"use client";

import * as React from "react";

import { ScanSearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingRetest, FindingReviewScope } from "@/lib/types";

const FOCUS_OPTIONS = [
  { key: "evidence", label: "证据是否成立" },
  { key: "impact", label: "影响/严重级是否夸大" },
  { key: "exploitability", label: "利用条件是否成立" },
  { key: "environment", label: "版本/环境是否匹配" },
  { key: "scope", label: "目标是否在测试范围内" },
];

interface FindingReviewDialogProps {
  findingId: string;
  findingName?: string;
  onClose: () => void;
  onStarted?: (review: FindingRetest) => void;
}

// 复核条件对话框：默认只复核已有证据，需显式勾选才允许发新请求。
export function FindingReviewDialog({ findingId, findingName, onClose, onStarted }: FindingReviewDialogProps) {
  const feedbackId = React.useId();
  const forbiddenId = React.useId();
  const [feedback, setFeedback] = React.useState("");
  const [minimal, setMinimal] = React.useState(false);
  const [focus, setFocus] = React.useState<string[]>(["evidence"]);
  const [maxRequests, setMaxRequests] = React.useState(5);
  const [forbidden, setForbidden] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const submitLock = React.useRef(false);

  function toggleFocus(key: string) {
    setFocus((cur) => (cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key]));
  }

  async function start() {
    if (submitLock.current) return;
    submitLock.current = true;
    setSubmitting(true);
    try {
      const scope: FindingReviewScope = {
        mode: minimal ? "minimal_verification" : "evidence_only",
        focus,
        allow_network: minimal,
        max_requests: minimal ? maxRequests : 0,
        forbidden: minimal ? forbidden.trim() : "",
      };
      const result = await api.startFindingReview(findingId, feedback.trim(), scope);
      onStarted?.(result.review);
      onClose();
      toast.success(result.created ? "复核已启动，可点击「复核中」查看会话" : "该漏洞正在复核，可查看已有会话");
    } catch (e) {
      toast.error(`发起复核失败：${(e as Error).message}`);
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !submitLock.current && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>复核漏洞 #{findingId}</DialogTitle>
          <DialogDescription className="break-words">
            {findingName ? <span className="mb-2 block font-medium text-foreground">{findingName}</span> : null}
            复核 Agent 会重新核对原始证据，判断漏洞是否成立、是否被夸大。它只给建议，
            <span className="text-foreground">不会自动修改漏洞状态或严重等级</span>，最终由你确认。
          </DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Field data-disabled={submitting}>
            <FieldLabel htmlFor={feedbackId}>审查意见 / 疑点</FieldLabel>
            <Textarea
              id={feedbackId}
              value={feedback}
              maxLength={4000}
              rows={4}
              disabled={submitting}
              onChange={(e) => setFeedback(e.target.value)}
              placeholder="例如：返回 200 但页面没有回显，怀疑把状态码当成了注入成功；或影响面被夸大，实际需要管理员权限。"
            />
            <FieldDescription>说明你怀疑哪里不成立，复核会重点核对这条。</FieldDescription>
          </Field>

          <Field data-disabled={submitting}>
            <FieldLabel>复核方式</FieldLabel>
            <label htmlFor="review-minimal" className="flex items-start gap-2 text-sm">
              <Checkbox
                id="review-minimal"
                checked={minimal}
                disabled={submitting}
                onCheckedChange={(v) => setMinimal(v === true)}
                className="mt-0.5"
              />
              <span>
                允许按原 PoC 做最小化验证
                <span className="block text-muted-foreground text-xs">
                  默认关闭：只基于已有证据判断，不发起任何新请求。开启后会走记录代理留痕，并受下方限制约束。
                </span>
              </span>
            </label>
          </Field>

          {minimal ? (
            <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
              <Field data-disabled={submitting}>
                <FieldLabel htmlFor="review-max-requests">请求上限</FieldLabel>
                <Input
                  id="review-max-requests"
                  type="number"
                  min={1}
                  max={50}
                  value={maxRequests}
                  disabled={submitting}
                  onChange={(e) => setMaxRequests(Math.max(1, Math.min(50, Number(e.target.value) || 1)))}
                />
              </Field>
              <Field data-disabled={submitting}>
                <FieldLabel htmlFor={forbiddenId}>禁止的操作（可选）</FieldLabel>
                <Textarea
                  id={forbiddenId}
                  value={forbidden}
                  maxLength={2000}
                  rows={2}
                  disabled={submitting}
                  onChange={(e) => setForbidden(e.target.value)}
                  placeholder="例如：不要尝试写入文件、不要横向、不要跑扫描器。"
                />
              </Field>
            </div>
          ) : null}

          <Field data-disabled={submitting}>
            <FieldLabel>重点关注</FieldLabel>
            <div className="grid gap-2 sm:grid-cols-2">
              {FOCUS_OPTIONS.map((opt) => (
                <label key={opt.key} htmlFor={`focus-${opt.key}`} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    id={`focus-${opt.key}`}
                    checked={focus.includes(opt.key)}
                    disabled={submitting}
                    onCheckedChange={() => toggleFocus(opt.key)}
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" disabled={submitting} onClick={onClose}>
            取消
          </Button>
          <Button disabled={submitting} onClick={() => void start()}>
            {submitting ? <Spinner data-icon="inline-start" /> : <ScanSearchIcon data-icon="inline-start" />}
            {submitting ? "正在创建…" : "开始复核"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
