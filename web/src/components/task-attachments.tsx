"use client";

import * as React from "react";

import { DownloadIcon, FileArchiveIcon, Loader2Icon, PaperclipIcon, RefreshCwIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { ArtifactManifest, TaskArtifact } from "@/lib/types";

const roles: [TaskArtifact["role"], string][] = [
  ["attachment", "附件"],
  ["binary", "主程序"],
  ["libc", "libc"],
  ["loader", "Loader"],
  ["source", "源码"],
  ["input", "输入文件"],
];

function bytes(size: number) {
  if (size < 1024) return `${size} B`;
  return size >= 1048576 ? `${(size / 1048576).toFixed(1)} MiB` : `${(size / 1024).toFixed(1)} KiB`;
}

function artifactBase(taskId: string | undefined, draftId: string): string {
  if (taskId) return `/tasks/${encodeURIComponent(taskId)}/artifacts`;
  if (draftId) return `/task-upload-drafts/${encodeURIComponent(draftId)}/files`;
  return "";
}

export function TaskAttachments({
  taskId,
  draftId = "",
  onDraftChange,
  onBusyChange,
  readOnly = false,
}: {
  taskId?: string;
  draftId?: string;
  onDraftChange?: (id: string) => void;
  onBusyChange?: (busy: boolean) => void;
  readOnly?: boolean;
}) {
  const [manifest, setManifest] = React.useState<ArtifactManifest>({ files: [], revision: 0 });
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const input = React.useRef<HTMLInputElement>(null);
  const operation = React.useRef(false);
  const requestEpoch = React.useRef(0);
  const base = artifactBase(taskId, draftId);

  React.useEffect(() => {
    if (operation.current) return;
    let current = true;
    const epoch = requestEpoch.current;
    setError("");
    if (!base) {
      setManifest({ files: [], revision: 0 });
      return;
    }
    api
      .artifacts(base)
      .then((value) => {
        if (current && epoch === requestEpoch.current && !operation.current) setManifest(value);
      })
      .catch((e) => {
        if (current && epoch === requestEpoch.current) setError((e as Error).message);
      });
    return () => {
      current = false;
    };
  }, [base]);

  async function run(work: () => Promise<ArtifactManifest>) {
    if (operation.current) return;
    requestEpoch.current += 1;
    operation.current = true;
    setBusy(true);
    onBusyChange?.(true);
    setError("");
    try {
      setManifest(await work());
    } catch (e) {
      setError((e as Error).message);
      // Multipart requests may have saved earlier files before a later failure.
      if (base) {
        try {
          setManifest(await api.artifacts(base));
        } catch {
          /* keep the visible error */
        }
      }
    } finally {
      operation.current = false;
      setBusy(false);
      onBusyChange?.(false);
    }
  }

  async function upload(files: File[]) {
    if (!files.length || readOnly) return;
    if (
      files.length > 32 ||
      files.some((f) => f.size > 64 * 1048576) ||
      files.reduce((n, f) => n + f.size, 0) > 120 * 1048576
    ) {
      setError("每次最多 32 个文件，单文件不超过 64 MiB，每批文件总量不超过 120 MiB。");
      return;
    }
    await run(async () => {
      let target = base;
      if (!target) {
        const draft = await api.createArtifactDraft();
        onDraftChange?.(draft.id);
        target = `/task-upload-drafts/${draft.id}/files`;
      }
      try {
        return await api.uploadArtifacts(target, files);
      } catch (e) {
        setManifest(await api.artifacts(target));
        throw e;
      }
    });
    if (input.current) input.current.value = "";
  }

  async function download(file: TaskArtifact) {
    if (!taskId) return;
    try {
      const blob = await api.downloadArtifact(taskId, file.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = file.name.split("/").pop() || file.name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  return (
    <div className="space-y-3">
      {!readOnly && (
        <section
          aria-label="附件上传区"
          className="rounded-lg border border-dashed p-4"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            if (!busy) void upload(Array.from(e.dataTransfer.files));
          }}
        >
          <input
            ref={input}
            type="file"
            multiple
            className="hidden"
            aria-label="选择题目附件"
            onChange={(e) => void upload(Array.from(e.target.files ?? []))}
          />
          <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => input.current?.click()}>
            {busy ? <Loader2Icon className="animate-spin" /> : <PaperclipIcon />} 上传附件
          </Button>
          <p className="mt-2 text-muted-foreground text-xs">
            支持拖拽、多文件和 ZIP；可上传主程序、libc、Loader、源码及输入文件。单文件最大 64 MiB。
          </p>
        </section>
      )}
      {error && (
        <p role="alert" className="break-all text-destructive text-sm">
          {error}
        </p>
      )}
      {manifest.blocked_reason && (
        <div role="alert" className="space-y-2 rounded-lg border p-3 text-sm">
          <p>{manifest.blocked_reason}</p>
          {taskId && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => void run(() => api.retryArtifactBind(taskId))}
            >
              <RefreshCwIcon /> 重试附件绑定
            </Button>
          )}
        </div>
      )}
      {manifest.files.length === 0 ? (
        <p className="text-muted-foreground text-sm">暂无附件</p>
      ) : (
        <ul className="space-y-2">
          {manifest.files.map((file) => (
            <li key={file.id} className="min-w-0 rounded-lg border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="min-w-0 flex-1 break-all font-medium text-sm">
                  {file.parent_id ? "↳ " : ""}
                  {file.name}
                </span>
                <select
                  aria-label={`${file.name} 的用途`}
                  className="rounded border bg-background px-2 py-1 text-xs"
                  value={file.role}
                  disabled={busy || readOnly}
                  onChange={(e) =>
                    void run(() => api.editArtifact(base, file.id, e.target.value as TaskArtifact["role"]))
                  }
                >
                  {roles.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
                {file.analysis.format === "ZIP" && !readOnly && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={busy}
                    onClick={() => void run(() => api.extractArtifact(base, file.id))}
                  >
                    <FileArchiveIcon /> 解压
                  </Button>
                )}
                {taskId && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => void download(file)}
                    aria-label={`下载 ${file.name}`}
                  >
                    <DownloadIcon />
                  </Button>
                )}
                {!taskId && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={busy}
                    aria-label={`移除 ${file.name}`}
                    onClick={() => void run(() => api.editArtifact(base, file.id, file.role, true))}
                  >
                    <XIcon />
                  </Button>
                )}
              </div>
              <p className="mt-1 break-all text-muted-foreground text-xs">
                {bytes(file.size)} ·{" "}
                {[
                  file.analysis.format,
                  file.analysis.architecture,
                  file.analysis.bits ? `${file.analysis.bits} 位` : "",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
              <p className="mt-1 break-all font-mono text-muted-foreground text-xs" title={file.sha256}>
                SHA-256: {file.sha256}
              </p>
              {file.analysis.error && (
                <p className="mt-1 break-all text-destructive text-xs">识别未完成：{file.analysis.error}</p>
              )}
            </li>
          ))}
        </ul>
      )}
      {manifest.revision > 0 && (
        <p className="text-muted-foreground text-xs">
          输入版本 {manifest.revision} · {manifest.files.length}{" "}
          个文件。正在执行的意图保留原输入版本，新文件用于后续意图。
        </p>
      )}
    </div>
  );
}
