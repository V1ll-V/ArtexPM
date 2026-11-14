"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckIcon,
  FileTextIcon,
  NetworkIcon,
  RefreshCwIcon,
  ShieldIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { CTFVpnSummary } from "@/lib/types";

interface ParsedPreview {
  address: string;
  dns: string[];
  endpoint: string;
  allowedIPs: string[];
  keepalive?: number;
}

const MAX_CONF_BYTES = 64 * 1024;
const BLOCKED_KEYS = new Set(["preup", "postup", "predown", "postdown", "saveconfig", "table"]);

function parseWireGuardPreview(raw: string): { ok: true; preview: ParsedPreview } | { ok: false; error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, error: "配置内容为空" };
  if (new TextEncoder().encode(raw).length > MAX_CONF_BYTES) {
    return { ok: false, error: "配置文件超过 64 KiB 上限" };
  }

  let section = "";
  let hasPrivateKey = false;
  let hasPublicKey = false;
  const addresses: string[] = [];
  const dns: string[] = [];
  let endpoint = "";
  const allowedIPs: string[] = [];
  let keepalive: number | undefined;

  for (const rawLine of raw.replace(/\r\n/g, "\n").split("\n")) {
    const line = rawLine.replace(/[#;].*$/, "").trim();
    if (!line) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1).trim().toLowerCase();
      if (section !== "interface" && section !== "peer") {
        return { ok: false, error: `不支持的配置段 [${line.slice(1, -1)}]` };
      }
      continue;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) return { ok: false, error: `无效配置行：${line}` };
    const key = line.slice(0, eq).trim().toLowerCase();
    const val = line.slice(eq + 1).trim();
    if (!val) return { ok: false, error: `字段 ${key} 值为空` };
    if (BLOCKED_KEYS.has(key)) {
      return { ok: false, error: `出于安全策略禁止包含 ${key} 字段` };
    }
    if (section === "interface") {
      if (key === "privatekey") hasPrivateKey = true;
      else if (key === "address") addresses.push(...val.split(",").map((s) => s.trim()).filter(Boolean));
      else if (key === "dns") dns.push(...val.split(",").map((s) => s.trim()).filter(Boolean));
    } else if (section === "peer") {
      if (key === "publickey") hasPublicKey = true;
      else if (key === "endpoint") endpoint = val;
      else if (key === "allowedips") allowedIPs.push(...val.split(",").map((s) => s.trim()).filter(Boolean));
      else if (key === "persistentkeepalive") {
        const n = Number(val);
        if (Number.isFinite(n)) keepalive = n;
      }
    } else {
      return { ok: false, error: "配置行必须位于 [Interface] 或 [Peer] 段内" };
    }
  }

  if (!hasPrivateKey || addresses.length === 0) {
    return { ok: false, error: "[Interface] 缺少 PrivateKey 或 Address" };
  }
  if (!hasPublicKey || !endpoint || allowedIPs.length === 0) {
    return { ok: false, error: "[Peer] 缺少 PublicKey、Endpoint 或 AllowedIPs" };
  }
  return {
    ok: true,
    preview: {
      address: addresses.join(", "),
      dns,
      endpoint,
      allowedIPs,
      keepalive,
    },
  };
}

function formatBytes(n?: number): string {
  if (!n || n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1048576).toFixed(2)} MiB`;
}

export function CTFVpnConfig({
  taskId,
  draftValue,
  onDraftChange,
  readOnly = false,
  onUpdated,
}: {
  taskId?: string;
  draftValue?: { config: string; filename: string } | null;
  onDraftChange?: (next: { config: string; filename: string } | null) => void;
  readOnly?: boolean;
  onUpdated?: () => void;
}) {
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const [summary, setSummary] = React.useState<CTFVpnSummary | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [showPaste, setShowPaste] = React.useState(false);
  const [pasteText, setPasteText] = React.useState("");
  const [pasteName, setPasteName] = React.useState("wg0.conf");

  const loadSummary = React.useCallback(async () => {
    if (!taskId) return;
    setLoading(true);
    setError("");
    try {
      setSummary(await api.ctfVPN(taskId));
    } catch (e) {
      setError(e instanceof Error ? e.message : "读取 VPN 状态失败");
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    if (taskId) void loadSummary();
  }, [taskId, loadSummary]);

  async function handleFileSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const text = await file.text();
    const check = parseWireGuardPreview(text);
    if (!check.ok) {
      setError(check.error);
      toast.error(check.error);
      return;
    }
    setError("");
    if (!taskId) {
      onDraftChange?.({ config: text, filename: file.name || "wg0.conf" });
      toast.success(`已载入 VPN 配置 ${file.name}`);
      return;
    }
    setBusy(true);
    try {
      const next = await api.uploadCTFVPNFile(taskId, file);
      setSummary(next);
      onUpdated?.();
      if (next.sidecar?.error) {
        toast.warning(`配置已保存，但 Sidecar 启动存在异常：${next.sidecar.error}`);
      } else {
        toast.success(`已应用赛题 WireGuard VPN（${next.filename || file.name}）`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "上传失败";
      setError(msg);
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  async function handleSavePaste() {
    const check = parseWireGuardPreview(pasteText);
    if (!check.ok) {
      setError(check.error);
      toast.error(check.error);
      return;
    }
    setError("");
    const fname = pasteName.trim() || "wg0.conf";
    if (!taskId) {
      onDraftChange?.({ config: pasteText, filename: fname });
      setShowPaste(false);
      toast.success(`已暂存 VPN 配置 ${fname}`);
      return;
    }
    setBusy(true);
    try {
      const next = await api.saveCTFVPNText(taskId, fname, pasteText);
      setSummary(next);
      setShowPaste(false);
      setPasteText("");
      onUpdated?.();
      if (next.sidecar?.error) {
        toast.warning(`配置已保存，但 Sidecar 启动存在异常：${next.sidecar.error}`);
      } else {
        toast.success("WireGuard VPN 已更新并激活");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "保存失败";
      setError(msg);
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  async function handleCheckSidecar() {
    if (!taskId) return;
    setBusy(true);
    setError("");
    try {
      const next = await api.checkCTFVPN(taskId);
      setSummary(next);
      if (next.sidecar?.running) {
        toast.success("WireGuard Sidecar 容器运行正常");
      } else {
        toast.warning(next.sidecar?.error || "WireGuard Sidecar 未运行");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "检查失败";
      setError(msg);
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove() {
    setError("");
    if (!taskId) {
      onDraftChange?.(null);
      return;
    }
    setBusy(true);
    try {
      const next = await api.deleteCTFVPN(taskId);
      setSummary(next);
      onUpdated?.();
      toast.success("已移除本任务的 WireGuard VPN 配置");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "移除失败";
      setError(msg);
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  // Draft UI inside "Create Task" sheet.
  if (!taskId) {
    const parsed = draftValue?.config ? parseWireGuardPreview(draftValue.config) : null;
    return (
      <div className="space-y-2.5 rounded-lg border bg-muted/20 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-sm font-medium">
            <NetworkIcon className="size-4 text-primary" />
            赛题专属 WireGuard VPN（可选）
            {draftValue?.config && (
              <Badge variant="secondary" className="text-[11px]">
                已选择：{draftValue.filename || "wg0.conf"}
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <input
              ref={fileInputRef}
              type="file"
              accept=".conf,.txt,text/plain"
              className="hidden"
              onChange={handleFileSelected}
            />
            <Button type="button" size="xs" variant="outline" onClick={() => fileInputRef.current?.click()}>
              <UploadIcon className="size-3.5" />
              选择 .conf 文件
            </Button>
            <Button type="button" size="xs" variant="ghost" onClick={() => setShowPaste((v) => !v)}>
              <FileTextIcon className="size-3.5" />
              {showPaste ? "收起粘贴" : "粘贴配置"}
            </Button>
            {draftValue?.config && (
              <Button type="button" size="xs" variant="ghost" onClick={handleRemove}>
                <Trash2Icon className="size-3.5" />
                清除
              </Button>
            )}
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          面向需要 VPN 接入的赛题（如 TPCTF 提供的 <code className="rounded bg-muted px-1">ctfy-*.conf</code>）：每个任务启动独立 WireGuard Sidecar 容器直连内网域名（<code className="rounded bg-muted px-1">*.internal</code>）与 <code className="rounded bg-muted px-1">ctfy-callback</code>，宿主机零代理、多题并行互不冲突。
        </p>
        {parsed && parsed.ok && (
          <div className="grid gap-1 rounded-md border bg-background px-2.5 py-2 text-xs sm:grid-cols-2">
            <div><span className="text-muted-foreground">隧道 IP：</span><code className="font-mono">{parsed.preview.address}</code></div>
            <div><span className="text-muted-foreground">对端节点：</span><code className="font-mono">{parsed.preview.endpoint}</code></div>
            <div><span className="text-muted-foreground">隧道 DNS：</span><code className="font-mono">{parsed.preview.dns.join(", ") || "默认"}</code></div>
            <div><span className="text-muted-foreground">允许网段：</span><code className="font-mono">{parsed.preview.allowedIPs.join(", ")}</code></div>
          </div>
        )}
        {showPaste && (
          <div className="space-y-2 rounded-md border bg-background p-2.5">
            <Textarea
              className="min-h-28 font-mono text-xs"
              placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 172.17.112.254/32&#10;DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8&#10;&#10;[Peer]&#10;PublicKey = ...&#10;Endpoint = node7.tpctf.ctfy.run:44749&#10;AllowedIPs = 172.17.112.0/24"
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
            />
            <div className="flex items-center justify-between gap-2">
              <input
                className="h-8 flex-1 rounded-md border bg-background px-2 text-xs"
                placeholder="文件名（默认 wg0.conf）"
                value={pasteName}
                onChange={(e) => setPasteName(e.target.value)}
              />
              <Button type="button" size="xs" onClick={handleSavePaste}>
                校验并暂存
              </Button>
            </div>
          </div>
        )}
        {error && <p className="text-xs text-destructive">{error}</p>}
      </div>
    );
  }

  // Task Detail management card.
  const enabled = Boolean(summary?.enabled);
  const sidecar = summary?.sidecar;
  const sidecarHealthy = Boolean(sidecar?.running && sidecar?.tunnel_ip);

  return (
    <Card className="mt-4">
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
        <div className="space-y-1">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            <NetworkIcon className="size-4" />
            赛题独立 WireGuard VPN 隧道
            {enabled ? (
              sidecarHealthy ? (
                <Badge className="bg-emerald-600 text-[11px] text-white">
                  <CheckIcon className="mr-1 size-3" />
                  隧道在线 ({sidecar?.tunnel_ip})
                </Badge>
              ) : (
                <Badge variant="outline" className="border-amber-500/60 text-[11px] text-amber-600">
                  {sidecar?.error ? "Sidecar 异常" : "已配置（待启动或检测）"}
                </Badge>
              )
            ) : (
              <Badge variant="secondary" className="text-[11px]">未配置（直连公共网）</Badge>
            )}
          </CardTitle>
          <CardDescription>
            上传题目专属 <code className="rounded bg-muted px-1">.conf</code> 后，本任务的 CTF 工具容器将通过独立命名空间的 WireGuard Sidecar 容器直连题目内网（多任务同网段并行互不冲突，宿主机无需配置任何代理）。
          </CardDescription>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <input
            ref={fileInputRef}
            type="file"
            accept=".conf,.txt,text/plain"
            className="hidden"
            onChange={handleFileSelected}
          />
          {!readOnly && (
            <>
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onClick={() => fileInputRef.current?.click()}
              >
                <UploadIcon />
                {enabled ? "更换 .conf" : "上传 .conf"}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                onClick={() => setShowPaste((v) => !v)}
              >
                <FileTextIcon />
                {showPaste ? "收起粘贴" : "粘贴文本"}
              </Button>
            </>
          )}
          {enabled && (
            <Button
              size="sm"
              variant="outline"
              disabled={busy || loading}
              onClick={handleCheckSidecar}
            >
              <RefreshCwIcon className={busy || loading ? "animate-spin" : ""} />
              检查 / 拉起隧道
            </Button>
          )}
          {enabled && !readOnly && (
            <Button size="sm" variant="ghost" disabled={busy} onClick={handleRemove}>
              <Trash2Icon />
              移除 VPN
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-3 text-sm">
        {enabled && summary && (
          <div className="grid gap-2 rounded-md border bg-muted/20 p-3 text-xs sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <span className="text-muted-foreground">配置文件：</span>
              <span className="font-mono font-medium">{summary.filename || "wg0.conf"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">隧道地址：</span>
              <code className="font-mono">{summary.address}</code>
            </div>
            <div>
              <span className="text-muted-foreground">对端 Endpoint：</span>
              <code className="font-mono">{summary.endpoint}</code>
            </div>
            <div>
              <span className="text-muted-foreground">隧道 DNS：</span>
              <code className="font-mono">{summary.dns?.join(", ") || "—"}</code>
            </div>
            <div>
              <span className="text-muted-foreground">路由网段：</span>
              <code className="font-mono">{summary.allowed_ips?.join(", ")}</code>
            </div>
            <div>
              <span className="text-muted-foreground">摘要指纹：</span>
              <code className="font-mono">{summary.hash?.slice(0, 16)}…</code>
            </div>
            {sidecar && (
              <>
                <div>
                  <span className="text-muted-foreground">Sidecar 容器：</span>
                  <code className="font-mono">{sidecar.container || "—"}</code>
                </div>
                <div>
                  <span className="text-muted-foreground">握手状态：</span>
                  <span>
                    {sidecar.handshake_at
                      ? `${sidecar.handshake_age_sec ?? 0}s 前 (${formatBytes(sidecar.rx_bytes)}↓ / ${formatBytes(sidecar.tx_bytes)}↑)`
                      : sidecar.running
                        ? "隧道就绪（首次访问内网时握手）"
                        : "未启动"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">容器 DNS：</span>
                  <code className="font-mono">{sidecar.dns || "—"}</code>
                </div>
              </>
            )}
          </div>
        )}

        {sidecar?.error && (
          <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-700 dark:text-amber-300">
            <AlertTriangleIcon className="mt-0.5 size-4 shrink-0" />
            <span className="break-all">{sidecar.error}</span>
          </div>
        )}

        {showPaste && !readOnly && (
          <div className="space-y-2 rounded-md border p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <ShieldIcon className="size-3.5" />
              仅允许标准 WireGuard 客户端字段（PrivateKey / Address / DNS / PublicKey / Endpoint / AllowedIPs / PersistentKeepalive）；PrivateKey 仅用于启动隔离容器，不向页面回传。
            </div>
            <Textarea
              className="min-h-32 font-mono text-xs"
              placeholder="粘贴 WireGuard .conf 全文…"
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
            />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <input
                className="h-8 min-w-48 flex-1 rounded-md border bg-background px-2.5 text-xs"
                placeholder="文件名（如 ctfy-40099377a2.conf）"
                value={pasteName}
                onChange={(e) => setPasteName(e.target.value)}
              />
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" onClick={() => setShowPaste(false)}>
                  取消
                </Button>
                <Button size="sm" disabled={busy} onClick={handleSavePaste}>
                  保存并拉起隧道
                </Button>
              </div>
            </div>
          </div>
        )}

        {error && <p className="text-xs text-destructive">{error}</p>}
      </CardContent>
    </Card>
  );
}
