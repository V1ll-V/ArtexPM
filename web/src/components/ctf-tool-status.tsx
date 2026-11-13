"use client";

import * as React from "react";

import { RefreshCwIcon, WrenchIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { CTFToolStatus } from "@/lib/types";

export function CTFToolStatusCard() {
  const [status, setStatus] = React.useState<CTFToolStatus>();
  const [loading, setLoading] = React.useState(false);
  async function refresh() {
    setLoading(true);
    try {
      setStatus(await api.ctfTools());
    } catch (e) {
      setStatus({ ok: false, error: e instanceof Error ? e.message : "检查失败", tools: [] });
    } finally {
      setLoading(false);
    }
  }
  return (
    <Card className="mt-4">
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <WrenchIcon className="size-4" />
          CTF 解题工具环境（Pwn / RE / Crypto / Forensics）
        </CardTitle>
        <Button size="sm" variant="outline" disabled={loading} onClick={refresh}>
          <RefreshCwIcon className={loading ? "animate-spin" : ""} />
          {loading ? "检查中…" : "检查实际环境"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Pwn / RE（GDB、pwntools、Ghidra、radare2、angr/Z3 等） · 密码学（PyCryptodome、gmpy2、sympy 等） · 取证与隐写（binwalk、tshark、exiftool、steghide 等）。检查会启动独立容器确认可用性。
        </p>
        {status && (
          <>
            <p className={status.ok ? "text-emerald-600" : "text-amber-600"}>
              {status.ok ? "全部检查通过" : status.error || "部分工具未就绪，请查看详情"}
            </p>
            {status.image && (
              <p className="break-all font-mono text-xs text-muted-foreground">
                {status.image} · {status.checked_at && new Date(status.checked_at).toLocaleString()}
              </p>
            )}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {status.tools?.map((t) => (
                <details className="rounded-md border p-3" key={`${t.group}-${t.name}`}>
                  <summary className="cursor-pointer text-xs">
                    <span className={t.ready ? "text-emerald-600" : "text-destructive"}>{t.ready ? "✓" : "✕"}</span>{" "}
                    {t.name} <span className="text-muted-foreground">{t.group}</span>
                  </summary>
                  <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-all text-xs">
                    {t.version || t.error}
                  </pre>
                </details>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
