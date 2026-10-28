"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { http } from "@/lib/api";
type Readiness = { enabled: boolean; ready_for_production: boolean; checks: {ready:boolean; reason?:string}[] };
export function TaskExecutionNotice() {
 const [reason, setReason] = useState<string | null>(null);
 useEffect(() => {
  let active = true;
  const refresh = async () => {
   try {
    const state = await http<Readiness>("/verification/readiness");
    if (active) setReason(state.ready_for_production ? null : !state.enabled
     ? "候选验收联动流程尚未启用。任务可以保存，但不会自动执行；请先完成启用检查。"
     : state.checks.filter(c => !c.ready).map(c => c.reason).filter(Boolean).join("；") || "运行配置尚未就绪。");
   } catch { if (active) setReason("暂时无法检查运行条件，请检查服务连接后重试。"); }
  };
  void refresh(); const timer = window.setInterval(refresh, 10000);
  window.addEventListener("focus", refresh);
  return () => { active = false; window.clearInterval(timer); window.removeEventListener("focus", refresh); };
 }, []);
 if (!reason) return null;
 return <Alert className="m-4 w-auto" role="status"><AlertTitle>任务尚不能启动</AlertTitle><AlertDescription>{reason}<Link href="/system/verification" className="font-medium underline">前往候选验收检查</Link></AlertDescription></Alert>;
}
