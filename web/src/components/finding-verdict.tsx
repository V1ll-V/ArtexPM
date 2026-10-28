import { Badge } from "@/components/ui/badge";
import type { Finding } from "@/lib/types";

export function FindingVerdictBadge({ finding }: { finding: Finding }) {
  let label = "候选 · 待验收";
  if (finding.effective) label = "当前验收有效";
  else if (finding.technical_verdict === "refuted") label = "已否定";
  else if (finding.verdict_stale) label = "判定已过期";
  else if (finding.technical_verdict === "needs_review") label = "需要复核";
  return <Badge variant={finding.effective ? "default" : "outline"}>{label}</Badge>;
}

export function FindingVerdictScope({ finding }: { finding: Finding }) {
  return (
    <div className="space-y-2 rounded-md border p-3 text-sm">
      <FindingVerdictBadge finding={finding} />
      <p className="whitespace-pre-wrap">{finding.display_claim ?? finding.summary}</p>
      {finding.effective && finding.accepted_detail?.preconditions?.length ? (
        <div>
          <p className="text-muted-foreground">适用前提</p>
          <ul className="list-disc pl-5">
            {Array.from(new Set(finding.accepted_detail.preconditions)).map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {finding.effective && finding.accepted_detail?.evidence_note ? (
        <p>{finding.accepted_detail.evidence_note}</p>
      ) : null}
      {finding.effective && finding.proposed_claim && finding.proposed_claim !== finding.accepted_claim ? (
        <details>
          <summary className="cursor-pointer text-muted-foreground">原始候选主张</summary>
          <p className="whitespace-pre-wrap">{finding.proposed_claim}</p>
        </details>
      ) : null}
      {finding.verdict_detail?.missing_evidence?.length ? (
        <div>
          <p className="text-muted-foreground">{finding.verdict_stale ? "历史验收提出的证据缺口" : "需补齐的证据"}</p>
          <ul className="list-disc pl-5">
            {Array.from(new Set(finding.verdict_detail.missing_evidence)).map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {finding.verdict_detail?.unsupported_claims?.length ? (
        <div>
          <p className="text-muted-foreground">未获支持的主张</p>
          <ul className="list-disc pl-5">
            {Array.from(new Set(finding.verdict_detail.unsupported_claims)).map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {!finding.effective ? (
        <p className="text-muted-foreground text-xs">该记录不能作为当前确认漏洞或目标完成的依据。处置状态独立保存。</p>
      ) : null}
      {finding.legacy_source ? (
        <p className="text-muted-foreground text-xs">历史记录，当前有效性以本次验收状态为准。</p>
      ) : null}
    </div>
  );
}
