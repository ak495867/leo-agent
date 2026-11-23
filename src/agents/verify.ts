import { callJsonAgent } from "../api/openrouter.js";
import { LeoConfig } from "../utils/config.js";
import { AuditFinding, AuditReport } from "./audit.js";

export interface VerificationRecord { finding_id: string; disposition: "confirmed" | "rejected" | "needs_review"; confidence: number; rationale: string; evidence_checked: string[]; attacker_controlled_source?: string; propagation_path?: string[]; security_boundary?: string; exploitable_sink?: string; mitigations_reviewed?: string[]; }
export interface VerificationReport { records: VerificationRecord[]; }
const VERIFY_PROMPT = `You are Leo's independent security finding verifier. You did not author the findings. Challenge each claim adversarially and construct an evidence-backed vulnerability argument. For every candidate, independently check: (1) the attacker-controlled source and why it is attacker-controlled, (2) the exact propagation path through assignments/calls/returns, (3) the trust or security boundary crossed, (4) the concrete exploitable sink and its arguments, and (5) mitigations such as validation, allowlists, escaping, parameterization, authentication, or safe APIs. The supplied static-analysis path is a hypothesis, not proof. Inspect the source excerpts and reject unsupported links. Do not infer missing code or claim a sanitizer is safe without checking its context. Return JSON only: {"records":[{"finding_id":"...","disposition":"confirmed|rejected|needs_review","confidence":0.0,"rationale":"...","evidence_checked":["..."],"attacker_controlled_source":"...","propagation_path":["..."],"security_boundary":"...","exploitable_sink":"...","mitigations_reviewed":["..."]}]}. Reject only when evidence clearly disproves the finding. Use needs_review when context is insufficient. Never upgrade severity.`;

export async function verifyFindings(report: AuditReport, files: Record<string, string>, config: LeoConfig): Promise<AuditReport & { verification: VerificationReport }> {
  const records: VerificationRecord[] = [];
  for (let i = 0; i < report.findings.length; i += 12) {
    const batch = report.findings.slice(i, i + 12).map(f => {
      const source = files[f.file] ?? ""; const lines = source.split(/\r?\n/); const start = Math.max(1, f.line - 8); const end = Math.min(lines.length, f.line + 8);
      let sourceOrigins: string[] = []; let sourceFile = f.file;
      try { const parsed = JSON.parse(f.evidence ?? "{}"); sourceOrigins = Array.isArray(parsed.source_origins) ? parsed.source_origins.filter((x: unknown): x is string => typeof x === "string") : []; if (typeof parsed.source_file === "string" && Object.prototype.hasOwnProperty.call(files, parsed.source_file)) sourceFile = parsed.source_file; } catch { /* model-authored evidence may not be JSON */ }
      const sourceLines = (files[sourceFile] ?? "").split(/\r?\n/);
      const sourceExcerpts = sourceOrigins.map(origin => {
        const rawExpression = origin.replace(/^source:/, "");
        const lineMatch = rawExpression.match(/#L(\d+)$/);
        const expression = rawExpression.replace(/#L\d+$/, "");
        const lineIndex = lineMatch ? Number(lineMatch[1]) - 1 : sourceLines.findIndex(line => line.includes(expression));
        if (lineIndex < 0 || lineIndex >= sourceLines.length) return { origin, source_file: sourceFile, excerpt: "Source expression not located verbatim in snapshot; requires review." };
        const from = Math.max(0, lineIndex - 3); const to = Math.min(sourceLines.length, lineIndex + 4);
        return { origin, source_file: sourceFile, excerpt: sourceLines.slice(from, to).map((line, n) => `${from + n + 1}: ${line}`).join("\n") };
      });
      return { ...f, source_file: sourceFile, source_excerpt: lines.slice(start - 1, end).map((line, n) => `${start + n}: ${line}`).join("\n"), source_excerpts: sourceExcerpts, security_boundary_hint: /XSS/.test(f.category) ? "untrusted request data to browser DOM" : "untrusted input to privileged application operation" };
    });
    let result: VerificationReport | null = null;
    try { result = await callJsonAgent<VerificationReport>(VERIFY_PROMPT, JSON.stringify({ findings: batch }), config.default_model, config.openrouter_api_key); } catch { /* preserve candidates as needs_review on transport errors */ }
    const valid = new Map((result?.records ?? []).filter(r => batch.some(f => f.id === r.finding_id) && ["confirmed", "rejected", "needs_review"].includes(r.disposition) && Number.isFinite(r.confidence) && r.confidence >= 0 && r.confidence <= 1).map(r => [r.finding_id, r]));
    for (const f of batch) records.push(valid.get(f.id) ?? { finding_id: f.id, disposition: "needs_review", confidence: 0, rationale: "Independent verifier did not return a valid result; retained for human review.", evidence_checked: [] });
  }
  const byId = new Map(records.map(r => [r.finding_id, r]));
  const findings = report.findings.map(f => {
    const v = byId.get(f.id) ?? { finding_id: f.id, disposition: "needs_review" as const, confidence: 0, rationale: "No verifier record was returned.", evidence_checked: [] };
    return { ...f, verification: v.disposition, verification_confidence: v.confidence, verification_rationale: v.rationale } as AuditFinding;
  });
  const rejected = [...(report.rejected_findings ?? []), ...findings.filter(f => (f as any).verification === "rejected").map(f => ({ finding: f, reason: `Independent verifier rejected: ${(f as any).verification_rationale}` }))];
  return { findings: findings.filter(f => (f as any).verification !== "rejected"), rejected_findings: rejected, verification: { records } };
}
