import { createHash } from "node:crypto";
import { AuditFinding, AuditReport } from "../agents/audit.js";

export function findingFingerprint(f: AuditFinding): string {
  const normalized = [f.file.replace(/\\/g, "/").toLowerCase(), f.category.toLowerCase().replace(/[^a-z0-9]+/g, "-"), String(f.line), (f.description || "").toLowerCase().replace(/\s+/g, " ").trim().slice(0, 240)].join("|");
  return createHash("sha256").update(normalized).digest("hex").slice(0, 20);
}

/** Deduplicate exact and near-identical reports without merging distinct lines. */
export function deduplicateFindings(reports: AuditReport[]): AuditReport {
  const accepted: AuditFinding[] = [];
  const rejected: Array<{ finding: unknown; reason: string }> = [];
  const seen = new Map<string, number>();
  for (const report of reports) {
    rejected.push(...(report.rejected_findings ?? []));
    for (const f of report.findings) {
      const exact = `${f.file.toLowerCase()}:${f.line}:${f.category.toLowerCase()}`;
      const semantic = `${f.file.toLowerCase()}:${f.line}:${f.category.toLowerCase()}:${(f.description || "").toLowerCase().replace(/\W+/g, " ").trim()}`;
      if (seen.has(exact) || seen.has(semantic)) continue;
      const id = findingFingerprint(f);
      const normalized = { ...f, id };
      seen.set(exact, accepted.length); seen.set(semantic, accepted.length);
      accepted.push(normalized);
    }
  }
  return { findings: accepted, rejected_findings: rejected };
}
