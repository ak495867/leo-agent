import { callJsonAgent } from "../api/openrouter.js";
import { AUDIT_SYSTEM_PROMPT } from "./prompts/audit.js";
import { LeoConfig } from "../utils/config.js";
import { ReconReport } from "./recon.js";
import { ExploitMap } from "./exploit.js";

export interface AuditFinding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  file: string;
  line: number;
  category: string;
  description: string;
  exploit_map_ref?: string;
  evidence?: string;
  recommendation?: string;
  verification?: "confirmed" | "rejected" | "needs_review";
  verification_confidence?: number;
  verification_rationale?: string;
  fingerprint?: string;
}

export interface AuditReport {
  findings: AuditFinding[];
  rejected_findings?: Array<{ finding: unknown; reason: string }>;
}

/**
 * Run the Audit agent.
 *   - `recon` — output of the Recon agent.
 *   - `exploit` — output of the Exploit agent (used for cross‑reference).
 *   - `snapshot` — original file contents.
 *   - `config` — API key, model, etc.
 *   - `topPatterns` — top‑50 memory‑DB patterns injected into the prompt.
 */
export async function runAudit(
  recon: ReconReport,
  exploit: ExploitMap,
  snapshot: { files: Record<string, string> },
  config: LeoConfig,
  topPatterns: any[] = []
): Promise<AuditReport | null> {
  const userMsg = JSON.stringify({
    recon,
    exploit,
    files: snapshot.files,
    top_patterns: topPatterns.map((p) => ({
      pattern_name: p.pattern_name,
      description: p.description,
      attack_class: p.attack_class,
    })),
  });

  const report = await callJsonAgent<AuditReport>(AUDIT_SYSTEM_PROMPT, userMsg, config.default_model, config.openrouter_api_key);
  if (!report || !Array.isArray(report.findings)) return null;
  const accepted: AuditFinding[] = [];
  const rejected: Array<{ finding: unknown; reason: string }> = [...(report.rejected_findings ?? [])];
  const seen = new Set<string>();
  for (const raw of report.findings) {
    const finding = raw as AuditFinding;
    if (!finding || typeof finding.file !== "string" || !Object.prototype.hasOwnProperty.call(snapshot.files, finding.file)) {
      rejected.push({ finding: raw, reason: "file path is not present in the scanned snapshot" }); continue;
    }
    const lines = snapshot.files[finding.file].split(/\r?\n/).length;
    if (!Number.isInteger(finding.line) || finding.line < 1 || finding.line > lines) {
      rejected.push({ finding: raw, reason: `line must be between 1 and ${lines}` }); continue;
    }
    if (!finding.id || !finding.description || !finding.category || !["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].includes(finding.severity)) {
      rejected.push({ finding: raw, reason: "required finding fields or severity are invalid" }); continue;
    }
    const key = `${finding.file}:${finding.line}:${finding.category.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key); accepted.push(finding);
  }
  return { findings: accepted, rejected_findings: rejected };
}
