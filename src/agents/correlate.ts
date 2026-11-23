import { callJsonAgent } from "../api/openrouter.js";
import { LeoConfig } from "../utils/config.js";
import { AuditFinding, AuditReport } from "./audit.js";
import { deduplicateFindings } from "../analysis/deduplicate.js";

export interface CorrelationReport { findings: AuditFinding[]; cross_file_chains: Array<{ title: string; files: string[]; explanation: string; finding_ids: string[] }>; }
const PROMPT = `You are Leo's cross-batch security correlation analyst. You receive findings from independent source batches. Identify only defensible multi-file attack chains between the supplied findings. Do not invent source facts, file paths, finding IDs, or new vulnerabilities. A chain must reference at least two supplied findings in at least two distinct files. Return JSON only: {"findings":[],"cross_file_chains":[{"title":"...","files":[...],"explanation":"...","finding_ids":[...]}]}. If no defensible links exist, return an empty array.`;

export async function correlateBatches(reports: AuditReport[], config: LeoConfig, knownFiles: string[] = []): Promise<{ report: AuditReport; chains: CorrelationReport["cross_file_chains"] }> {
  // Interleave reports so each bounded correlation request sees findings from
  // multiple source batches rather than a single contiguous batch's findings.
  const queues = reports.map(r => [...r.findings]);
  const interleaved: AuditFinding[] = [];
  let remaining = true;
  while (remaining) {
    remaining = false;
    for (const queue of queues) { const item = queue.shift(); if (item) { interleaved.push(item); remaining = true; } }
  }
  const deduped = deduplicateFindings([{ findings: interleaved, rejected_findings: reports.flatMap(r => r.rejected_findings ?? []) }]);
  if (!deduped.findings.length) return { report: deduped, chains: [] };
  const chains: CorrelationReport["cross_file_chains"] = [];
  const fileByFinding = new Map(deduped.findings.map(f => [f.id, f.file.replace(/\\/g, "/")]));
  const known = new Set(knownFiles.map(f => f.replace(/\\/g, "/")));
  // Keep each global reasoning request comfortably below the model context cap.
  for (let i = 0; i < deduped.findings.length; i += 150) {
    const chunk = deduped.findings.slice(i, i + 150);
    const compact = chunk.map(f => ({ id: f.id, file: f.file, line: f.line, severity: f.severity, category: f.category, description: f.description, evidence: (f.evidence ?? "").slice(0, 400), exploit_map_ref: f.exploit_map_ref }));
    try {
      const result = await callJsonAgent<CorrelationReport>(PROMPT, JSON.stringify({ findings: compact }), config.default_model, config.openrouter_api_key);
      if (!result) continue;
      const allowed = new Set(chunk.map(f => f.id));
      for (const chain of result.cross_file_chains ?? []) {
        if (!Array.isArray(chain.finding_ids) || chain.finding_ids.length < 2 || !chain.finding_ids.every(id => allowed.has(id))) continue;
        if (!Array.isArray(chain.files) || chain.files.length < 2 || !chain.files.every(file => known.has(String(file).replace(/\\/g, "/")))) continue;
        const referencedFiles = new Set(chain.finding_ids.map(id => fileByFinding.get(id)).filter(Boolean));
        if (referencedFiles.size < 2 || [...referencedFiles].some(file => !chain.files.map(f => f.replace(/\\/g, "/")).includes(file!))) continue;
        if (typeof chain.title === "string" && typeof chain.explanation === "string") chains.push(chain);
      }
    } catch { /* preserve deterministic findings if the optional correlation pass is unavailable */ }
  }
  const findings = deduped.findings;
  return { report: { ...deduped, findings }, chains };
}
