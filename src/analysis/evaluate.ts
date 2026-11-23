import { AuditFinding } from "../agents/audit.js";

export interface GroundTruthCase { id: string; file: string; expected: "vulnerable" | "safe"; category?: string; line?: number; }
export interface EvaluationResult {
  tp: number; fp: number; tn: number; fn: number;
  precision: number; recall: number; f1: number;
  evaluated_cases: number; unscored_findings: AuditFinding[];
  matches: Array<{ truth_id: string; finding_id: string }>;
}
const normalizePath = (p: string) => p.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
const normalizeCategory = (p?: string) => (p ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");

/** Evaluate detections only against explicitly labeled files/cases. */
export function evaluateLabeledFindings(truth: GroundTruthCase[], findings: AuditFinding[], lineTolerance = 5): EvaluationResult {
  const labeledFiles = new Set(truth.map(t => normalizePath(t.file)));
  const remaining = new Set(findings.map((_, i) => i));
  const matches: Array<{ truth_id: string; finding_id: string }> = [];
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const item of truth.filter(t => t.expected === "vulnerable")) {
    const candidate = [...remaining].filter(i => {
      const f = findings[i];
      return normalizePath(f.file) === normalizePath(item.file) &&
        (!item.category || normalizeCategory(f.category) === normalizeCategory(item.category)) &&
        (item.line === undefined || Math.abs(f.line - item.line) <= lineTolerance);
    }).sort((a, b) => item.line === undefined ? a - b : Math.abs(findings[a].line - item.line) - Math.abs(findings[b].line - item.line))[0];
    if (candidate === undefined) fn++;
    else { tp++; remaining.delete(candidate); matches.push({ truth_id: item.id, finding_id: findings[candidate].id }); }
  }
  for (const item of truth.filter(t => t.expected === "safe")) {
    const indices = [...remaining].filter(i => normalizePath(findings[i].file) === normalizePath(item.file));
    if (!indices.length) tn++;
    else { fp += indices.length; for (const i of indices) remaining.delete(i); }
  }
  // Extra findings in labeled vulnerable files are false positives; findings in
  // unlabelled files are not scored and are returned separately.
  for (const i of [...remaining]) {
    if (labeledFiles.has(normalizePath(findings[i].file))) { fp++; remaining.delete(i); }
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  return { tp, fp, tn, fn, precision, recall, f1: precision + recall ? 2 * precision * recall / (precision + recall) : 0, evaluated_cases: truth.length, unscored_findings: [...remaining].map(i => findings[i]), matches };
}
