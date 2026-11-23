import { runTaintHeuristics } from "./taint.js";

export interface RegressionCase { id: string; expected: "vulnerable" | "safe"; file: string; source: string; category?: string; }
export interface RegressionSummary { tp: number; fp: number; tn: number; fn: number; precision: number; recall: number; f1: number; cases: Array<{ id: string; expected: string; detected: boolean; pass: boolean; findings: number }> }

/** Runs deterministic static-rule fixtures; these are rule-regression metrics, not model benchmark metrics. */
export function runRuleRegression(cases: RegressionCase[]): RegressionSummary {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const details = cases.map(c => {
    const result = runTaintHeuristics({ [c.file]: c.source }); const detected = result.findings.length > 0;
    if (c.expected === "vulnerable" && detected) tp++; else if (c.expected === "vulnerable") fn++; else if (detected) fp++; else tn++;
    return { id: c.id, expected: c.expected, detected, pass: detected === (c.expected === "vulnerable"), findings: result.findings.length };
  });
  const precision = tp + fp ? tp / (tp + fp) : 0; const recall = tp + fn ? tp / (tp + fn) : 0;
  return { tp, fp, tn, fn, precision, recall, f1: precision + recall ? 2 * precision * recall / (precision + recall) : 0, cases: details };
}
