/**
 * Leo – autonomous security auditing CLI
 *
 * Entry point re‑export. Allows `import { … } from "@leo-agent/cli"` style usage.
 * The actual CLI logic lives in ./cli.
 */
export { program } from "./cli.js";
export { runCoordinator } from "./agents/coordinator.js";
export { loadConfig, saveConfig } from "./utils/config.js";
export { createSession, listSessions, loadSession } from "./core/session.js";
export { MemoryDB } from "./core/memory-db.js";
export { buildSnapshot } from "./core/snapshot.js";
export { applyPatchSet } from "./core/patcher.js";
export { projectHash } from "./utils/hash.js";

export { runTaintHeuristics, runProjectAnalysis } from "./analysis/taint.js";
export { analyzeProject } from "./analysis/project-analysis.js";
export { analyzeContextsAndHeap, solvePathConditions, runCounterexampleInSandbox, buildBenchmarkReport } from "./analysis/engine-v1.js";
export type { ContextHeapResult, ContextCallEdge, HeapFact, PathConstraint, PathSolveResult, SandboxResult, BenchmarkReport } from "./analysis/engine-v1.js";
