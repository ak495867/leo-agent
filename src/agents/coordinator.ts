import path from "node:path";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { LeoConfig, loadConfig } from "../utils/config.js";
import { buildSnapshot, CodebaseSnapshot } from "../core/snapshot.js";
import { projectHash } from "../utils/hash.js";
import { createSession } from "../core/session.js";
import { MemoryDB } from "../core/memory-db.js";
import { SessionLogger } from "../utils/logger.js";
import { narrowTerminalWarning } from "../utils/terminal.js";
import { reportProgress, pushLog } from "../utils/progress.js";

import { runRecon, ReconReport } from "./recon.js";
import { runExploit, ExploitMap } from "./exploit.js";
import { runAudit, AuditReport } from "./audit.js";
import { runPatch, PatchSet } from "./patch.js";
import { runMemory, MemoryUpdate } from "./memory.js";

import { applyPatchSet } from "../core/patcher.js";
import { createSnapshotBatches, snapshotForBatch } from "../analysis/batching.js";
import { runTaintHeuristics } from "../analysis/taint.js";
import { scanDependencies } from "../analysis/osv.js";
import { correlateBatches } from "./correlate.js";
import { verifyFindings } from "./verify.js";

async function writeEarlyArtifact(sessionDir: string, name: string, obj: unknown): Promise<void> {
  await fs.writeFile(path.join(sessionDir, `${name}.json`), JSON.stringify(obj, null, 2), { encoding: "utf8", mode: 0o600 });
}

/**
 * Run a full Leo session.
 *
 * Steps:
 *   1️⃣ Load user config (and warn if terminal is narrow)
 *   2️⃣ Compute project hash and create a session folder (via createSession)
 *   3️⃣ Load top‑50 patterns from the memory DB (injected into every agent prompt)
 *   4️⃣ Build a codebase snapshot
 *   5️⃣ Run Recon
 *   6️⃣ Run Exploit & Audit in parallel (Audit now receives real exploit data)
 *   7️⃣ Run Patch agent, then apply patches safely
 *   8️⃣ Compute a simple session score
 *   9️⃣ Run Memory agent and persist its update
 *  10️⃣ Write all artefacts (JSON + log) to the session directory
 *
 * @param projectRoot  – absolute path to the target project.
 * @param resumeFrom   – optional session ID to resume from (loads prior context).
 */
export async function runCoordinator(
  projectRoot: string,
  resumeFrom?: string
) {
  // -------------------------------------------------------------------
  // 1️⃣  Terminal check + config
  // -------------------------------------------------------------------
  const narrowWarning = narrowTerminalWarning();
  const config: LeoConfig = await loadConfig();
  if (!config.openrouter_api_key) {
    reportProgress("config", "error", "API key missing");
    throw new Error(
      "OpenRouter API key not set – run `leo config` or edit ~/.leo/config.json"
    );
  }
  reportProgress("config", "done");

  // -------------------------------------------------------------------
  // 2️⃣  Create session directory (via core/session.ts for consistency)
  // -------------------------------------------------------------------
  const { sessionDir, meta: sessionMeta } = await createSession(projectRoot, {
    config_snapshot: config,
    model_used: config.default_model,
    scores: {}, // will be filled after computation
  });
  const sessionId = sessionMeta.session_id;
  const projHash = sessionMeta.project_hash;

  const logger = new SessionLogger(sessionDir);
  await logger.write(`=== Leo session ${sessionId} started ===`);
  pushLog("session", `Session ${sessionId} started`);
  await logger.write(`Project root: ${projectRoot}`);
  await logger.write(`Project hash: ${projHash}`);
  if (narrowWarning) { await logger.write(narrowWarning.trim()); pushLog("config", narrowWarning.trim()); }
  if (resumeFrom) { await logger.write(`Resuming from session ${resumeFrom}`); pushLog("session", `Resuming from session ${resumeFrom}`); }

  // -------------------------------------------------------------------
  // 3️⃣  Load top patterns from memory DB (inject into all sub‑agents)
  // -------------------------------------------------------------------
  reportProgress("memory", "running", "loading patterns");
  const memory = await MemoryDB.getInstance(projectRoot);
  const topPatterns = config.memory_enabled === false ? [] : memory.getTopPatterns(50);
  reportProgress("memory", "done", `${topPatterns.length} patterns`);
  await logger.write(`Loaded ${topPatterns.length} project-scoped pattern(s) from memory DB`);
  pushLog("memory", `Loaded ${topPatterns.length} known vulnerability patterns from memory`);

  // -------------------------------------------------------------------
  // 4️⃣  Build snapshot
  // -------------------------------------------------------------------
  reportProgress("snapshot", "running");
  const snapshot: CodebaseSnapshot = await buildSnapshot(projectRoot);
  reportProgress("snapshot", "done", `${snapshot.file_count} files`);
  await logger.write(`Snapshot built – ${snapshot.file_count} file(s) captured`);
  pushLog("snapshot", `Codebase snapshot built – ${snapshot.file_count} files analysed; ${snapshot.skipped_files.length} skipped`);

  const snapshotHash = createHash("sha256").update(JSON.stringify(Object.entries(snapshot.files).sort(([a], [b]) => a.localeCompare(b)))).digest("hex");
  await writeEarlyArtifact(sessionDir, "snapshot_manifest", { snapshot_hash: snapshotHash, file_count: snapshot.file_count, total_bytes: snapshot.total_bytes, skipped_files: snapshot.skipped_files, snapshot_at: snapshot.snapshot_at });
  const configFingerprint = createHash("sha256").update(JSON.stringify({ pipeline: "0.6.0", model: config.default_model, scan_depth: config.scan_depth, patterns: topPatterns })).digest("hex");
  const cachedBatches: Record<string, { batch_id: string; config_fingerprint?: string; recon: ReconReport; exploit: ExploitMap; audit: AuditReport }> = {};
  if (resumeFrom) {
    if (!/^[a-f0-9]{6,32}$/i.test(resumeFrom)) throw new Error("Invalid resume session ID.");
    const home = process.env.HOME ?? process.env.USERPROFILE ?? process.cwd();
    const oldDir = path.join(home, ".leo", "sessions", projHash, resumeFrom);
    const manifest = JSON.parse(await fs.readFile(path.join(oldDir, "snapshot_manifest.json"), "utf8"));
    if (manifest.snapshot_hash !== snapshotHash) throw new Error("Cannot resume: the project snapshot differs from the saved session. Start a fresh scan to avoid mixing results from different source states.");
    const oldBatchDir = path.join(oldDir, "batches");
    try {
      for (const name of await fs.readdir(oldBatchDir)) {
        if (!name.endsWith(".json")) continue;
        try { const item = JSON.parse(await fs.readFile(path.join(oldBatchDir, name), "utf8")); if (item?.batch_id) cachedBatches[item.batch_id] = item; } catch { /* ignore corrupt individual checkpoint; it will be recomputed */ }
      }
    } catch { /* legacy session without batch checkpoints: recompute */ }

  }

  // -------------------------------------------------------------------
  // 5️⃣  Bounded multi-batch analysis. Each file is sent exactly once to
  //      the per-batch agents; aggregate findings are correlated globally.
  // -------------------------------------------------------------------
  const batches = createSnapshotBatches(snapshot, 48_000);
  await writeEarlyArtifact(sessionDir, "batch_manifest", { total_batches: batches.length, batches: batches.map(b => ({ id: b.id, index: b.index, total: b.total, files: Object.keys(b.files), byte_count: b.byte_count })) });
  await logger.write(`Analysis split into ${batches.length} deterministic batch(es); ${Object.keys(cachedBatches).length} cached checkpoints available`);
  reportProgress("recon", "running", `${batches.length} batches`);
  const reconReports: ReconReport[] = [];
  const exploitReports: ExploitMap[] = [];
  const auditReports: AuditReport[] = [];
  for (const batch of batches) {
    const batchSnapshot = snapshotForBatch(snapshot, batch);
    await logger.write(`Batch ${batch.index}/${batch.total}: ${batch.id}, ${batchSnapshot.file_count} files, ${batch.byte_count} bytes`);
    let cached: (typeof cachedBatches)[string] | undefined = cachedBatches[batch.id];
    if (cached && cached.config_fingerprint !== configFingerprint) cached = undefined;
    if (cached) await logger.write(`Reusing verified snapshot/config checkpoint for ${batch.id}`);
    else {
      const batchRecon = await runRecon(batchSnapshot, config, topPatterns);
      if (!batchRecon) throw new Error(`Recon failed for ${batch.id}; no findings will be reported as a successful scan.`);
      const batchExploit = await runExploit(batchRecon, batchSnapshot, config, topPatterns);
      if (!batchExploit || !Array.isArray(batchExploit.scenarios)) throw new Error(`Exploit analysis failed for ${batch.id}.`);
      const batchAudit = await runAudit(batchRecon, batchExploit, batchSnapshot, config, topPatterns);
      if (!batchAudit || !Array.isArray(batchAudit.findings)) throw new Error(`Audit analysis failed for ${batch.id}.`);
      cached = { batch_id: batch.id, config_fingerprint: configFingerprint, recon: batchRecon, exploit: batchExploit, audit: batchAudit };
      const batchDir = path.join(sessionDir, "batches"); await fs.mkdir(batchDir, { recursive: true, mode: 0o700 });
      await writeEarlyArtifact(batchDir, batch.id, cached);
    }
    reconReports.push(cached.recon); exploitReports.push(cached.exploit); auditReports.push(cached.audit);
    reportProgress("recon", "running", `completed ${batch.index}/${batch.total}`);
  }

  const unique = <T>(items: T[]): T[] => [...new Map(items.map(item => [JSON.stringify(item), item])).values()];
  const recon: ReconReport = {
    project_hash: projHash, scanned_at: new Date().toISOString(),
    tech_stack: {
      languages: unique(reconReports.flatMap(r => r.tech_stack?.languages ?? [])),
      frameworks: unique(reconReports.flatMap(r => r.tech_stack?.frameworks ?? [])),
      runtime_versions: Object.assign({}, ...reconReports.map(r => r.tech_stack?.runtime_versions ?? {})),
      package_managers: unique(reconReports.flatMap(r => r.tech_stack?.package_managers ?? [])),
    },
    entry_points: unique(reconReports.flatMap(r => r.entry_points ?? [])),
    trust_boundaries: unique(reconReports.flatMap(r => r.trust_boundaries ?? [])),
    dependencies: unique(reconReports.flatMap(r => r.dependencies ?? [])),
    complexity_hotspots: unique(reconReports.flatMap(r => r.complexity_hotspots ?? [])),
    secrets_surface: unique(reconReports.flatMap(r => r.secrets_surface ?? [])),
  };
  const exploitMap: ExploitMap = { scenarios: unique(exploitReports.flatMap((r, i) => (r.scenarios ?? []).map(s => ({ ...s, id: `${batches[i]?.id ?? "batch"}:${s.id}` })))) };
  reportProgress("recon", "done", `${batches.length} batches; ${snapshot.file_count} files`);
  reportProgress("exploit", "done", `${exploitMap.scenarios.length} scenarios`);
  reportProgress("audit", "running", "cross-batch aggregation");

  // Merge deterministic static-analysis results with model findings.
  const taintReport = runTaintHeuristics(snapshot.files);
  const dependencyReport = await scanDependencies(snapshot.files);
  const preCorrelation: AuditReport[] = [...auditReports, taintReport, { findings: dependencyReport.findings, rejected_findings: [] }];
  const correlated = await correlateBatches(preCorrelation, config, Object.keys(snapshot.files));
  let auditReport: AuditReport & { verification?: unknown } = correlated.report;
  await logger.write(`Cross-batch correlation completed: ${correlated.chains.length} chain(s); ${auditReport.findings.length} unique candidate finding(s)`);

  // Independent verifier challenges every candidate. If verifier transport
  // fails, findings remain visible and explicitly unverified.
  try {
    auditReport = await verifyFindings(auditReport, snapshot.files, config);
  } catch (err) {
    await logger.write(`Verifier unavailable: ${(err as Error).message}; candidates retained as needs_review`);
    auditReport = { ...auditReport, findings: auditReport.findings.map(f => ({ ...f, verification: "needs_review", verification_confidence: 0, verification_rationale: "Verifier unavailable; requires human review." })) };
  }
  const scenarioCount = exploitMap.scenarios.length;
  const findingCount = auditReport.findings.length;
  reportProgress("audit", "done", `${findingCount} verified or review-required findings`);
  await logger.write(`Audit completed – ${findingCount} retained finding(s); ${auditReport.rejected_findings?.length ?? 0} rejected finding(s)`);
  pushLog("audit", `Audit completed across ${batches.length} batches; ${findingCount} findings retained`);

  await writeEarlyArtifact(sessionDir, "taint_report", { findings: taintReport.findings, rejected_findings: taintReport.rejected_findings });
  await writeEarlyArtifact(sessionDir, "project_analysis", taintReport.project_analysis);
  await writeEarlyArtifact(sessionDir, "dependency_audit", dependencyReport);
  await writeEarlyArtifact(sessionDir, "correlations", { cross_file_chains: correlated.chains });
  if ((auditReport as any).verification) await writeEarlyArtifact(sessionDir, "verification", (auditReport as any).verification);

  // -------------------------------------------------------------------
  // 7️⃣  Run Patch agent
  // -------------------------------------------------------------------
  reportProgress("patch", "running");
  const patchSets: PatchSet[] = [];
  try {
    for (const batch of batches) {
      const batchSnapshot = snapshotForBatch(snapshot, batch);
      const batchFiles = new Set(Object.keys(batch.files));
      const localAudit: AuditReport = { findings: auditReport.findings.filter(f => batchFiles.has(f.file) && f.verification === "confirmed"), rejected_findings: [] };
      const localExploit: ExploitMap = { scenarios: exploitMap.scenarios.filter(s => batchFiles.has(s.target_file.replace(/^.*?:/, ""))) };
      if (!localAudit.findings.length) continue;
      const result = await runPatch(localExploit, localAudit, batchSnapshot, config, topPatterns);
      if (result?.patches) patchSets.push(result);
    }
  } catch (err: any) {
    pushLog("patch", `✖ Patch agent threw: ${err?.message ?? err}`);
    await logger.write(`✖ Patch agent threw: ${err?.message ?? err}`);
    throw new Error(`Patch phase failed: ${err?.message ?? err}`);
  }
  const patchSet: PatchSet = { patches: patchSets.flatMap(p => p.patches) };
  const patchCount = patchSet.patches.length;
  reportProgress("patch", "done", `${patchCount} patches`);
  await logger.write(`PatchSet generated – ${patchCount} patch(es)`);
  pushLog("patch", `Patch generator created ${patchCount} patch(es)`);

  // -------------------------------------------------------------------
  // 8️⃣  Apply patches (only READY ones are applied)
  // -------------------------------------------------------------------
  reportProgress("apply", "running");
  let appliedPatchCount = 0;
  if (patchSet.patches.length > 0 && config.auto_apply_patches === true) {
    appliedPatchCount = await applyPatchSet(patchSet, projectRoot, logger, sessionDir);
    reportProgress("apply", "done", `${appliedPatchCount} applied`);
    await logger.write("Patch application finished");
    pushLog("apply", `Applied ${appliedPatchCount} patch(es) to the codebase`);
  } else if (patchSet.patches.length > 0) {
    reportProgress("apply", "done", "approval required");
    await logger.write("Patch application skipped: auto_apply_patches is disabled. Review patches.json and explicitly enable application.");
    pushLog("apply", "Generated patches saved for human review; no source files modified");
  } else {
    reportProgress("apply", "done", "nothing to apply");
    await logger.write("No patches to apply – skipping patch application.");
    pushLog("apply", "No patches to apply — skipped");
  }

  // -------------------------------------------------------------------
  // 9️⃣  Record operational counts only. Detection precision/recall require
  //      ground-truth labels and are never inferred from patch counts.
  // -------------------------------------------------------------------
  const totalFindings = auditReport.findings.length;
  const computedScores = {
    files_analyzed: snapshot.file_count,
    files_skipped: snapshot.skipped_files.length,
    exploit_scenarios: exploitMap.scenarios.length,
    findings_reported: totalFindings,
    patches_proposed: patchSet.patches.length,
    patches_applied: appliedPatchCount,
    benchmark_metrics: null,
    batches_processed: batches.length,
    taint_candidates: taintReport.findings.length,
    dependencies_queried: dependencyReport.queried,
    dependency_scan_available: dependencyReport.status === "unavailable" ? 0 : 1,
    verified_findings: auditReport.findings.filter(f => f.verification === "confirmed").length,
    needs_review_findings: auditReport.findings.filter(f => f.verification === "needs_review").length,
    cross_file_chains: correlated.chains.length,
  };

  // -------------------------------------------------------------------
  // 🔟  Run Memory agent and persist its update
  // -------------------------------------------------------------------
  reportProgress("memory-update", "running");
  let memoryUpdate: MemoryUpdate | null = null;
  if (config.memory_enabled !== false) {
    try {
      memoryUpdate = await runMemory(recon, exploitMap, auditReport, patchSet, computedScores, config, topPatterns);
    } catch (err: any) {
      // Memory learning is optional and must never invalidate a completed audit.
      pushLog("memory-update", `Memory update skipped: ${err?.message ?? err}`);
      await logger.write(`Memory update skipped: ${err?.message ?? err}`);
    }
  }

  const newPatterns = memoryUpdate?.new_patterns ?? [];
  const falsePositives = memoryUpdate?.false_positives ?? [];

  const newTemplates = memoryUpdate?.new_patch_templates ?? [];
  if (config.memory_enabled !== false && memoryUpdate && (newPatterns.length > 0 || newTemplates.length > 0)) {
    await logger.write(`MemoryUpdate generated – ${newPatterns.length} new pattern(s), ${newTemplates.length} patch template(s)`);
    pushLog("memory-update", `Memory updated with ${newPatterns.length} new pattern(s) and ${newTemplates.length} patch template(s)`);

    // Persist new patterns to the DB
    const now = new Date().toISOString();
    for (const np of newPatterns) {
      memory.insertPattern({
        id: `${sessionId}-${np.pattern_name?.slice(0, 20).replace(/\s+/g, "-")}`,
        pattern_name: np.pattern_name ?? "unknown",
        description: np.description ?? "",
        attack_class: np.attack_class ?? "",
        code_signatures: JSON.stringify(np.code_signatures ?? []),
        languages: JSON.stringify(np.languages ?? []),
        created_at: now,
      });
    }
    for (const template of newTemplates) {
      const patternId = memory.getPatternIdByName(template.vulnerability_pattern_name);
      if (!patternId) { await logger.write(`Skipped patch template without a known pattern: ${template.vulnerability_pattern_name}`); continue; }
      memory.insertPatchTemplate({
        id: `${sessionId}-tpl-${Buffer.from(template.vulnerability_pattern_name + template.language).toString("hex").slice(0, 32)}`,
        vulnerability_pattern_id: patternId,
        language: template.language,
        description: template.description,
        before_pattern: template.before_pattern,
        after_pattern: template.after_pattern,
        created_at: now,
      });
    }
    reportProgress("memory-update", "done", `${newPatterns.length} new patterns`);
  } else {
    reportProgress("memory-update", "done", "skipped");
    await logger.write("Memory disabled, agent returned no updates, or no reusable patterns/templates were produced.");
    pushLog("memory-update", "No memory updates — agent returned no changes");
  }

  // -------------------------------------------------------------------
  // 1️⃣1️⃣  Write all artefacts (JSON) to session directory
  // -------------------------------------------------------------------
  const writeJSON = async (name: string, obj: any) => {
    const p = path.join(sessionDir, `${name}.json`);
    await fs.writeFile(p, JSON.stringify(obj, null, 2), { encoding: "utf-8", mode: 0o600 });
  };

  await writeJSON("recon", recon);
  await writeJSON("exploit", exploitMap);
  await writeJSON("audit", auditReport);
  await writeJSON("patches", patchSet);
  await writeJSON("memory_update", memoryUpdate ?? {});
  await writeJSON("snapshot_manifest", { snapshot_hash: snapshotHash, file_count: snapshot.file_count, total_bytes: snapshot.total_bytes, skipped_files: snapshot.skipped_files, snapshot_at: snapshot.snapshot_at });

  // Update session.json with final scores
  const finalMeta = {
    ...sessionMeta,
    scores: computedScores,
    model_used: config.default_model,
  };
  await writeJSON("session", finalMeta);

  await logger.write(`=== Leo session ${sessionId} completed ===`);
  pushLog("session", `Session ${sessionId} completed — ${totalFindings} total findings, ${appliedPatchCount} patches applied`);
  await logger.flush();

  return {
    sessionId,
    scores: computedScores,
    patchesApplied: appliedPatchCount,
    totalFindings,
  };
}
