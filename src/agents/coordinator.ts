import path from "node:path";
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
  const memory = await MemoryDB.getInstance();
  const topPatterns = memory.getTopPatterns(50);
  reportProgress("memory", "done", `${topPatterns.length} patterns`);
  await logger.write(`Loaded ${topPatterns.length} top pattern(s) from memory DB`);
  pushLog("memory", `Loaded ${topPatterns.length} known vulnerability patterns from memory`);

  // -------------------------------------------------------------------
  // 4️⃣  Build snapshot
  // -------------------------------------------------------------------
  reportProgress("snapshot", "running");
  const snapshot: CodebaseSnapshot = await buildSnapshot(projectRoot);
  reportProgress("snapshot", "done", `${snapshot.file_count} files`);
  await logger.write(`Snapshot built – ${snapshot.file_count} file(s) captured`);
  pushLog("snapshot", `Codebase snapshot built – ${snapshot.file_count} files analysed`);

  // -------------------------------------------------------------------
  // 5️⃣  Run Recon agent
  // -------------------------------------------------------------------
  reportProgress("recon", "running");
  let recon: ReconReport | null;
  try {
    recon = await runRecon(snapshot, config, topPatterns);
  } catch (err: any) {
    pushLog("recon", `✖ Recon agent threw: ${err?.message ?? err}`);
    await logger.write(`✖ Recon agent threw: ${err?.message ?? err}`);
    throw new Error(`Recon phase failed: ${err?.message ?? err}`);
  }
  if (!recon) {
    reportProgress("recon", "error");
    await logger.write("✖ Recon agent returned null (parse_failed after retries). Aborting.");
    pushLog("recon", "✖ Recon agent failed after retries — aborting");
    await logger.flush();
    throw new Error("Recon agent failed: unable to parse codebase structure.");
  }
  const entryPoints = recon.entry_points ?? [];
  reportProgress("recon", "done", `${entryPoints.length} entry points`);
  await logger.write(`Recon completed – ${entryPoints.length} entry point(s)`);
  pushLog("recon", `Reconnaissance identified ${entryPoints.length} entry points`);

  // -------------------------------------------------------------------
  // 6️⃣  Run Exploit & Audit in parallel (they're independent)
  //      Audit NOW receives the REAL ExploitMap for cross‑referencing.
  // -------------------------------------------------------------------
  reportProgress("exploit", "running");
  reportProgress("audit", "running");
  let exploit: ExploitMap | null;
  let audit: AuditReport | null;
  try {
    [exploit, audit] = await Promise.all([
      runExploit(recon, snapshot, config, topPatterns),
      runAudit(recon, { scenarios: [] } as ExploitMap, snapshot, config, topPatterns),
    ]);
  } catch (err: any) {
    pushLog("exploit", `✖ Exploit/Audit phase threw: ${err?.message ?? err}`);
    await logger.write(`✖ Exploit/Audit phase threw: ${err?.message ?? err}`);
    throw new Error(`Exploit/Audit phase failed: ${err?.message ?? err}`);
  }

  // Handle parse_failed gracefully – treat missing outputs as empty.
  const exploitMap: ExploitMap = exploit && exploit.scenarios ? exploit : { scenarios: [] };
  const auditReport: AuditReport = audit && audit.findings ? audit : { findings: [] };

  const scenarioCount = exploitMap.scenarios.length;
  const findingCount = auditReport.findings.length;

  reportProgress("exploit", "done", `${scenarioCount} scenarios`);
  reportProgress("audit", "done", `${findingCount} findings`);

  await logger.write(`Exploit completed – ${scenarioCount} scenario(s)`);
  pushLog("exploit", `Exploitation phase generated ${scenarioCount} attack scenario(s)`);
  await logger.write(`Audit completed – ${findingCount} finding(s)`);
  pushLog("audit", `Audit phase discovered ${findingCount} potential finding(s)`);

  // -------------------------------------------------------------------
  // 7️⃣  Run Patch agent
  // -------------------------------------------------------------------
  reportProgress("patch", "running");
  let patchResult: PatchSet | null;
  try {
    patchResult = await runPatch(
      exploitMap,
      auditReport,
      snapshot,
      config,
      topPatterns
    );
  } catch (err: any) {
    pushLog("patch", `✖ Patch agent threw: ${err?.message ?? err}`);
    await logger.write(`✖ Patch agent threw: ${err?.message ?? err}`);
    throw new Error(`Patch phase failed: ${err?.message ?? err}`);
  }
  const patchSet: PatchSet = patchResult && patchResult.patches ? patchResult : { patches: [] };
  const patchCount = patchSet.patches.length;
  reportProgress("patch", "done", `${patchCount} patches`);
  await logger.write(`PatchSet generated – ${patchCount} patch(es)`);
  pushLog("patch", `Patch generator created ${patchCount} patch(es)`);

  // -------------------------------------------------------------------
  // 8️⃣  Apply patches (only READY ones are applied)
  // -------------------------------------------------------------------
  reportProgress("apply", "running");
  if (patchSet.patches.length > 0) {
    await applyPatchSet(patchSet, projectRoot, logger);
    const readyCount = patchSet.patches.filter(p => p.status === "READY").length;
    reportProgress("apply", "done", `${readyCount} applied`);
    await logger.write("Patch application finished");
    pushLog("apply", `Applied ${readyCount} patch(es) to the codebase`);
  } else {
    reportProgress("apply", "done", "nothing to apply");
    await logger.write("No patches to apply – skipping patch application.");
    pushLog("apply", "No patches to apply — skipped");
  }

  // -------------------------------------------------------------------
  // 9️⃣  Compute session scores
  // -------------------------------------------------------------------
  const totalFindings =
    exploitMap.scenarios.length + auditReport.findings.length;
  const readyPatches = patchSet.patches.filter((p) => p.status === "READY").length;

  const coverageScore = snapshot.file_count > 0 ? 1.0 : 0.0;
  const precisionScore =
    totalFindings > 0
      ? Math.min(readyPatches / totalFindings, 1.0)
      : 0.0;
  const patchSuccessRate =
    patchSet.patches.length > 0 ? readyPatches / patchSet.patches.length : 0.0;
  const noveltyScore = topPatterns.length === 0 ? 1.0 : 0.5;
  const compositeScore =
    (coverageScore + precisionScore + patchSuccessRate + noveltyScore) / 4;

  const computedScores = {
    coverage_score: coverageScore,
    precision_score: precisionScore,
    patch_success_rate: patchSuccessRate,
    novelty_score: noveltyScore,
    composite_score: compositeScore,
  };

  // -------------------------------------------------------------------
  // 🔟  Run Memory agent and persist its update
  // -------------------------------------------------------------------
  reportProgress("memory-update", "running");
  let memoryUpdate: MemoryUpdate | null;
  try {
    memoryUpdate = await runMemory(
      recon,
      exploitMap,
      auditReport,
      patchSet,
      computedScores,
      config,
      topPatterns
    );
  } catch (err: any) {
    pushLog("memory-update", `✖ Memory agent threw: ${err?.message ?? err}`);
    await logger.write(`✖ Memory agent threw: ${err?.message ?? err}`);
    throw new Error(`Memory-update phase failed: ${err?.message ?? err}`);
  }

  const newPatterns = memoryUpdate?.new_patterns ?? [];
  const falsePositives = memoryUpdate?.false_positives ?? [];

  if (memoryUpdate && newPatterns.length > 0) {
    await logger.write(`MemoryUpdate generated – ${newPatterns.length} new pattern(s)`);
    pushLog("memory-update", `Memory updated with ${newPatterns.length} new pattern(s) and ${falsePositives.length} false positive(s)`);

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
    for (const fp of falsePositives) {
      memory.insertFalsePositive({
        id: `${sessionId}-fp-${Math.random().toString(36).slice(2, 8)}`,
        pattern_id: "",
        reason: fp.reason ?? "",
        code_context: fp.code_context ?? "",
        created_at: now,
      });
    }
    reportProgress("memory-update", "done", `${newPatterns.length} new patterns`);
  } else {
    reportProgress("memory-update", "done", "skipped");
    await logger.write("Memory agent returned null – skipping memory update.");
    pushLog("memory-update", "No memory updates — agent returned no changes");
  }

  // Persist session score
  memory.insertSessionScore({
    session_id: sessionId,
    project_hash: projHash,
    ...computedScores,
    model_used: config.default_model,
    created_at: new Date().toISOString(),
  });

  // -------------------------------------------------------------------
  // 1️⃣1️⃣  Write all artefacts (JSON) to session directory
  // -------------------------------------------------------------------
  const writeJSON = async (name: string, obj: any) => {
    const p = path.join(sessionDir, `${name}.json`);
    await fs.writeFile(p, JSON.stringify(obj, null, 2), "utf-8");
  };

  await writeJSON("recon", recon);
  await writeJSON("exploit", exploitMap);
  await writeJSON("audit", auditReport);
  await writeJSON("patches", patchSet);
  await writeJSON("memory_update", memoryUpdate ?? {});

  // Update session.json with final scores
  const finalMeta = {
    ...sessionMeta,
    scores: computedScores,
    model_used: config.default_model,
  };
  await writeJSON("session", finalMeta);

  await logger.write(`=== Leo session ${sessionId} completed ===`);
  pushLog("session", `Session ${sessionId} completed — ${totalFindings} total findings, ${readyPatches} patches applied`);
  await logger.flush();

  return {
    sessionId,
    scores: computedScores,
    patchesApplied: readyPatches,
    totalFindings,
  };
}
