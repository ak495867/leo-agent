import { program } from "commander";
import path from "node:path";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createInterface } from "node:readline";
import React from "react";
import { render } from "ink";
import { App } from "./ui/App.js";
import { runCoordinator } from "./agents/coordinator.js";
import { loadConfig, saveConfig, LeoConfig } from "./utils/config.js";
import { createSession, listSessions, loadSession, SessionMeta } from "./core/session.js";
import { projectHash } from "./utils/hash.js";
import { narrowTerminalWarning } from "./utils/terminal.js";
import { evaluateLabeledFindings, GroundTruthCase } from "./analysis/evaluate.js";
import { runRuleRegression, RegressionCase } from "./analysis/regression.js";
import { buildBenchmarkReport, runCounterexampleInSandbox } from "./analysis/engine-v1.js";

/* --------------------------------------------------------------- */
/*  SHARED HELPERS                                                 */
/* --------------------------------------------------------------- */

/** Resolve the session index path for the current project. */
async function sessionIndex(projRoot: string) {
  const projHash = projectHash(projRoot);
  const indexPath = path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? "",
    ".leo",
    "sessions",
    projHash,
    "index.json",
  );
  return indexPath;
}

/** Print a formatted session entry. */
function printSession(label: string, e: SessionMeta) {
  const scores = e.scores ?? {};
  console.log(
    `${label}) ${e.session_id} – ${new Date(e.created_at).toLocaleString()}` +
      `  files: ${scores.files_analyzed ?? "—"}` +
      `  findings: ${scores.findings_reported ?? "—"}` +
      `  model: ${e.model_used ?? "—"}`,
  );
}

/* --------------------------------------------------------------- */
/*  SCAN                                                           */
/* --------------------------------------------------------------- */

/**
 * Run a full Leo scan (non‑interactive).
 * Session creation is handled entirely by runCoordinator.
 */
async function runScan(projectRoot: string): Promise<void> {
  const warn = narrowTerminalWarning();
  if (warn) console.error(warn);

  const cfg = await loadConfig();
  if (!cfg.openrouter_api_key) {
    console.error("⚠️  No OpenRouter API key configured. Run `leo config` first.");
    process.exit(1);
  }

  console.log(`🚀 Starting Leo scan…`);
  const result = await runCoordinator(projectRoot);
  console.log("\n=== Scan Complete ===");
  console.log(`Session ID: ${result.sessionId}`);
  console.log(`Findings discovered: ${result.totalFindings}`);
  console.log(`Patches applied: ${result.patchesApplied}`);
  console.log("Scores:", result.scores);
}

/* --------------------------------------------------------------- */
/*  CONFIG WIZARD                                                  */
/* --------------------------------------------------------------- */

async function runConfigWizard(): Promise<void> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string): Promise<string> =>
    new Promise((r) => rl.question(q, r));

  const apiKey = await ask("OpenRouter API key: ");
  const model = await ask("Default model (e.g., anthropic/claude-sonnet-4-5): ");
  const depth = await ask("Preferred scan depth (quick|deep|paranoid) [deep]: ");

  const cfg: LeoConfig = {
    openrouter_api_key: apiKey.trim(),
    default_model: model.trim() || "anthropic/claude-sonnet-4-5",
    scan_depth: (depth.trim() as LeoConfig["scan_depth"]) || "deep",
    created_at: new Date().toISOString(),
    auto_apply_patches: false,
    memory_enabled: true,
  };
  await saveConfig(cfg);
  console.log("✅ Config saved to ~/.leo/config.json");
  rl.close();
}

/* --------------------------------------------------------------- */
/*  HISTORY                                                        */
/* --------------------------------------------------------------- */

async function runHistory(): Promise<void> {
  const projRoot = process.cwd();
  const projHash = projectHash(projRoot);
  const sessionsRoot = path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? "",
    ".leo",
    "sessions",
    projHash,
  );

  let index: any[];
  try {
    const raw = await fs.readFile(path.join(sessionsRoot, "index.json"), "utf-8");
    index = JSON.parse(raw);
  } catch {
    console.log("No sessions found for this project.");
    return;
  }

  if (!index.length) {
    console.log("No sessions found for this project.");
    return;
  }

  console.log(`Session history for ${projRoot}\n`);
  for (let i = 0; i < index.length; i++) {
    const entry = index[i];
    const label = `${i + 1}`;
    try {
      const full = await loadSession(projRoot, entry.id);
      printSession(label, full);
    } catch {
      console.log(`${label}) ${entry.id} – (failed to load details)`);
    }
  }
  console.log(`\nTotal sessions: ${index.length}`);
}

/* --------------------------------------------------------------- */
/*  RESTORE                                                        */
/* --------------------------------------------------------------- */

/**
 * Restore patches from a specific session by copying .leo-backup files
 * back over their originals.
 */
async function runRestore(sessionId?: string): Promise<void> {
  const projRoot = process.cwd();

  // Resolve the session
  if (!sessionId) {
    // If no session ID provided, pick the latest one
    const sessions = await listSessions(projRoot);
    if (!sessions.length) {
      console.log("No sessions found for this project.");
      return;
    }
    sessionId = sessions[0].session_id;
    console.log(`Using latest session: ${sessionId}`);
  }

  // Load the patches.json for this session to know which files to restore
  if (!/^[a-f0-9]{6,32}$/i.test(sessionId)) { console.error("Invalid session ID."); return; }
  const projHash = projectHash(projRoot);
  const sessionDir = path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? "",
    ".leo", "sessions", projHash, sessionId,
  );

  let patches: { patches: Array<{ id: string; file: string; status: string }> };
  try {
    const raw = await fs.readFile(path.join(sessionDir, "patches.json"), "utf-8");
    patches = JSON.parse(raw);
  } catch {
    console.error(`⚠️  Could not load patches.json for session ${sessionId}.`);
    console.error("   Nothing to restore.");
    return;
  }

  let restored = 0;
  let skipped = 0;
  for (const p of patches.patches) {
    if (!p.file || path.isAbsolute(p.file) || p.file.split(/[\\/]/).includes("..")) { skipped++; console.log(`Rejected unsafe restore path: ${p.file}`); continue; }
    const targetFile = path.resolve(projRoot, p.file);
    if (!targetFile.startsWith(path.resolve(projRoot) + path.sep)) { skipped++; console.log(`Rejected restore path outside project: ${p.file}`); continue; }
    const backupName = Buffer.from(path.relative(path.resolve(projRoot), targetFile)).toString("hex") + ".bak";
    const backupFile = path.join(sessionDir, "backups", backupName);
    try {
      const realTarget = await fs.realpath(targetFile);
      if (!realTarget.startsWith(path.resolve(projRoot) + path.sep)) throw new Error("symlink target escapes project root");
      const backupContent = await fs.readFile(backupFile, "utf-8");
      await fs.writeFile(realTarget, backupContent, "utf-8");
      console.log(`Restored ${p.file} from session backup`); restored++;
    } catch { skipped++; console.log(`No session backup found for ${p.file} – skipping`); }
  }

  console.log(`\nRestore complete: ${restored} file(s) restored, ${skipped} skipped.`);
}

/* --------------------------------------------------------------- */
/*  COMMAND DEFINITIONS                                            */
/* --------------------------------------------------------------- */

export const programName = "leo";
program.name("leo").description("Leo – autonomous security auditing CLI").version("1.0.0");

export { program };

/* ---- scan ---- */
program
  .command("scan")
  .description("Run a full security scan in the current directory")
  .action(() => {
    runScan(process.cwd()).catch((e) => {
      console.error("Scan failed:", e.message);
      process.exit(1);
    });
  });

/* ---- ui ---- */
program
  .command("ui")
  .description("Launch interactive UI")
  .action(() => {
    render(React.createElement(App, {}));
  });

/* ---- resume (aliases: resume <session-id>) ---- */
program
  .command("resume [sessionId]")
  .description("Resume a previous session (or list all if no ID given)")
  .action(async (sessionId?: string) => {
    const projRoot = process.cwd();
    if (sessionId) {
      console.log(`🚀 Resuming session ${sessionId}…`);
      try {
        const result = await runCoordinator(projRoot, sessionId);
        console.log("\n=== Scan Complete ===");
        console.log(`Session ID: ${result.sessionId}`);
        console.log(`Findings: ${result.totalFindings}`);
        console.log(`Patches: ${result.patchesApplied}`);
      } catch (e: any) {
        console.error("Resume failed:", e.message);
        process.exit(1);
      }
    } else {
      const sessions = await listSessions(projRoot);
      if (!sessions.length) {
        console.log("No sessions found.");
        return;
      }
      console.log(`Available sessions for ${projRoot}:`);
      sessions.forEach((e, idx) => printSession(`${idx + 1}`, e));
    }
  });

/* ---- history ---- */
program
  .command("history")
  .description("Show previous scans for the current project")
  .action(runHistory);

/* ---- status ---- */
program
  .command("status")
  .description("Show the most recent session summary")
  .action(async () => {
    const projRoot = process.cwd();
    try {
      const sessions = await listSessions(projRoot);
      if (!sessions.length) {
        console.log("No sessions found for this project.");
        return;
      }
      const latest = sessions[0]; // listSessions returns newest-first
      console.log("--- Latest session summary ---");
      console.log(`Session ID: ${latest.session_id}`);
      console.log(`Created: ${new Date(latest.created_at).toLocaleString()}`);
      console.log("Scan statistics:", latest.scores);
      console.log(`Model used: ${latest.model_used}`);
    } catch (e) {
      console.error("⚠️  Could not read session data:", e);
    }
  });

/* ---- evaluate ---- */
program
  .command("evaluate <truthFile> <auditFile>")
  .description("Evaluate an audit.json against labeled ground truth (JSON)")
  .action(async (truthFile: string, auditFile: string) => {
    try {
      const truth = JSON.parse(await fs.readFile(path.resolve(truthFile), "utf8")) as GroundTruthCase[];
      const audit = JSON.parse(await fs.readFile(path.resolve(auditFile), "utf8"));
      if (!Array.isArray(truth) || !Array.isArray(audit?.findings)) throw new Error("Expected a ground-truth JSON array and an audit JSON object with a findings array.");
      const result = evaluateLabeledFindings(truth, audit.findings);
      console.log(JSON.stringify(result, null, 2));
    } catch (e: any) {
      console.error(`Evaluation failed: ${e.message}`);
      process.exit(1);
    }
  });

/* ---- explicit container-isolated counterexample runner ---- */
program
  .command("sandbox <fixtureDir> <image> <command...>")
  .description("Explicitly run a supplied fixture command in a network-disabled Docker/Podman container")
  .option("--runtime <runtime>", "Container runtime: docker or podman", "docker")
  .option("--timeout <ms>", "Execution timeout in milliseconds (100-30000)", (v: string) => Number(v), 5000)
  .action(async (fixtureDir: string, image: string, command: string[], opts: { runtime: string; timeout: number }) => {
    try {
      if (!["docker", "podman"].includes(opts.runtime)) throw new Error("Runtime must be docker or podman.");
      if (!Number.isFinite(opts.timeout) || opts.timeout < 100 || opts.timeout > 30000) throw new Error("Timeout must be between 100 and 30000 milliseconds.");
      const root = path.resolve(fixtureDir);
      const files: Record<string, string> = {};
      let totalBytes = 0;
      const walk = async (dir: string): Promise<void> => {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
          if ([".git", "node_modules", ".leo"].includes(entry.name)) continue;
          const full = path.join(dir, entry.name);
          if (entry.isSymbolicLink()) continue;
          if (entry.isDirectory()) await walk(full);
          else if (entry.isFile()) {
            const rel = path.relative(root, full).split(path.sep).join("/");
            const content = await fs.readFile(full);
            totalBytes += content.byteLength;
            if (Object.keys(files).length >= 5000 || totalBytes > 20 * 1024 * 1024) throw new Error("Fixture exceeds 5,000 files or 20 MiB.");
            files[rel] = content.toString("utf8");
          }
        }
      };
      await walk(root);
      const result = runCounterexampleInSandbox({ files, image, command, runtime: opts.runtime as "docker" | "podman", timeoutMs: opts.timeout });
      console.log(JSON.stringify(result, null, 2));
      if (result.status !== "executed") process.exitCode = 1;
    } catch (e: any) {
      console.error(`Sandbox execution rejected: ${e.message}`);
      process.exitCode = 1;
    }
  });

/* ---- reproducible labeled benchmark ---- */
program
  .command("benchmark <casesFile> [outputFile]")
  .description("Run deterministic security-rule regression cases and write a labeled benchmark report")
  .action(async (casesFile: string, outputFile?: string) => {
    try {
      const corpusBytes = await fs.readFile(path.resolve(casesFile));
      const cases = JSON.parse(corpusBytes.toString("utf8")) as RegressionCase[];
      if (!Array.isArray(cases) || cases.some(c => !c || typeof c.id !== "string" || typeof c.file !== "string" || typeof c.source !== "string" || !["safe", "vulnerable"].includes(c.expected))) {
        throw new Error("Expected a JSON array of {id,file,source,expected:'safe'|'vulnerable'} cases.");
      }
      const summary = runRuleRegression(cases);
      const corpusSha256 = createHash("sha256").update(corpusBytes).digest("hex");
      const report = buildBenchmarkReport(path.basename(casesFile), summary, cases.length, corpusSha256);
      const serialized = JSON.stringify({ ...report, case_results: summary.cases }, null, 2);
      if (outputFile) await fs.writeFile(path.resolve(outputFile), serialized + "\n", { mode: 0o600 });
      console.log(serialized);
    } catch (e: any) {
      console.error(`Benchmark failed: ${e.message}`);
      process.exit(1);
    }
  });

/* ---- config ---- */
program
  .command("config")
  .description("Configure Leo (API key, model, scan depth)")
  .action(runConfigWizard);

/* ---- restore ---- */
program
  .command("restore [sessionId]")
  .description("Restore original files from a session-specific backup")
  .action((sessionId?: string) => {
    runRestore(sessionId).catch((e) => {
      console.error("Restore failed:", e.message);
      process.exit(1);
    });
  });

/* ---- reset ---- */
program
  .command("reset")
  .description("Delete all Leo session data for the current project")
  .action(async () => {
    const projRoot = process.cwd();
    const projHash = projectHash(projRoot);
    const sessionsRoot = path.join(
      process.env.HOME ?? process.env.USERPROFILE ?? "",
      ".leo",
      "sessions",
      projHash,
    );
    try {
      await fs.rm(sessionsRoot, { recursive: true, force: true });
      console.log("✅ All Leo session data cleared for this project.");
    } catch (e) {
      console.error("⚠️  Failed to clear sessions:", e);
    }
  });

/* ---- global options (launch UI when called with no sub‑command) ---- */
program
  .option("--model <model>", "Override the default model for this run")
  .option("--depth <depth>", "Override scan depth for this run")
  .action(async (opts) => {
    if (process.argv.length <= 2) {
      const cfg = await loadConfig();
      if (opts.model) cfg.default_model = opts.model;
      if (opts.depth) cfg.scan_depth = opts.depth as any;
      await saveConfig(cfg);
      render(React.createElement(App, {}));
    }
  });

program.parseAsync(process.argv);
