import { program } from "commander";
import path from "node:path";
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
      `  scores: ${scores.composite_score?.toFixed(2) ?? "—"}` +
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
  let totalFindings = 0;
  let totalPatches = 0;
  for (let i = 0; i < index.length; i++) {
    const entry = index[i];
    const label = `${i + 1}`;
    try {
      const full = await loadSession(projRoot, entry.id);
      printSession(label, full);
      totalFindings +=
        (full.scores?.composite_score ?? 0) > 0 ? 1 : 0;
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
  const projHash = projectHash(projRoot);
  const sessionDir = path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? "",
    ".leo",
    "sessions",
    projHash,
    sessionId,
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
    const targetFile = path.resolve(projRoot, p.file);
    const backupFile = targetFile + ".leo-backup";

    try {
      await fs.access(backupFile);
      const backupContent = await fs.readFile(backupFile, "utf-8");
      await fs.writeFile(targetFile, backupContent, "utf-8");
      console.log(`✅ Restored ${p.file} from backup`);
      restored++;
    } catch {
      skipped++;
      console.log(`⚠️  No backup found for ${p.file} – skipping`);
    }
  }

  console.log(`\nRestore complete: ${restored} file(s) restored, ${skipped} skipped.`);
}

/* --------------------------------------------------------------- */
/*  COMMAND DEFINITIONS                                            */
/* --------------------------------------------------------------- */

export const programName = "leo";
program.name("leo").description("Leo – autonomous security auditing CLI").version("0.1.0");

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
  .description("Show session history with stats for the current project")
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
      console.log("Scores:", latest.scores);
      console.log(`Model used: ${latest.model_used}`);
    } catch (e) {
      console.error("⚠️  Could not read session data:", e);
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
  .description("Restore patched files from a session's .leo-backup files")
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
