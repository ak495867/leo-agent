import path from "node:path";
import { promises as fs } from "node:fs";
import { projectHash } from "../utils/hash.js";

/**
 * Information stored in each session's `session.json`.
 */
export interface SessionMeta {
  session_id: string;
  project_hash: string;
  created_at: string; // ISO timestamp
  config_snapshot?: any; // copy of LeoConfig at start of session
  scores?: {
    coverage_score?: number;
    precision_score?: number;
    patch_success_rate?: number;
    novelty_score?: number;
    composite_score?: number;
  };
  model_used?: string;
}

/**
 * Helper to get the base directory where all Leo session data lives.
 * Path: ~/.leo/sessions/<project‑hash>
 */
function getProjectSessionRoot(projectRoot: string): string {
  const hash = projectHash(projectRoot);
  const base = path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? "",
    ".leo",
    "sessions",
    hash
  );
  return base;
}

/**
 * Create a brand‑new session directory and write its metadata.
 * Returns the full path to the session directory and the metadata object.
 */
export async function createSession(
  projectRoot: string,
  metaOverrides: Partial<SessionMeta> = {}
): Promise<{ sessionDir: string; meta: SessionMeta }> {
  const projHash = projectHash(projectRoot);
  const sessionsRoot = getProjectSessionRoot(projectRoot);
  await fs.mkdir(sessionsRoot, { recursive: true });

  // short 6‑char hex ID (derived from timestamp)
  const sessionId = Date.now().toString(16).slice(-6);
  const sessionDir = path.join(sessionsRoot, sessionId);
  await fs.mkdir(sessionDir, { recursive: true });

  const meta: SessionMeta = {
    session_id: sessionId,
    project_hash: projHash,
    created_at: new Date().toISOString(),
    ...metaOverrides,
  };

  // write session.json
  const sessionPath = path.join(sessionDir, "session.json");
  await fs.writeFile(sessionPath, JSON.stringify(meta, null, 2), "utf-8");

  // update the per‑project index (append entry)
  const indexPath = path.join(sessionsRoot, "index.json");
  let index: any[] = [];
  try {
    const raw = await fs.readFile(indexPath, "utf-8");
    index = JSON.parse(raw);
  } catch {
    // file may not exist yet – start with empty array
  }
  index.push({
    id: sessionId,
    created_at: meta.created_at,
    scores: meta.scores ?? {},
    model_used: meta.model_used ?? "",
  });
  await fs.writeFile(indexPath, JSON.stringify(index, null, 2), "utf-8");

  return { sessionDir, meta };
}

/**
 * Load a previously‑saved session's metadata.
 */
export async function loadSession(
  projectRoot: string,
  sessionId: string
): Promise<SessionMeta> {
  const sessionDir = path.join(getProjectSessionRoot(projectRoot), sessionId);
  const sessionPath = path.join(sessionDir, "session.json");
  const raw = await fs.readFile(sessionPath, "utf-8");
  return JSON.parse(raw) as SessionMeta;
}

/**
 * List all sessions for the given project, sorted newest ➜ oldest.
 */
export async function listSessions(
  projectRoot: string
): Promise<SessionMeta[]> {
  const sessionsRoot = getProjectSessionRoot(projectRoot);
  const indexPath = path.join(sessionsRoot, "index.json");
  try {
    const raw = await fs.readFile(indexPath, "utf-8");
    const entries = JSON.parse(raw) as Array<{ id: string; created_at: string; scores?: any; model_used?: string }>;
    // Load each session's full meta for completeness (optional – we could just return shallow data)
    const metas: SessionMeta[] = [];
    for (const e of entries) {
      const meta = await loadSession(projectRoot, e.id);
      metas.push(meta);
    }
    // sort by created_at descending
    metas.sort((a, b) => (b.created_at > a.created_at ? 1 : -1));
    return metas;
  } catch {
    // No index means no sessions yet
    return [];
  }
}
