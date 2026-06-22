import { callJsonAgent } from "../api/openrouter.js";
import { PATCH_SYSTEM_PROMPT } from "./prompts/patch.js";
import { LeoConfig } from "../utils/config.js";
import { ExploitMap } from "./exploit.js";
import { AuditReport } from "./audit.js";

export interface Patch {
  id: string;
  finding_ref: string;
  file: string;
  original_block: string;
  patched_block: string;
  commit_message: string;
  vulnerability_class: string;
  new_dependencies: string[];
  status: "READY" | "DEFERRED";
  deferred_reason?: string;
}

export interface PatchSet {
  patches: Patch[];
}

/**
 * Run the Patch agent.
 *   - `exploit` — output of the Exploit agent.
 *   - `audit` — output of the Audit agent.
 *   - `snapshot` — original file contents.
 *   - `config` — API key, model, etc.
 *   - `topPatterns` — top‑50 memory‑DB patterns injected into the prompt.
 */
export async function runPatch(
  exploit: ExploitMap,
  audit: AuditReport,
  snapshot: { files: Record<string, string> },
  config: LeoConfig,
  topPatterns: any[] = []
): Promise<PatchSet | null> {
  const userMsg = JSON.stringify({
    exploit,
    audit,
    files: snapshot.files,
    top_patterns: topPatterns.map((p) => ({
      pattern_name: p.pattern_name,
      description: p.description,
      attack_class: p.attack_class,
    })),
  });

  return callJsonAgent<PatchSet>(
    PATCH_SYSTEM_PROMPT,
    userMsg,
    config.default_model,
    config.openrouter_api_key
  );
}
