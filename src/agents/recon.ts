import { callJsonAgent } from "../api/openrouter.js";
import { RECON_SYSTEM_PROMPT } from "./prompts/recon.js";
import { CodebaseSnapshot } from "../core/snapshot.js";
import { LeoConfig } from "../utils/config.js";

export interface ReconReport {
  project_hash: string;
  scanned_at: string;
  tech_stack: {
    languages: string[];
    frameworks: string[];
    runtime_versions: Record<string, string>;
    package_managers: string[];
  };
  entry_points: Array<{
    file: string;
    line: number;
    type: "http_route" | "websocket" | "cli_arg" | "file_upload" | "ipc" | "other";
    method?: string;
    path?: string;
    accepts_external_input: boolean;
  }>;
  trust_boundaries: Array<{
    file: string;
    line: number;
    description: string;
    auth_present: boolean;
  }>;
  dependencies: Array<{
    name: string;
    version: string;
    known_cve?: string[];
  }>;
  complexity_hotspots: Array<{
    file: string;
    reason: string;
    severity: "HIGH" | "MEDIUM" | "LOW";
  }>;
  secrets_surface: Array<{
    file: string;
    line: number;
    pattern_matched: string;
    redacted_value: string;
  }>;
}

/**
 * Run the Recon agent.
 *   - `snapshot` provides the directory tree and file contents.
 *   - `config` supplies API key, model, etc.
 *   - `topPatterns` — top‑50 memory‑DB patterns injected into the prompt.
 *   - Returns a parsed ReconReport, or null if parsing failed after retries.
 */
export async function runRecon(
  snapshot: CodebaseSnapshot,
  config: LeoConfig,
  topPatterns: any[] = []
): Promise<ReconReport | null> {
  const userMsg = JSON.stringify({
    root: snapshot.root,
    file_count: snapshot.file_count,
    directory_tree: snapshot.directory_tree,
    top_patterns: topPatterns.map((p) => ({
      pattern_name: p.pattern_name,
      description: p.description,
      attack_class: p.attack_class,
      confidence_weight: p.confidence_weight,
    })),
  });

  return callJsonAgent<ReconReport>(
    RECON_SYSTEM_PROMPT,
    userMsg,
    config.default_model,
    config.openrouter_api_key
  );
}
