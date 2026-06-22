import { callJsonAgent } from "../api/openrouter.js";
import { AUDIT_SYSTEM_PROMPT } from "./prompts/audit.js";
import { LeoConfig } from "../utils/config.js";
import { ReconReport } from "./recon.js";
import { ExploitMap } from "./exploit.js";

export interface AuditFinding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  file: string;
  line: number;
  category: string;
  description: string;
  exploit_map_ref?: string;
}

export interface AuditReport {
  findings: AuditFinding[];
}

/**
 * Run the Audit agent.
 *   - `recon` — output of the Recon agent.
 *   - `exploit` — output of the Exploit agent (used for cross‑reference).
 *   - `snapshot` — original file contents.
 *   - `config` — API key, model, etc.
 *   - `topPatterns` — top‑50 memory‑DB patterns injected into the prompt.
 */
export async function runAudit(
  recon: ReconReport,
  exploit: ExploitMap,
  snapshot: { files: Record<string, string> },
  config: LeoConfig,
  topPatterns: any[] = []
): Promise<AuditReport | null> {
  const userMsg = JSON.stringify({
    recon,
    exploit,
    files: snapshot.files,
    top_patterns: topPatterns.map((p) => ({
      pattern_name: p.pattern_name,
      description: p.description,
      attack_class: p.attack_class,
    })),
  });

  return callJsonAgent<AuditReport>(
    AUDIT_SYSTEM_PROMPT,
    userMsg,
    config.default_model,
    config.openrouter_api_key
  );
}
