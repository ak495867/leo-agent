import { callJsonAgent } from "../api/openrouter.js";
import { MEMORY_SYSTEM_PROMPT } from "./prompts/memory.js";
import { LeoConfig } from "../utils/config.js";
import { ReconReport } from "./recon.js";
import { ExploitMap } from "./exploit.js";
import { AuditReport } from "./audit.js";
import { PatchSet } from "./patch.js";

export interface MemoryUpdate {
  new_patterns: Array<{
    pattern_name: string;
    description: string;
    attack_class: string;
    code_signatures: string[];
    languages: string[];
  }>;
  new_patch_templates: Array<{
    vulnerability_pattern_name: string;
    language: string;
    description: string;
    before_pattern: string;
    after_pattern: string;
  }>;
  false_positives: Array<{
    pattern_name: string;
    reason: string;
    code_context: string;
  }>;
  session_score: {
    coverage_score: number;
    precision_score: number;
    patch_success_rate: number;
    novelty_score: number;
    composite_score: number;
  };
}

/**
 * Run the Memory agent.
 *   - `recon`, `exploit`, `audit`, `patchSet` — artefacts from the current session.
 *   - `sessionScore` — computed scores from the Coordinator.
 *   - `config` — API key, model, etc.
 *   - `topPatterns` — top‑50 memory‑DB patterns injected into the prompt.
 */
export async function runMemory(
  recon: ReconReport,
  exploit: ExploitMap,
  audit: AuditReport,
  patchSet: PatchSet,
  sessionScore: { coverage_score: number; precision_score: number; patch_success_rate: number; novelty_score: number; composite_score: number },
  config: LeoConfig,
  topPatterns: any[] = []
): Promise<MemoryUpdate | null> {
  const userMsg = JSON.stringify({
    recon,
    exploit,
    audit,
    patchSet,
    sessionScore,
    top_patterns: topPatterns.map((p) => ({
      pattern_name: p.pattern_name,
      description: p.description,
      attack_class: p.attack_class,
    })),
  });

  return callJsonAgent<MemoryUpdate>(
    MEMORY_SYSTEM_PROMPT,
    userMsg,
    config.default_model,
    config.openrouter_api_key
  );
}
