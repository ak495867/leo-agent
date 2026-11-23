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
  session_score?: null;
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
  sessionScore: Record<string, number | null>,
  config: LeoConfig,
  topPatterns: any[] = []
): Promise<MemoryUpdate | null> {
  // Memory extraction is a summarization task; bound its payload so a large
  // repository cannot fail an otherwise completed scan at the final stage.
  const userMsg = JSON.stringify({
    recon: { tech_stack: recon.tech_stack, entry_points: (recon.entry_points ?? []).slice(0, 80), trust_boundaries: (recon.trust_boundaries ?? []).slice(0, 80), dependencies: (recon.dependencies ?? []).slice(0, 120), complexity_hotspots: (recon.complexity_hotspots ?? []).slice(0, 60) },
    exploit: { scenarios: (exploit.scenarios ?? []).slice(0, 80) },
    audit: { findings: (audit.findings ?? []).slice(0, 100).map(f => ({ id: f.id, severity: f.severity, category: f.category, description: f.description, verification: f.verification })) },
    patchSet: { patches: (patchSet.patches ?? []).slice(0, 50).map(p => ({ vulnerability_class: p.vulnerability_class, status: p.status, commit_message: p.commit_message })) },
    sessionScore,
    top_patterns: topPatterns.slice(0, 50).map((p) => ({ pattern_name: p.pattern_name, description: p.description, attack_class: p.attack_class })),
  });

  return callJsonAgent<MemoryUpdate>(
    MEMORY_SYSTEM_PROMPT,
    userMsg,
    config.default_model,
    config.openrouter_api_key
  );
}
