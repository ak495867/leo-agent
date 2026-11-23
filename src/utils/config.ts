import { promises as fs } from "node:fs";
import path from "node:path";

export interface LeoConfig {
  openrouter_api_key: string;
  default_model: string;
  scan_depth: "quick" | "deep" | "paranoid";
  created_at: string;
  auto_apply_patches?: boolean;
  memory_enabled?: boolean;
}

/** Resolve the config directory path (always ~/.leo). */
function configDir(): string {
  return path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? "",
    ".leo",
  );
}

/** Resolve the config file path (always ~/.leo/config.json). */
function configPath(): string {
  return path.join(configDir(), "config.json");
}

/**
 * Load the Leo configuration from ~/.leo/config.json.
 *
 * If the file does not exist a placeholder with empty fields is saved
 * and returned — the SetupFlow UI (or `leo config`) will fill it in.
 */
export async function loadConfig(): Promise<LeoConfig> {
  const filePath = configPath();
  let raw: string;
  try { raw = await fs.readFile(filePath, "utf-8"); }
  catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    const placeholder: LeoConfig = {
      openrouter_api_key: process.env.OPENROUTER_API_KEY ?? "",
      default_model: "anthropic/claude-sonnet-4-5",
      scan_depth: "deep",
      created_at: new Date().toISOString(),
      auto_apply_patches: false,
      memory_enabled: true,
    };
    await saveConfig(placeholder);
    return placeholder;
  }
  let cfg: LeoConfig;
  try { cfg = JSON.parse(raw) as LeoConfig; }
  catch { throw new Error(`Invalid JSON in ${filePath}. Fix the file; Leo will not overwrite a malformed configuration.`); }
  if (!cfg || typeof cfg !== "object") throw new Error(`Invalid configuration in ${filePath}.`);
  cfg.openrouter_api_key = process.env.OPENROUTER_API_KEY || cfg.openrouter_api_key || "";
  cfg.default_model = cfg.default_model || "anthropic/claude-sonnet-4-5";
  if (!["quick", "deep", "paranoid"].includes(cfg.scan_depth)) cfg.scan_depth = "deep";
  if (typeof cfg.auto_apply_patches !== "boolean") cfg.auto_apply_patches = false;
  if (typeof cfg.memory_enabled !== "boolean") cfg.memory_enabled = true;
  return cfg;
}

/**
 * Persist the Leo configuration to ~/.leo/config.json.
 */
export async function saveConfig(cfg: LeoConfig): Promise<void> {
  const dir = configDir();
  await fs.mkdir(dir, { recursive: true });
  const filePath = path.join(dir, "config.json");
  await fs.writeFile(filePath, JSON.stringify(cfg, null, 2), { encoding: "utf-8", mode: 0o600 });
  try { await fs.chmod(filePath, 0o600); } catch { /* Windows ACLs govern permissions there. */ }
}
