import { promises as fs } from "node:fs";
import path from "node:path";

export interface LeoConfig {
  openrouter_api_key: string;
  default_model: string;
  scan_depth: "quick" | "deep" | "paranoid";
  created_at: string;
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
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    return JSON.parse(raw) as LeoConfig;
  } catch {
    // No config yet – write an empty placeholder
    const placeholder: LeoConfig = {
      openrouter_api_key: "",
      default_model: "",
      scan_depth: "deep",
      created_at: new Date().toISOString(),
    };
    await saveConfig(placeholder);
    return placeholder;
  }
}

/**
 * Persist the Leo configuration to ~/.leo/config.json.
 */
export async function saveConfig(cfg: LeoConfig): Promise<void> {
  const dir = configDir();
  await fs.mkdir(dir, { recursive: true });
  const filePath = path.join(dir, "config.json");
  await fs.writeFile(filePath, JSON.stringify(cfg, null, 2), "utf-8");
}
