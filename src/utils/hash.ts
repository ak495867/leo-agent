import { createHash } from "node:crypto";
import path from "node:path";

/**
 * Return a SHA‑256 hash of the absolute project path.
 * Truncated to the first 12 hex characters for readability.
 */
export function projectHash(projectRoot: string): string {
  const abs = path.resolve(projectRoot);
  const hash = createHash("sha256").update(abs).digest("hex");
  return hash.slice(0, 12);
}
