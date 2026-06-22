/**
 * Terminal‑aware helpers.
 *
 * Provides a terminal‑width check and a simple banner formatter.
 */
import { stdout } from "node:process";

/** Minimum column count Leo expects for a comfortable layout. */
export const MIN_COLS = 80;

/**
 * Return `true` when the terminal is wide enough.
 */
export function isTerminalWide(min: number = MIN_COLS): boolean {
  return stdout.columns !== undefined && stdout.columns >= min;
}

/**
 * Return a warning string if the terminal is too narrow, or empty string.
 */
export function narrowTerminalWarning(min: number = MIN_COLS): string {
  if (stdout.columns === undefined) return ""; // non‑interactive – skip
  if (stdout.columns < min) {
    const cols = stdout.columns;
    return `⚠️  Terminal is ${cols} columns wide. Leo works best at ≥ ${min} columns.\n   Some UI elements may wrap.\n`;
  }
  return "";
}

export const LEO_BANNER = `
╔══════════════════════════════════════════════════════╗
║                                                      ║
║    ██╗     ███████╗ ██████╗                          ║
║    ██║     ██╔════╝██╔═══██╗                         ║
║    ██║     █████╗  ██║   ██║                         ║
║    ██║     ██╔══╝  ██║   ██║                         ║
║    ███████╗███████╗╚██████╔╝                         ║
║    ╚══════╝╚══════╝ ╚═════╝                          ║
║                                                      ║
║    Autonomous Security Auditing CLI                  ║
║    v0.1.0                                            ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
`;
