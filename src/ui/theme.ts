/**
 * Theme constants for Leo TUI.
 *
 * Centralises colour names, Unicode symbols, spacing values, and
 * helper components so every screen draws from the same palette.
 * All Ink colour values use the 16 ANSI names supported everywhere.
 */

// ── Colour palette (ANSI / Ink named colours) ────────────────────
export const colors = {
  success: 'green',
  warning: 'yellow',
  error: 'red',
  info: 'cyan',
  highlight: 'blue',
  accent: 'magenta',
  muted: 'gray',
  white: 'white',
} as const;

// ── Unicode symbols ──────────────────────────────────────────────
export const sym = {
  check: '✓',
  cross: '✖',
  bullet: '○',
  dot: '·',
  arrow: '▶',
  separator: '─',
  divider: '│',

  // Progress bar characters
  progressFull: '█',
  progressEmpty: '░',

  // Box-drawing characters (for manual borders in Ink v3)
  box: {
    h: '─',
    v: '│',
    tl: '┌',
    tr: '┐',
    bl: '└',
    br: '┘',
    hd: '═',
    vd: '║',
    tld: '╔',
    trd: '╗',
    bld: '╚',
    brd: '╝',
  },

  // Step indicator
  stepDone: '✓',
  stepCurrent: '◉',
  stepPending: '○',
} as const;

// ── Spacing ──────────────────────────────────────────────────────
export const space = {
  section: 1,       // blank line between sections
  item: 0,          // blank line between items in a list
  indent: 2,        // spaces for nested content
  labelWidth: 14,   // aligned label column width
} as const;

// ── Utility helpers ──────────────────────────────────────────────

/**
 * Render a horizontal line of `char` that fills at least `minWidth`
 * columns.  Use inside a flex‑grow container to stretch to terminal width.
 */
export function hRule(char = sym.box.h, minWidth = 40): string {
  return char.repeat(minWidth);
}

/**
 * Build a labelled progress bar like:
 *   ██████░░░░  60%
 */
export function progressBar(value: number, width = 10): string {
  const filled = Math.round(Math.max(0, Math.min(1, value)) * width);
  return sym.progressFull.repeat(filled) + sym.progressEmpty.repeat(width - filled);
}

/**
 * Return a human‑readable interpretation for a score 0‑1.
 */
export function interpretScore(value: number): { label: string; color: string } {
  if (value >= 0.9) return { label: 'Excellent', color: colors.success };
  if (value >= 0.7) return { label: 'Good', color: colors.info };
  if (value >= 0.5) return { label: 'Fair', color: colors.warning };
  return { label: 'Needs Work', color: colors.error };
}

/**
 * Map internal score keys to display labels.
 */
export const SCORE_LABELS: Record<string, string> = {
  coverage_score: 'Coverage',
  precision_score: 'Precision',
  patch_success_rate: 'Patch Rate',
  novelty_score: 'Novelty',
  composite_score: 'Overall',
};

/**
 * Phase labels for the scan dashboard.
 */
export const PHASE_LABELS: Record<string, string> = {
  config: 'Config',
  snapshot: 'Snapshot',
  memory: 'Memory',
  recon: 'Recon',
  exploit: 'Exploit',
  audit: 'Audit',
  patch: 'Patch',
  apply: 'Patcher',
  'memory-update': 'Memory Update',
};
