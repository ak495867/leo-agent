/**
 * Minimal progress pub/sub for the multi‑agent scan pipeline.
 *
 * The Coordinator calls `reportProgress()` at each phase transition;
 * the ScanView subscribes via `onProgress()` and re-renders the
 * column display.
 *
 * Log entries (step‑by‑step messages) flow through a separate
 * subscription so the UI can show a live, scrolling log panel.
 */

export type PhaseStatus = "pending" | "running" | "done" | "error";

export interface ProgressEvent {
  phase: string;
  status: PhaseStatus;
  detail?: string;
}

export interface LogEntry {
  timestamp: string;   // HH:MM:SS
  phase: string;
  message: string;
}

type Listener = (evt: ProgressEvent) => void;
type LogListener = (entry: LogEntry) => void;

const listeners: Listener[] = [];
const logListeners: LogListener[] = [];

/** Maximum number of log entries kept in memory. */
const MAX_LOG = 200;
const logHistory: LogEntry[] = [];

// ── Progress events ──────────────────────────────────────────────

/** Subscribe to progress events. Returns an unsubscribe function. */
export function onProgress(cb: Listener): () => void {
  listeners.push(cb);
  return () => {
    const idx = listeners.indexOf(cb);
    if (idx !== -1) listeners.splice(idx, 1);
  };
}

/** Publish a progress event. */
export function reportProgress(
  phase: string,
  status: PhaseStatus,
  detail?: string,
): void {
  const evt: ProgressEvent = { phase, status, detail };
  for (const cb of listeners) {
    try {
      cb(evt);
    } catch {
      // Swallow listener errors – don't crash the pipeline.
    }
  }
}

// ── Log entries ──────────────────────────────────────────────────

/** Publish a step‑level log message. */
export function pushLog(phase: string, message: string): void {
  const now = new Date();
  const ts = now.toTimeString().slice(0, 8); // HH:MM:SS
  const entry: LogEntry = { timestamp: ts, phase, message };
  logHistory.push(entry);
  if (logHistory.length > MAX_LOG) logHistory.shift();
  for (const cb of logListeners) {
    try {
      cb(entry);
    } catch {
      // swallow
    }
  }
}

/** Subscribe to new log entries. Returns an unsubscribe function. */
export function onLog(cb: LogListener): () => void {
  logListeners.push(cb);
  return () => {
    const idx = logListeners.indexOf(cb);
    if (idx !== -1) logListeners.splice(idx, 1);
  };
}

/** Return all accumulated log entries (for initial hydration). */
export function getLogHistory(): LogEntry[] {
  return logHistory;
}

// ── Cleanup ──────────────────────────────────────────────────────

/** Reset all listeners and log history (useful between scans). */
export function clearListeners(): void {
  listeners.length = 0;
  logListeners.length = 0;
  logHistory.length = 0;
}

/** Clear only the log history (keeps listeners intact). */
export function clearLogHistory(): void {
  logHistory.length = 0;
}
