import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { runCoordinator } from '../agents/coordinator';
import { onProgress, onLog, getLogHistory, clearLogHistory, PhaseStatus, LogEntry } from '../utils/progress';
import { colors, sym, PHASE_LABELS, progressBar } from './theme.js';

interface Props {
  projectRoot: string;
  onComplete: (result: any) => void;
}

interface PhaseInfo {
  label: string;
  status: PhaseStatus;
  detail?: string;
}

/** Ordered phase definitions — groups are separated visually. */
const PHASES = [
  { key: 'config', group: 'init' },
  { key: 'snapshot', group: 'init' },
  { key: 'memory', group: 'init' },
  { key: 'recon', group: 'analysis' },
  { key: 'exploit', group: 'analysis' },
  { key: 'audit', group: 'analysis' },
  { key: 'patch', group: 'remediation' },
  { key: 'apply', group: 'remediation' },
  { key: 'memory-update', group: 'finalize' },
] as const;

const GROUPS = [
  { id: 'init', label: 'Preparation' },
  { id: 'analysis', label: 'Analysis & Exploitation' },
  { id: 'remediation', label: 'Remediation' },
  { id: 'finalize', label: 'Finalize' },
] as const;

const PHASE_DEFS = PHASES.map((p) => ({
  key: p.key,
  label: PHASE_LABELS[p.key] ?? p.key,
  group: p.group,
}));

export const ScanView: React.FC<Props> = ({ projectRoot, onComplete }) => {
  const [phases, setPhases] = useState<Record<string, PhaseInfo>>(() => {
    const map: Record<string, PhaseInfo> = {};
    for (const p of PHASE_DEFS) {
      map[p.key] = { label: p.label, status: 'pending' };
    }
    return map;
  });
  const [summary, setSummary] = useState<any>(null);
  const [done, setDone] = useState(false);
  const [logEntries, setLogEntries] = useState<LogEntry[]>(() => getLogHistory());

  useEffect(() => {
    let cancelled = false;

    // Start fresh — discard stale log entries from prior sessions
    clearLogHistory();
    setLogEntries([]);

    const unsub = onProgress((evt) => {
      if (cancelled) return;
      setPhases((prev) => ({
        ...prev,
        [evt.phase]: {
          label:
            PHASE_DEFS.find((p) => p.key === evt.phase)?.label ?? evt.phase,
          status: evt.status,
          detail: evt.detail,
        },
      }));
    });

    const unsubLog = onLog((entry) => {
      if (cancelled) return;
      setLogEntries((prev) => {
        const next = [...prev, entry];
        return next.length > 100 ? next.slice(-100) : next;
      });
    });

    (async () => {
      try {
        const result = await runCoordinator(projectRoot);
        if (cancelled) return;
        setSummary(result);
        setDone(true);
        onComplete(result);
      } catch (err: any) {
        if (cancelled) return;
        // Normalise common Node.js runtime errors
        const raw = err?.message ?? String(err);
        let friendly: string;
        if (raw === "terminated" || raw.includes("terminated")) {
          friendly = "Scan interrupted — the process was terminated, possibly by Ctrl+C";
        } else if (raw.includes("fetch failed")) {
          friendly = `Network error — could not reach the API. Check your internet connection.\n  ${raw}`;
        } else {
          friendly = raw;
        }
        setSummary({ error: friendly });
        setDone(true);
        onComplete(null);
      }
    })();

    return () => {
      cancelled = true;
      unsub();
      unsubLog();
    };
  }, []);

  // ── Derive aggregate state ──────────────────────────
  const doneCount = PHASE_DEFS.filter(
    (p) => phases[p.key]?.status === 'done',
  ).length;
  const totalCount = PHASE_DEFS.length;
  const pct = totalCount > 0 ? doneCount / totalCount : 0;

  // ── Done state ──────────────────────────────────────
  if (done) {
    if (summary?.error) {
      return (
        <Box flexDirection="column">
          <Box
            borderStyle="single"
            borderColor={colors.error}
            flexDirection="column"
            paddingX={1}
            paddingY={0}
          >
            <Box>
              <Text color={colors.error}>
                {sym.cross}  Scan failed
              </Text>
            </Box>
            <Box marginTop={1}>
              <Text color={colors.error}>{summary.error}</Text>
            </Box>
          </Box>
        </Box>
      );
    }

    return (
      <Box flexDirection="column">
        {/* Complete banner */}
        <Box
          borderStyle="single"
          borderColor={colors.success}
          flexDirection="column"
          paddingX={1}
          paddingY={0}
          marginBottom={1}
        >
          <Box>
            <Text bold color={colors.success}>
              {sym.check}  Scan complete
            </Text>
          </Box>

          {/* Phase summary */}
          <Box flexDirection="column" marginTop={1}>
            {PHASE_DEFS.map((p) => {
              const info = phases[p.key];
              if (!info || info.status === 'pending') return null;
              const mark =
                info.status === 'done'
                  ? sym.check
                  : sym.cross;
              const c = info.status === 'done' ? colors.success : colors.error;
              return (
                <Box key={p.key}>
                  <Box width={2}>
                    <Text color={c}>{mark}</Text>
                  </Box>
                  <Box width={14}>
                    <Text color={c}>{info.label}</Text>
                  </Box>
                  {info.detail ? (
                    <Text dimColor>— {info.detail}</Text>
                  ) : null}
                </Box>
              );
            })}
          </Box>

          {/* Results card */}
          <Box
            borderStyle="single"
            borderColor="gray"
            marginTop={1}
            paddingX={1}
          >
            <Text>
              Findings:{' '}
              <Text bold color={colors.warning}>
                {summary.totalFindings}
              </Text>
              <Text dimColor>  {sym.divider}  </Text>
              Patches:{' '}
              <Text bold color={colors.success}>
                {summary.patchesApplied}
              </Text>
            </Text>
          </Box>
        </Box>
      </Box>
    );
  }

  // ── Running state ───────────────────────────────────
  const currentPhaseKey = PHASE_DEFS.find(
    (p) => phases[p.key]?.status === 'running',
  )?.key;
  const currentPhase = currentPhaseKey ? phases[currentPhaseKey] : null;

  return (
    <Box flexDirection="column">
      {/* Dashboard header */}
      <Box>
        <Text bold color={colors.info}>
          Leo
        </Text>
        <Text dimColor> — Autonomous Security Scan</Text>
      </Box>

      {/* Progress summary bar */}
      <Box
        borderStyle="single"
        borderColor="gray"
        marginTop={1}
        paddingX={1}
      >
        <Box flexGrow={1}>
          <Text>
            {progressBar(pct, 20)}{'  '}
            <Text bold>{doneCount}</Text>
            <Text dimColor>/{totalCount}</Text>
          </Text>
        </Box>
        {currentPhase ? (
          <Box>
            <Text dimColor>Current: </Text>
            <Text bold color={colors.warning}>
              {currentPhase.label}
            </Text>
          </Box>
        ) : null}
      </Box>

      {/* Phase groups */}
      <Box flexDirection="column" marginTop={1}>
        {GROUPS.map((g) => {
          const groupPhases = PHASE_DEFS.filter((p) => p.group === g.id);
          const groupStarted = groupPhases.some(
            (p) =>
              phases[p.key]?.status === 'running' ||
              phases[p.key]?.status === 'done' ||
              phases[p.key]?.status === 'error',
          );
          if (!groupStarted) return null;

          return (
            <Box key={g.id} flexDirection="column">
              <Box>
                <Text bold dimColor>
                  {sym.box.h} {g.label} {sym.box.h}
                </Text>
              </Box>
              {groupPhases.map((p) => {
                const info = phases[p.key];
                if (!info) return null;

                const isRunning = info.status === 'running';
                const isDone = info.status === 'done';
                const isError = info.status === 'error';
                const isPending = info.status === 'pending';
                const isActive = isRunning || isDone || isError;

                let icon: React.ReactNode;
                let iconColor: string;

                if (isRunning) {
                  icon = <Spinner type="dots" />;
                  iconColor = colors.warning;
                } else if (isDone) {
                  icon = <Text color={colors.success}>{sym.check}</Text>;
                  iconColor = colors.success;
                } else if (isError) {
                  icon = <Text color={colors.error}>{sym.cross}</Text>;
                  iconColor = colors.error;
                } else {
                  icon = <Text dimColor>{sym.bullet}</Text>;
                  iconColor = colors.muted;
                }

                const detailText =
                  info.detail ??
                  (isRunning
                    ? 'Running…'
                    : isDone
                      ? ''
                      : isPending
                        ? ''
                        : '');

                return (
                  <Box key={p.key} marginLeft={1}>
                    <Box width={3} marginRight={1}>
                      {icon}
                    </Box>
                    <Box width={14}>
                      <Text
                        color={isActive ? iconColor : colors.muted}
                        bold={isRunning}
                      >
                        {info.label}
                      </Text>
                    </Box>
                    {detailText ? (
                      <Text color={iconColor} italic={isPending}>
                        {detailText}
                      </Text>
                    ) : null}
                  </Box>
                );
              })}
              {/* Blank line between groups */}
              <Box marginBottom={0} />
            </Box>
          );
        })}
      </Box>

      {/* ── Live log panel ──────────────────────────── */}
      {logEntries.length > 0 && (
        <Box
          borderStyle="single"
          borderColor="gray"
          marginTop={1}
          flexDirection="column"
          paddingX={1}
        >
          <Box>
            <Text bold dimColor>
              Step Log
            </Text>
          </Box>
          <Box flexDirection="column" marginTop={0}>
            {logEntries
              .slice(-12)
              .reverse()
              .map((entry, i) => (
                <Box key={logEntries.length - 1 - i}>
                  <Box width={10}>
                    <Text dimColor>{entry.timestamp}</Text>
                  </Box>
                  <Box width={10}>
                    <Text color={colors.info}>{entry.phase}</Text>
                  </Box>
                  <Text wrap="truncate">{entry.message}</Text>
                </Box>
              ))}
          </Box>
        </Box>
      )}
    </Box>
  );
};
