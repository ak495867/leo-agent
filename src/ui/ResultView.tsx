import React from 'react';
import { Box, Text } from 'ink';
import { colors, sym } from './theme.js';

interface Props {
  result: {
    sessionId: string;
    totalFindings: number;
    patchesApplied: number;
    scores: Record<string, number | null>;
  };
  onExit?: () => void;
}

export const ResultView: React.FC<Props> = ({ result, onExit }) => {
  return (
    <Box flexDirection="column">
      {/* ── Header ─────────────────────────────────── */}
      <Box
        borderStyle="single"
        borderColor={colors.success}
        paddingX={1}
      >
        <Box>
          <Text bold color={colors.success}>
            {sym.check}  Scan Complete
          </Text>
        </Box>
        <Box marginTop={1}>
          <Text dimColor>
            Session:{' '}
            <Text bold color={colors.white}>
              {result.sessionId}
            </Text>
          </Text>
        </Box>
      </Box>

      {/* ── Summary counts card ─────────────────────── */}
      <Box
        borderStyle="single"
        borderColor="gray"
        marginTop={1}
        flexDirection="column"
        paddingX={1}
      >
        <Box>
          <Text>
            <Text color={colors.warning} bold>
              {sym.dot}
            </Text>{' '}
            Findings:{' '}
            <Text bold color={colors.warning}>
              {result.totalFindings}
            </Text>
          </Text>
        </Box>
        <Box>
          <Text>
            <Text color={colors.success} bold>
              {sym.dot}
            </Text>{' '}
            Patches:{' '}
            <Text bold color={colors.success}>
              {result.patchesApplied}
            </Text>
          </Text>
        </Box>
      </Box>

      {/* ── Operational audit summary ───────────────── */}
      <Box
        borderStyle="single"
        borderColor="gray"
        marginTop={1}
        flexDirection="column"
        paddingX={1}
        paddingY={0}
      >
        <Box marginBottom={0}>
          <Text bold>Audit Summary</Text>
        </Box>
        {([
          ['files_analyzed', 'Files analyzed'],
          ['files_skipped', 'Files skipped'],
          ['batches_processed', 'Batches processed'],
          ['exploit_scenarios', 'Exploit scenarios'],
          ['findings_reported', 'Findings retained'],
          ['verified_findings', 'Confirmed findings'],
          ['needs_review_findings', 'Needs review'],
          ['taint_candidates', 'Taint candidates'],
          ['dependencies_queried', 'Dependencies queried'],
          ['cross_file_chains', 'Cross-file chains'],
          ['patches_proposed', 'Patches proposed'],
          ['patches_applied', 'Patches applied'],
        ] as Array<[string, string]>).map(([key, label]) => {
          const value = result.scores[key];
          if (typeof value !== 'number') return null;
          return (
            <Box key={key}>
              <Box width={25}><Text dimColor>{label}</Text></Box>
              <Text bold>{value}</Text>
            </Box>
          );
        })}
        <Box>
          <Box width={25}><Text dimColor>OSV lookup</Text></Box>
          <Text color={result.scores.dependency_scan_available === 1 ? colors.success : colors.warning}>
            {result.scores.dependency_scan_available === 1 ? 'Available' : 'Unavailable / partial'}
          </Text>
        </Box>
      </Box>

      {onExit && (
        <Box marginTop={1}>
          <Text dimColor>Press any key to exit…</Text>
        </Box>
      )}
    </Box>
  );
};
