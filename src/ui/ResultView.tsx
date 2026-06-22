import React from 'react';
import { Box, Text } from 'ink';
import { colors, sym, SCORE_LABELS, interpretScore, progressBar } from './theme.js';

interface Props {
  result: {
    sessionId: string;
    totalFindings: number;
    patchesApplied: number;
    scores: Record<string, number>;
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

      {/* ── Score cards ──────────────────────────────── */}
      <Box
        borderStyle="single"
        borderColor="gray"
        marginTop={1}
        flexDirection="column"
        paddingX={1}
        paddingY={0}
      >
        <Box marginBottom={0}>
          <Text bold>Scores</Text>
        </Box>
        {Object.entries(result.scores).map(([k, v]) => {
          const label = SCORE_LABELS[k] ?? k;
          const pct = (v * 100).toFixed(0);
          const { label: interpretation, color } = interpretScore(v);
          return (
            <Box key={k}>
              <Box width={14}>
                <Text dimColor>{label}</Text>
              </Box>
              <Box width={14}>
                <Text>{progressBar(v)}</Text>
              </Box>
              <Box width={6}>
                <Text bold>{pct}%</Text>
              </Box>
              <Box>
                <Text color={color}>({interpretation})</Text>
              </Box>
            </Box>
          );
        })}
      </Box>

      {onExit && (
        <Box marginTop={1}>
          <Text dimColor>Press any key to exit…</Text>
        </Box>
      )}
    </Box>
  );
};
