import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { SetupFlow } from './SetupFlow.js';
import { SessionPicker } from './SessionPicker.js';
import { ScanView } from './ScanView.js';
import { ResultView } from './ResultView.js';
import { loadConfig } from '../utils/config.js';
import { colors, sym } from './theme.js';

const BORDER_COLOR = 'gray';

/**
 * Frame – wraps every screen in a consistent bordered container with a
 * status bar at the foot.
 */
const Frame: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Box flexDirection="column">
    {/* ── Main content area ─────────────────────────── */}
    <Box
      borderStyle="round"
      borderColor={BORDER_COLOR}
      flexDirection="column"
      paddingX={1}
      paddingBottom={1}
    >
      {children}
    </Box>

    {/* ── Status bar ────────────────────────────────── */}
    <Box>
      <Text dimColor>
        {sym.box.h} leo v0.1.0 {sym.box.h}{' '}
        Autonomous Security Auditing CLI
      </Text>
    </Box>
  </Box>
);

/** Simple error boundary independent of Ink's event loop. */
function renderError(msg: string) {
  return (
    <Frame>
      <Box flexDirection="column">
        <Box>
          <Text color={colors.error}>
            {sym.cross}  Error
          </Text>
        </Box>
        <Box marginTop={1}>
          <Text color={colors.error}>{msg}</Text>
        </Box>
      </Box>
    </Frame>
  );
}

export const App: React.FC = () => {
  const [configReady, setConfigReady] = useState<boolean>(false);
  const [showPicker, setShowPicker] = useState<boolean>(false);
  const [projectRoot, setProjectRoot] = useState<string>('');
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<any>(null);
  const [fatalError, setFatalError] = useState<string | null>(null);

  // On mount, determine if config exists
  useEffect(() => {
    (async () => {
      try {
        const cfg = await loadConfig();
        if (cfg.openrouter_api_key) {
          setConfigReady(true);
          setShowPicker(true);
          setProjectRoot(process.cwd());
        } else {
          setConfigReady(false);
        }
      } catch (err: any) {
        setFatalError(err?.message ?? 'Failed to load configuration');
      }
    })();
  }, []);

  // When a session is selected (null = new scan)
  const handleSessionSelect = (sessionId: string | null) => {
    setSelectedSession(sessionId);
    setShowPicker(false);
    // For now we only support a fresh scan; future code could load a past session.
  };

  // When ScanView finishes, show results
  const handleScanComplete = (result: any) => {
    setScanResult(result);
  };

  // ── Error state ────────────────────────────────────
  if (fatalError) return renderError(fatalError);

  // ── Setup wizard ───────────────────────────────────
  if (!configReady) {
    return (
      <Frame>
        <SetupFlow onComplete={() => setConfigReady(true)} />
      </Frame>
    );
  }

  // ── Session picker ─────────────────────────────────
  if (showPicker) {
    return (
      <Frame>
        <SessionPicker
          projectRoot={projectRoot}
          onSelect={handleSessionSelect}
        />
      </Frame>
    );
  }

  // ── Scan running ───────────────────────────────────
  if (selectedSession === null && !scanResult) {
    return (
      <Frame>
        <ScanView projectRoot={projectRoot} onComplete={handleScanComplete} />
      </Frame>
    );
  }

  // ── Scan results ───────────────────────────────────
  if (scanResult) {
    return (
      <Frame>
        <ResultView result={scanResult} />
      </Frame>
    );
  }

  // Fallback (should not reach)
  return renderError('Unexpected state – exiting.');
};
