import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import SelectInput from 'ink-select-input';
import { listSessions, SessionMeta } from '../core/session.js';
import { colors, sym } from './theme.js';

interface Props {
  projectRoot: string;
  onSelect: (sessionId: string | null) => void;
}

export const SessionPicker: React.FC<Props> = ({ projectRoot, onSelect }) => {
  const [sessions, setSessions] = useState<SessionMeta[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const list = await listSessions(projectRoot);
      setSessions(list);
      setLoading(false);
    })();
  }, []);

  if (loading) {
    return (
      <Box>
        <Text>
          <Spinner type="dots" /> Loading previous sessions…
        </Text>
      </Box>
    );
  }

  const items = sessions.map((sess) => ({
    label: `${sess.session_id}  ${sym.dot}  ${new Date(sess.created_at).toLocaleString()}`,
    value: sess.session_id,
  }));
  items.unshift({ label: `${sym.arrow}  Start a new scan`, value: 'new' });

  const handleSelect = (item: { label: string; value: string | number }) => {
    if (item.value === 'new') {
      onSelect(null);
    } else {
      onSelect(item.value as string);
    }
  };

  return (
    <Box flexDirection="column">
      {/* Header */}
      <Box>
        <Text bold color={colors.info}>
          Leo
        </Text>
        <Text dimColor> — Autonomous Security Audit</Text>
      </Box>

      {/* Session count badge */}
      {sessions.length > 0 && (
        <Box
          borderStyle="single"
          borderColor="gray"
          marginTop={1}
          marginBottom={1}
          paddingX={1}
        >
          <Text dimColor>
            Previous sessions:{' '}
            <Text bold color={colors.white}>
              {sessions.length}
            </Text>
          </Text>
        </Box>
      )}

      {/* Separator */}
      <Box>
        <Text dimColor>Select an option:</Text>
      </Box>

      <SelectInput items={items} onSelect={handleSelect} />
    </Box>
  );
};
