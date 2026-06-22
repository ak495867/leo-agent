import React, { useState } from 'react';
import { Text, Box } from 'ink';
import TextInput from 'ink-text-input';
import SelectInput from 'ink-select-input';
import { saveConfig, LeoConfig } from '../utils/config.js';
import { LEO_BANNER, narrowTerminalWarning } from '../utils/terminal.js';
import { colors, sym } from './theme.js';

const models = [
  { label: 'anthropic/claude-sonnet-4-5', value: 'anthropic/claude-sonnet-4-5' },
  { label: 'openai/gpt-4o', value: 'openai/gpt-4o' },
  { label: 'meta-llama/llama-3.1-405b-instruct', value: 'meta-llama/llama-3.1-405b-instruct' },
  { label: 'Custom (enter manually)', value: 'custom' },
];

const depths = [
  { label: 'Quick', value: 'quick' },
  { label: 'Deep (default)', value: 'deep' },
  { label: 'Paranoid', value: 'paranoid' },
];

const STEP_LABELS = ['API Key', 'Model', 'Custom Model', 'Depth', 'Save'];

// ── Step indicator ───────────────────────────────────────────────
function StepIndicator({ current }: { current: number }) {
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Box>
        {STEP_LABELS.map((label, i) => {
          let symbol: string;
          let color: string;
          if (i < current) {
            symbol = sym.stepDone;
            color = colors.success;
          } else if (i === current) {
            symbol = sym.stepCurrent;
            color = colors.info;
          } else {
            symbol = sym.stepPending;
            color = colors.muted;
          }
          // Skip showing custom model step in the indicator unless relevant
          const show = i !== 2 || label === 'Custom Model';
          if (!show) return null;

          return (
            <Box key={label} marginRight={2}>
              <Text color={color}>
                {symbol} {label}
              </Text>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}

export const SetupFlow: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
  const [step, setStep] = useState(0);
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState(models[0].value);
  const [customModel, setCustomModel] = useState('');
  const [depth, setDepth] = useState(depths[1].value);

  const handleSubmit = async () => {
    const cfg: LeoConfig = {
      openrouter_api_key: apiKey.trim(),
      default_model: model === 'custom' ? customModel.trim() : model,
      scan_depth: depth as any,
      created_at: new Date().toISOString(),
    };
    await saveConfig(cfg);
    onComplete();
  };

  /** Advance step, skipping the custom-model sub-step unless needed. */
  const advance = (next: number) => {
    if (next === 2 && model !== 'custom') {
      setStep(3);
    } else {
      setStep(next);
    }
  };

  const warning = narrowTerminalWarning();

  // ── Step content ───────────────────────────────────
  const renderBody = () => {
    switch (step) {
      case 0:
        return (
          <Box flexDirection="column">
            <Box flexDirection="column" marginBottom={1}>
              <Text color={colors.info}>{LEO_BANNER}</Text>
              {warning ? <Text color={colors.warning}>{warning}</Text> : null}
            </Box>
            <Box>
              <Text>Enter your OpenRouter API key:</Text>
            </Box>
            <Box marginTop={0}>
              <TextInput
                value={apiKey}
                onChange={setApiKey}
                onSubmit={() => advance(1)}
                placeholder="sk-or-..."
              />
            </Box>
          </Box>
        );

      case 1:
        return (
          <Box flexDirection="column">
            <Box marginBottom={0}>
              <Text>Select your default model:</Text>
            </Box>
            <SelectInput
              items={models}
              onSelect={(item: { label: string; value: string | number }) => {
                setModel(item.value as string);
                advance(2);
              }}
            />
          </Box>
        );

      case 2:
        return (
          <Box flexDirection="column">
            <Box marginBottom={0}>
              <Text>Enter custom model ID:</Text>
            </Box>
            <TextInput
              value={customModel}
              onChange={setCustomModel}
              onSubmit={() => advance(3)}
              placeholder="provider/model-name"
            />
          </Box>
        );

      case 3:
        return (
          <Box flexDirection="column">
            <Box marginBottom={0}>
              <Text>Select scan depth:</Text>
            </Box>
            <SelectInput
              items={depths}
              onSelect={(item: { label: string; value: string | number }) => {
                setDepth(item.value as string);
                advance(4);
              }}
            />
          </Box>
        );

      case 4: {
        // Fire-and-forget save
        handleSubmit();
        return (
          <Box>
            <Text color={colors.success}>
              {sym.check}  Configuration saved. Starting scan…
            </Text>
          </Box>
        );
      }

      default:
        return null;
    }
  };

  return (
    <Box flexDirection="column">
      <StepIndicator current={step} />
      <Box
        borderStyle="single"
        borderColor="gray"
        flexDirection="column"
        paddingX={1}
        paddingY={0}
      >
        {renderBody()}
      </Box>
    </Box>
  );
};
