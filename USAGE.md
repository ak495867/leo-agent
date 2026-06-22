# Usage Guide

## Installation

```bash
npm install -g @leo-agent/cli
```

Verify it works:

```bash
leo --version
```

## First-Time Setup

### 1. Get an API Key

Leo uses OpenRouter to access LLM models. Get a free API key at [openrouter.ai/keys](https://openrouter.ai/keys).

### 2. Run the Configuration Wizard

```bash
leo config
```

You'll be prompted for:
- **API Key** — your OpenRouter key
- **Model** — choose from the list or enter a custom model ID
- **Scan Depth** — quick, deep, or paranoid

### 3. Launch the Interactive UI

```bash
leo
```

The TUI will show:
- Session picker (resume past scans or start new)
- Live scan dashboard with phase tracking
- Real-time step log
- Results view with score interpretation

---

## Commands

### `leo scan` — Headless Scan

Run a full scan without the interactive UI:

```bash
# Default scan
leo scan

# Not working? Try npx
npx @leo-agent/cli scan
```

Output example:
```
🚀 Starting Leo scan…
✓  Config loaded
✓  Session a1b2c3 created
✓  Memory loaded — 1 patterns
✓  Snapshot built — 71 files
✓  Recon — 4 entry points
✓  Exploit — 2 scenarios
✓  Audit — 3 findings
✓  Patches — 1 applied

=== Scan Complete ===
Session ID: a1b2c3
Findings discovered: 5
Patches applied: 1
Scores: { coverage_score: 1, precision_score: 0.2, ... }
```

### `leo config` — Configuration

Interactively set or update your configuration:

```bash
leo config
```

To check current config:

```bash
cat ~/.leo/config.json
```

### `leo history` — Past Sessions

List all previous scans for the current project:

```bash
leo history
```

### `leo status` — Latest Session

Show a summary of the most recent scan:

```bash
leo status
```

### `leo restore` — Rollback Patches

If a patch caused issues, restore the original files:

```bash
# Restore from the latest session
leo restore

# Restore from a specific session
leo restore a1b2c3
```

Restore works by copying `.leo-backup` files back over the patched originals.

### `leo reset` — Clear Data

Delete all session data for the current project:

```bash
leo reset
```

This removes `~/.leo/sessions/<project-hash>/` — the memory DB and config are not affected.

---

## Interactive TUI (recommended)

Running `leo` without any subcommand launches the terminal UI:

### Session Picker

Select a previous session to review, or start a fresh scan.

### Live Scan Dashboard

During a scan, you'll see:

```
─ Preparation ─
  ✓  Config
  ✓  Snapshot     71 files
  ✓  Memory       1 patterns
─ Analysis & Exploitation ─
  ✓  Recon        4 entry points
  ⠏  Exploit      Running…
  ⠇  Audit        Running…
```

A real-time **Step Log** panel shows detailed progress messages.

### Results View

After completion, scores are displayed with interpretation:

```
┌─ Scores ─────────────────────────────────────┐
│ Coverage     ██████████  100%  (Excellent)   │
│ Precision    ████░░░░░░  40%   (Fair)        │
│ Patch Rate   █████░░░░░  50%   (Fair)        │
│ Overall      ███████░░░  72%   (Good)        │
└──────────────────────────────────────────────┘
```

---

## Override Options

Pass these before the subcommand:

```bash
leo --model anthropic/claude-sonnet-4-5 scan
leo --depth paranoid scan
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `API key missing` | Run `leo config` to set your key |
| `Rate limit exceeded` | Add credits at [openrouter.ai](https://openrouter.ai) |
| `Scan interrupted` | Process was killed (Ctrl+C). Run again |
| `0 findings` | The model might need a more detailed prompt. Try `paranoid` depth |
| Patch broke something | Run `leo restore` to rollback |

## Best Practices

1. **Commit your code** before running Leo — patches modify files in place
2. **Start with `quick` depth** on a new project to test the pipeline
3. **Review logs** in `~/.leo/sessions/<hash>/log.txt` for full details
4. **Use the memory DB** — Leo learns across sessions, so repeated scans get smarter
5. **Run on CI** with `leo scan` for automated security auditing in your pipeline
