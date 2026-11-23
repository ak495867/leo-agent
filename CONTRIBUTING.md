# Contributing to Leo

Thanks for your interest in contributing! 🦁

## Code of Conduct

This project is governed by the [Apache 2.0 License](LICENSE). Be respectful, constructive, and inclusive.

## How to Contribute

### Report a Bug

Open an issue at [github.com/ak495867/leo-agent/issues](https://github.com/ak495867/leo-agent/issues) with:

- A clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Your environment (Node version, OS, model used)

### Suggest a Feature

Open an issue with:

- What you're trying to achieve
- How Leo currently falls short
- A proposed solution or approach

### Submit a Pull Request

1. **Fork** the repo
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Make your changes**
4. **Build**: `npm run build`
5. **Commit**: use clear commit messages
6. **Push**: `git push origin feature/my-feature`
7. **Open a PR** against `main`

## Development Setup

```bash
# Clone your fork
git clone https://github.com/ak495867/leo-agent.git
cd leo-agent

# Install dependencies
npm install

# Build
npm run build

# Run regression tests
npm test

# Test a real scan locally after configuring OpenRouter
node bin/leo scan
```

### Project Structure

```
leo/
├── bin/                 # CLI entry point (shebang)
│   └── leo
├── src/
│   ├── agents/          # AI agent implementations
│   │   ├── prompts/     # Agent system prompts
│   │   ├── verify.ts    # Independent finding verifier
│   │   ├── correlate.ts # Cross-batch evidence correlation
│   │   ├── coordinator.ts
│   │   ├── recon.ts
│   │   ├── exploit.ts
│   │   ├── audit.ts
│   │   ├── patch.ts
│   │   └── memory.ts
│   ├── api/             # OpenRouter API client
│   │   └── openrouter.ts
│   ├── analysis/        # Batching, taint, OSV, deduplication, evaluation
│   ├── core/            # Core modules
│   │   ├── memory-db.ts
│   │   ├── session.ts
│   │   ├── snapshot.ts
│   │   └── patcher.ts
│   ├── ui/              # Ink TUI components
│   │   ├── App.tsx
│   │   ├── SetupFlow.tsx
│   │   ├── SessionPicker.tsx
│   │   ├── ScanView.tsx
│   │   ├── ResultView.tsx
│   │   └── theme.ts
│   ├── utils/           # Utilities
│   │   ├── config.ts
│   │   ├── hash.ts
│   │   ├── logger.ts
│   │   ├── progress.ts
│   │   ├── terminal.ts
│   │   └── tree.ts
│   ├── @types/          # TypeScript type declarations
│   ├── cli.ts           # Commander CLI entry
│   └── index.ts         # Module re-exports
├── dist/                # Compiled output (gitignored)
├── package.json
├── tsconfig.json
└── README.md
```

### Coding Guidelines

- **TypeScript** — strict mode enabled. Avoid `any` where possible
- **CJS output** — we compile to CommonJS for Node.js compatibility
- **No ESM-only dependencies** — everything must work with `require()`
- **Existing patterns** — match the surrounding code's comment density and naming
- **Error handling** — every agent call should have retry logic and graceful fallbacks
- **Logging** — use `logger.write()` for file logs and `pushLog()` for UI logs

### Testing

Run a quick sanity check:

```bash
node bin/leo --help
node bin/leo scan
```

## Release Process

1. Update version in `package.json`
2. Run `npm run build`
3. Commit and tag: `git tag v0.3.0`
4. Publish: `npm publish --access public`
5. Push tags: `git push --tags`


