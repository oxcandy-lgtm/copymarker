# Contributing to CopyMarker

Thank you for contributing!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/oxcandy-lgtm/copymarker.git
cd copymarker

# Install dependencies
npm ci --ignore-scripts --no-audit --no-fund

# Run tests
npm run test:safety

# Run safety scanner
npm run safety
```

## Code Style

- TypeScript with strict mode
- No `any` types in public APIs
- Prefer explicit types over inference for exported functions

## Testing

- Add tests for new public-safety rules
- Use synthetic fixtures only
- Run `npm run test:safety` before committing

## Pull Requests

1. Create a feature branch from `main`
2. Make focused, atomic changes
3. Ensure CI passes
4. Open a Draft PR for review
5. Address review feedback
6. Mark Ready when all checks pass

## Phase Guidelines

- Phase 0: Public-safety foundation only
- Phase 1: Manifest V3 scaffold
- Phase 2+: Runtime features

Do not mix phases in a single PR.
