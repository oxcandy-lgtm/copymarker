# CopyMarker

A local-first Chrome extension that marks copied text with persistent highlights.

## Current Status

This repository contains the **public-safety foundation (Phase 0)** only. The browser extension runtime is not yet implemented.

### Implemented (Phase 0)

- Public-safety policy document
- Synthetic fixture policy
- Local public-safety scanner (`scripts/public-safety.mjs`)
- Scanner tests with positive and negative cases
- Phase 0 CI workflow (`source_safety` + `safety_tests`)

### Not Yet Implemented (Phase 1+)

- Browser extension (Manifest V3)
- Copy detection and text highlighting
- Persistence via `chrome.storage`
- Popup and options UI
- Site permissions and dynamic content script injection
- ChatGPT copy-button integration
- Color-wheel highlight cycling

## Quick Start

```bash
# Install dependencies
npm ci --ignore-scripts --no-audit --no-fund

# Run public-safety scanner on tracked files
npm run safety

# Run scanner tests
npm run test:safety

# Build extension (when Phase 1 is implemented)
# npm run build (unavailable in Phase 0)
```

## Safety

The public-safety scanner detects:
- Private keys and certificates
- API tokens and secrets
- Authorization headers
- Cookie headers
- Non-example email addresses
- IP addresses (non-reserved)
- Absolute file paths (Unix/Windows)
- Browser profile paths
- Webhook URLs
- Private denylist terms (via `COPYMARKER_PRIVATE_DENYLIST_FILE`)
- Runtime network primitives (`fetch`, `XMLHttpRequest`, etc.)
- Source map local paths

The scanner never prints matched secret values to output.

## License

MIT License — see [LICENSE](LICENSE) for details.
