# Privacy Policy

**Last updated: 2026**

## Overview

CopyMarker is designed for not-yet-implemented browser extension. The extension runtime does not exist yet.

### Intended Behavior

- **Local-first by design**: All copied text and highlights stay on your device
- **No external servers**: No telemetry, analytics, or data transmission to third parties
- **User-controlled storage**: You can view, export, and delete all stored data

## Data Handling (Intended)

| Data Type | Storage | Retention | Deletion |
|-----------|---------|-----------|----------|
| Highlights | `chrome.storage.local` | Until user clears | Via popup/options UI |
| Settings | `chrome.storage.local` | Until changed | Via options UI |
| Site permissions | `chrome.storage.local` | Until changed | Via options UI |

## Permissions

The extension will request:
- `storage` — Local highlight/settings persistence
- `scripting` — Dynamic content script injection
- `activeTab` — Highlight on current tab
- `webNavigation` — Detect page loads for injection
- Optional `<all_urls>` host permission — User-granted per site

## What CopyMarker Will NOT Do

- Send any data to external servers
- Track browsing history
- Access clipboard without user action
- Use cloud sync or accounts
- Include analytics or crash reporting

## Contact

For privacy questions, open a GitHub issue.
