# DISCORD SIDE

**Enter through the side door.**

Multi-account manager for Discord — a Chrome extension for fast token-based login, account switching, and session tracking. Built by [TTL SIDE](https://ttlside.com).

**[→ Product page](https://ttlside.com/discordside)**

![Version](https://img.shields.io/badge/version-1.3.0-5865f2?style=flat-square)
![Manifest](https://img.shields.io/badge/manifest-v3-57f287?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-white?style=flat-square)

---

## Features

- **Token Login** — paste a Discord token, validate it against the API, and log in instantly
- **Token Extraction** — pull your session token from any active Discord tab
- **Saved Accounts** — bookmark up to 20 accounts with one-click quick switch
- **Session Tracking** — see who you're currently logged in as with a live indicator
- **Login History** — 10 most recent logins with timestamps and quick reuse
- **AES-256-GCM Encryption** — all stored tokens are encrypted via Web Crypto API (PBKDF2, 100k iterations)
- **Speed Mode** — disables all animations for instant account switching
- **Dark & Light Theme** — adapts to your preference
- **Keyboard Shortcuts** — every action has a hotkey
- **Zero Telemetry** — no analytics, no tracking, no external requests beyond `discord.com`

## Keyboard Shortcuts

| Action | Shortcut |
|---|---|
| Log in with current token | `Ctrl+Shift+L` |
| Extract token from Discord tab | `Ctrl+Shift+E` |
| Copy current token | `Ctrl+Shift+C` |

## Installation

1. Download or clone this repository
2. Open `chrome://extensions` in Chrome
3. Enable **Developer mode** (toggle in the top-right corner)
4. Click **Load unpacked** and select the project folder
5. Pin the extension from the toolbar — you're ready

## How It Works

1. **Extract** — click Extract Token while on a Discord tab to pull the session token
2. **Save** — click the bookmark icon to save the token under a custom name
3. **Switch** — click the ▶ button on any saved account to instant-login

Tokens are validated against `discord.com/api/v9/users/@me` before every login. Invalid or expired tokens are flagged immediately.

## Security

- Tokens are encrypted with **AES-256-GCM** before writing to `chrome.storage.local`
- Encryption key is derived from a random salt + extension runtime ID via **PBKDF2** (100,000 iterations, SHA-256)
- Plain-text tokens are **never** persisted to storage
- Legacy unencrypted tokens are automatically migrated on first run
- No data leaves your machine — the only network requests go to `discord.com`

See the full [Privacy Policy](https://ttlside.com/discordside/privacy) on the product page.

## Permissions

| Permission | Reason |
|---|---|
| `activeTab` | Interact with the current Discord tab |
| `scripting` | Extract/apply tokens on discord.com pages |
| `storage` | Save encrypted tokens and preferences locally |
| `contextMenus` | Right-click quick actions on the extension icon |
| `discord.com` (host) | Run scripts on Discord pages for token operations |

## Project Structure

```
├── manifest.json      Manifest V3 configuration
├── background.js      Service worker — context menus, tab management
├── popup.html         Extension popup UI
├── popup.css          Styles with dark/light theme support
├── popup.js           Core logic — encryption, accounts, UI
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

## Disclaimer

This extension is provided as-is for personal use. Using self-bots or token-based login may violate [Discord's Terms of Service](https://discord.com/terms). Use at your own risk.

## License

[MIT](LICENSE) © TTL SIDE
