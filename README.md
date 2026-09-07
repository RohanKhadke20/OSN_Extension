# OSN Guard - Social Safety & Privacy Shield

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](manifest.json)
[![Manifest](https://img.shields.io/badge/Manifest-V3-success.svg)](manifest.json)
[![Tests](https://img.shields.io/badge/tests-36%20passing-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/CSP-zero--external--network-blueviolet.svg)](manifest.json)

**OSN Guard** is a Manifest V3 browser extension engineered to safeguard user privacy, data integrity, and identity across Online Social Networks (OSNs) such as Twitter/X, Facebook, LinkedIn, Reddit, and modern web applications.

It provides real-time client-side protection against Personal Identifiable Information (PII) leaks, phishing links, IDN punycode spoofing, cryptocurrency drainers, credential harvesting lures, and insecure HTTP data transmission.

---

## Architectural Highlights & Engineering Design

```
                     ┌──────────────────────────────────────────────┐
                     │          OSN Guard Service Worker            │
                     │              (background.js)                 │
                     │  - Persistent tab threat store (MV3 session) │
                     │  - Toolbar badge coordinator                 │
                     │  - Serialized global statistics queue        │
                     └──────────────────────┬───────────────────────┘
                                            │ chrome.runtime messages
                                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Target Web Page / OSN Feed                    │
│                                                                  │
│  ┌─────────────────────────┐      ┌───────────────────────────┐  │
│  │   Content Script        │      │   Interactive Composer    │  │
│  │     (content.js)        │      │   - Real-time PII guard   │  │
│  │   - Scans DOM nodes     │◄────►│   - Floating alert banner │  │
│  │   - Mutation observer   │      │   - Luhn / regex checkers │  │
│  │   - Shared body tooltip │      └───────────────────────────┘  │
│  └────────────┬────────────┘                                     │
│               │                                                  │
│               ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Core Detection Engines                   │ │
│  │  1. url-analyzer.js (Safe registries, Punycode, TLD, IPs)   │ │
│  │  2. pii-analyzer.js (Cards, SSNs, API tokens, Phone, Custom)│ │
│  │  3. scam-analyzer.js (Drainers, Urgency lures, Support fake)│ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 1. Hardened Against DOM-based XSS
All dynamic data extracted from web pages (`href`, element text content, form action attributes, user custom regex names) is rendered exclusively through secure DOM construction (`textContent`, `createElement`, `replaceChildren`). No `innerHTML` interpolation of untrusted inputs exists in popup, content scripts, or options.

### 2. Manifest V3 Service Worker Ephemeral Storage Resilience
Manifest V3 service workers automatically terminate after 30 seconds of inactivity. OSN Guard tab threats are persisted in `chrome.storage.session` (with fallback to `chrome.storage.local`), guaranteeing that active tab analysis is never lost when the background worker enters dormancy.

### 3. Shared Non-Clipped Floating Tooltips
Traditional browser extension badges embedded within parent cards often get clipped or occluded when social feeds apply `overflow: hidden`. OSN Guard uses a shared, dynamically positioned viewport overlay (`position: fixed; z-index: 2147483647`) attached directly to `document.body` on `mouseenter`, ensuring tooltips remain 100% visible and unclipped across all platforms.

### 4. Zero External Dependencies & Strict CSP
All fonts and assets run on a native system font stack (`system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`), eliminating remote Google Fonts network requests that violate Content Security Policy (CSP) and leak network metadata.

### 5. Atomic Stats Queue
Concurrent link and threat detections are serialized via a promise queue in `background.js`, preventing race condition state loss during high-volume parallel scans.

---

## Core Protection Capabilities

### 1. PII Leak Protection
* **Payment Cards**: 13-to-19 digit card detection validated via the **Luhn Algorithm (Mod 10)**. Rejects non-card digit sequences and timestamps.
* **US Social Security Numbers (SSN)**: Detects `XXX-XX-XXXX` formats and validates against prohibited area, group, and serial rules.
* **API Secrets & Private Keys**: Detects leaked OpenAI (`sk-...`), Anthropic (`sk-ant-...`), GitHub personal access tokens (`ghp_...`), AWS Access Keys (`AKIA...`), and PEM private key blocks before they are posted to social media.
* **Phone Numbers**: Handles international and North American formats (`+1 (555) 234-5678`, `+44 20 7946 0958`, `+91 98765 43210`).
* **Custom User Patterns**: User-defined regular expressions configurable in the Options page with custom severity tags.

### 2. URL Reputation & Phishing Scanner
* **IDN Homograph / Punycode Detection**: Intercepts spoofed Unicode/Punycode domains (`xn--...`) commonly used to impersonate brands like PayPal, Apple, or Google.
* **Raw IP Hostnames**: Identifies direct IP address links (`192.168.1.100`, public IPv4 addresses).
* **High-Abuse Disposable TLDs**: Flags risky low-cost TLDs (`.xyz`, `.cc`, `.info`, `.click`, `.top`, etc.).
* **Phishing Keywords**: Analyzes URL subdomains and paths for multi-keyword phishing lures (`login`, `verify`, `account`, `banking`, `airdrop`).
* **Protocol Warnings**: Flags unencrypted `http://` links on social platforms.
* **Domain Whitelist**: Honors exact and wildcard entries (`*.mycompany.com`), bypassing scans for verified intranets.

### 3. Scam & Fraud Content Filter
* **Crypto Drainers & Seed Phrase Theft**: Flags requests asking users to "enter seed phrase", "enter secret recovery phrase", or "connect wallet to claim".
* **Crypto Doubling Schemes**: Detects classic fake giveaways ("double your bitcoin", "send ETH for 2x return").
* **Credential Phishing & Urgency Cues**: Catches urgent threats designed to bypass critical thinking ("account suspension warning", "unusual activity detected, verify within 24 hours").
* **Tech Support Scams**: Flags fake virus removal hotlines ("call Microsoft support toll-free").
* **Spam Recruitment**: Detects work-from-home and WhatsApp/Telegram pump spam.

### 4. Insecure Form Warning
* Warns users when an unencrypted HTTP action target (`action="http://..."`) is present on a secure HTTPS website.

---

## Project Structure

```
osn-safety-scanner/
├── manifest.json              # Manifest V3 configuration & content script declarations
├── background.js              # Service worker (tab threat store, badge counter, stats queue)
├── content.js                 # In-page scanner, floating tooltip coordinator, PII watcher
├── content.css                # Tooltip, badge, and banner styles
├── core/
│   ├── url-analyzer.js        # Heuristics URL safety engine & whitelist manager
│   ├── pii-analyzer.js        # Multi-pattern PII detector & Luhn validator
│   └── scam-analyzer.js       # Scam, seed-phrase drainer, & phishing text detector
├── popup/
│   ├── popup.html             # Glassmorphic safety dashboard UI
│   ├── popup.js               # Reactive score calculator, shield toggles, in-place rescan
│   └── popup.css              # Dashboard styling & SVG radial gauge
├── options/
│   ├── options.html           # Settings UI (custom PII rules, whitelist, live metrics)
│   ├── options.js             # Options controller & data management
│   └── (shared styling)
├── tests/
│   ├── url-safety.test.js     # URL analyzer unit & edge-case tests
│   ├── pii-detector.test.js   # PII & Luhn algorithm verification tests
│   ├── scam-detector.test.js  # Scam & fraud phrase detector tests
│   └── storage-sync.test.js   # Whitelist wildcard & resilience tests
├── test-page.html             # Interactive browser sandbox for manual extension verification
└── package.json               # Test scripts & project metadata
```

---

## Running Automated Tests

OSN Guard uses Node.js's native test runner (`node:test` and `node:assert/strict`), requiring zero external test dependencies:

```bash
# Run complete test suite
npm test

# Run tests in watch mode during development
npm run test:watch
```

---

## Loading the Extension in Chrome / Edge / Brave

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `osn-safety-scanner` directory.
5. Open [`test-page.html`](test-page.html) in your browser to test all shields in action.
