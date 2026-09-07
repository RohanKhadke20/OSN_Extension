# OSN Guard - Social Safety & Privacy Shield

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](manifest.json)
[![Manifest](https://img.shields.io/badge/Manifest-V3-success.svg)](manifest.json)
[![Tests](https://img.shields.io/badge/tests-85%20passing-brightgreen.svg)](tests/)
[![Benchmarks](https://img.shields.io/badge/benchmarks-60k%2B%20ops%2Fsec-orange.svg)](scripts/bench.js)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue.svg)](.github/workflows/ci.yml)
[![Security](https://img.shields.io/badge/CSP-zero--external--network-blueviolet.svg)](manifest.json)

**OSN Guard** is a hardened Manifest V3 browser extension engineered to safeguard user privacy, data integrity, and identity across Online Social Networks (OSNs) such as Twitter/X, Facebook, LinkedIn, Reddit, Threads, Bluesky, Instagram, YouTube comments, and modern web applications.

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
                     │  - Tab navigation lifecycle manager          │
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
│  │   - Mutation observer   │      │   - Luhn / ISO 7064 checks│  │
│  │   - Shared body tooltip │      │   - Fast paste & no reflow│  │
│  └────────────┬────────────┘      └───────────────────────────┘  │
│               │                                                  │
│               ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Core Detection Engines                   │ │
│  │  1. url-analyzer.js (Safe registries, Punycode, TLD, IPs)   │ │
│  │  2. pii-analyzer.js (Cards, IBAN, SSN, API tokens, Custom)  │ │
│  │  3. scam-analyzer.js (Quishing, Drainers, AI fraud, Phish)  │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 1. Hardened Against DOM-based XSS
All dynamic data extracted from web pages (`href`, element text content, form action attributes, user custom regex names) is rendered exclusively through secure DOM construction (`textContent`, `createElement`, `replaceChildren`). No `innerHTML` interpolation of untrusted inputs exists in popup, content scripts, or options.

### 2. Manifest V3 Service Worker Ephemeral Storage Resilience
Manifest V3 service workers automatically terminate after 30 seconds of inactivity. OSN Guard tab threats are persisted in `chrome.storage.session` (with fallback to `chrome.storage.local`), guaranteeing that active tab analysis is never lost when the background worker enters dormancy. Navigation cleanup via `chrome.tabs.onUpdated` purges stale tab records immediately when a user navigates to a new page.

### 3. Shared Non-Clipped Floating Tooltips
Traditional browser extension badges embedded within parent cards often get clipped or occluded when social feeds apply `overflow: hidden`. OSN Guard uses a shared, dynamically positioned viewport overlay (`position: fixed; z-index: 2147483647`) attached directly to `document.body` on `mouseenter`, ensuring tooltips remain 100% visible and unclipped across all platforms.

### 4. Zero External Dependencies & Strict CSP
All fonts and assets run on a native system font stack (`system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`), eliminating remote Google Fonts network requests that violate Content Security Policy (CSP) and leak network metadata.

### 5. Atomic Stats Queue & Single-Count Site Metric
Concurrent link and threat detections are serialized via a promise queue in `background.js`, preventing race condition state loss. Site protection counters are deduplicated so dynamic scroll operations never falsely increment site visit counts.

---

## Core Protection Capabilities

### 1. PII Leak Protection
* **International Bank Account Numbers (IBAN)**: Detects international bank account formats with strict **ISO 7064 Mod-97** checksum validation, safeguarding international wire and banking privacy.
* **Payment Cards**: 13-to-19 digit card detection validated via the **Luhn Algorithm (Mod 10)**. Rejects non-card digit sequences and timestamps.
* **US Social Security Numbers (SSN)**: Detects `XXX-XX-XXXX` and `XXX XX XXXX` formats and validates against prohibited area, group, and serial rules.
* **Modern API Secrets & Private Keys**: Detects leaked OpenAI (`sk-...`), Anthropic (`sk-ant-...`), GitHub personal access tokens (`ghp_...` and modern `github_pat_...`), Stripe secret keys (`sk_live_...`, `rk_live_...`), Slack tokens (`xoxb-...`), Google/Firebase API keys (`AIza...`), AWS Access Keys (`AKIA...`), and PEM private key blocks (PGP, DSA, ENCRYPTED).
* **Phone Numbers**: Handles international and North American formats (`+1 (555) 234-5678`, `+44 20 7946 0958`, `+91 98765 43210`).
* **Live Interactive Redactor & Sanitizer Sandbox**: Options page preview sandbox with real-time text sanitization, custom regex testing, and single-click sanitized clipboard copy.
* **Composer Optimization**: Exemption of password/file fields, accelerated paste inspection (50ms), and zero-reflow `textContent` inspection for contenteditable social editors.
* **Custom User Patterns**: User-defined regular expressions configurable in the Options page with LRU compilation caching and non-blocking validation notices.

### 2. URL Reputation & Phishing Scanner
* **Embedded Authority Userinfo Spoofing**: Intercepts classic phishing lures containing fake credentials in the authority (`https://google.com@phishing-target.com`).
* **IDN Homograph & Mixed-Script Detection**: Intercepts spoofed Unicode/Punycode domains (`xn--...`) and Latin-Cyrillic / Latin-Greek mixed-script confusable homoglyphs.
* **Obfuscated IP Hostnames**: Identifies IPv4, IPv6 (`[::1]`), dotted-octal (`0177.0.0.1`), dotted-hex (`0x7f.0.0.1`), and integer dword (`2130706433`) notation.
* **Suspicious Executable & Script Downloads**: Detects direct links to dangerous executables and dropper scripts (`.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.msi`, `.hta`, `.apk`, `.iso`).
* **URL Shortener Destination Obscurity**: Detects URL shortener links (`bit.ly`, `tinyurl.com`, `is.gd`, `t.ly`) and compound risk combinations.
* **Open Redirect Heuristics**: Detects URLs containing external destination parameters (`?redirect=`, `?url=`, `?next=`) and inspects destination targets recursively.
* **High-Abuse Disposable TLDs**: Flags risky low-cost TLDs (`.xyz`, `.cc`, `.info`, `.click`, `.top`, `.sbs`, `.cfd`, `.beauty`, etc.).
* **Phishing Keywords**: Analyzes URL subdomains and paths for multi-keyword phishing lures (`login`, `verify`, `account`, `banking`, `airdrop`).
* **Developer Intranet & Port Whitelist**: Supports exact hosts, subdomains, wildcards (`*.corp.com`), port specifications (`localhost:3000`), and private subnet ranges (`192.168.*`, `10.*`).

### 3. Scam & Fraud Content Filter
* **Web3 / Crypto Drainer Signatures**: Detects requests tricking users into signing Permit2 batch allowances, `setApprovalForAll`, `increaseAllowance`, and raw `eth_sign` payloads.
* **QR Code Phishing (Quishing)**: Detects urgent instructions directing users to scan off-screen QR codes to bypass link safety scanners.
* **NFT Drainers & Stealth Drops**: Identifies fake free mint lures and malicious contract approval scams.
* **AI Token & Yield Scams**: Catches fraudulent AI compute, arbitrage bots, and guaranteed yield schemes.
* **Crypto Drainers & Seed Phrase Theft**: Flags requests asking users to "enter seed phrase", "enter secret recovery phrase", or "connect wallet to claim".
* **Modern Social Engineering Scams**: Detects romance grooming / pig-butchering investment redirects, fake invoice / auto-renewal refund scams, and family emergency impersonation.
* **Severity Prioritization**: Compound threats automatically surface critical risks over secondary warnings.

### 4. Form Action & Security Inspector
* **Mixed-Content Submissions**: Warns when an unencrypted HTTP form action (`action="http://..."`) is present on a secure HTTPS website.
* **Malicious URI Schemes**: Flags dangerous execution schemes (`javascript:`, `data:`) in form action targets.
* **Cross-Origin Credential Theft**: Flags password and payment forms posting credentials to external unverified domains.

### 5. Quick Actions & Incident Auditing
* **Context Menus**: Right-click any link to "Scan link with OSN Guard" or any text to "Analyze text for scams/PII" with non-blocking toast alerts.
* **Security Audit Event Log**: Rolling 50-event incident history in Options UI with severity indicators, incident timestamps, and single-click JSON export.
* **Accessible Keyboard Interaction**: Badges support full keyboard navigation (`Tab`, `Enter`, `Space` toggle, and `Escape` dismiss) with WCAG-compliant ARIA attributes.

---

## Project Structure

```
osn-safety-scanner/
├── .github/
│   └── workflows/ci.yml       # GitHub Actions cross-platform matrix CI (Node 18/20/22)
├── manifest.json              # Manifest V3 configuration & content script declarations
├── background.js              # Service worker (tab threat store, badge sync, audit log buffer)
├── content.js                 # In-page scanner, floating tooltips, toast dispatcher, keyboard ARIA
├── content.css                # Tooltip, badge, toast notification, and focus-visible styles
├── core/
│   ├── url-analyzer.js        # Heuristics URL safety engine, IDN, IP obfuscation, shorteners
│   ├── pii-analyzer.js        # Multi-pattern PII detector, Luhn check, ISO 7064 IBAN, LRU cache
│   └── scam-analyzer.js       # Modern scam rules, Web3 drainers, romance grooming, refund fraud
├── popup/
│   ├── popup.html             # Glassmorphic safety dashboard UI
│   ├── popup.js               # Reactive score calculator, shield toggles, in-place rescan
│   └── popup.css              # Dashboard styling, accent variables, SVG radial gauge
├── options/
│   ├── options.html           # Settings UI (PII sandbox, whitelist, audit log, metrics)
│   ├── options.js             # Options controller, sandbox redactor, audit export & clear
│   └── (shared styling)
├── scripts/
│   ├── pack.js                # Zero-dependency MS-DOS/DEFLATE extension zip packager
│   └── bench.js               # Zero-dependency performance benchmark suite (node:perf_hooks)
├── tests/
│   ├── dashboard-score.test.js# Dashboard scoring engine & safety status transition tests
│   ├── url-safety.test.js     # URL analyzer unit, IDN, shorteners, dangerous executables
│   ├── pii-detector.test.js   # PII, Luhn algorithm, IBAN ISO 7064, LRU regex compilation tests
│   ├── scam-detector.test.js  # Scam, quishing, Web3 drainer, romance grooming tests
│   ├── storage-sync.test.js   # Whitelist wildcard, developer ports, resilience tests
│   ├── bench.test.js          # Benchmark suite unit tests
│   └── e2e/
│       ├── extension-lifecycle.test.js # Headless browser extension lifecycle & UI E2E test
│       └── test-server.js     # Zero-dependency local test HTTP server
├── test-page.html             # Interactive browser sandbox for manual extension verification
└── package.json               # Scripts, static check scripts, and project metadata
```

---

## Running Automated Tests & Verification

OSN Guard uses Node.js's native test runner (`node:test` and `node:assert/strict`) and zero external dependencies:

```bash
# Run syntax and static checks across all 13 JavaScript files
npm run check

# Run complete unit test suite (85 tests across 21 suites)
npm test

# Run performance benchmark suite (URL, PII, and Scam engines)
npm run bench

# Run automated headless browser end-to-end lifecycle tests
npm run test:e2e

# Build production Chrome Web Store distribution archive
npm run pack
```

---

## Loading the Extension in Chrome / Edge / Brave

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `osn-safety-scanner` directory.
5. Open [`test-page.html`](test-page.html) in your browser to test all shields in action.

