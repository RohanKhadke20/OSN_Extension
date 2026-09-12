# OSN Guard - Social Safety & Privacy Shield

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](manifest.json)
[![Manifest](https://img.shields.io/badge/Manifest-V3-success.svg)](manifest.json)
[![Tests](https://img.shields.io/badge/tests-100%20passing-brightgreen.svg)](tests/)
[![Benchmarks](https://img.shields.io/badge/benchmarks-100k%2B%20ops%2Fsec-orange.svg)](scripts/bench.js)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue.svg)](.github/workflows/ci.yml)
[![Security](https://img.shields.io/badge/CSP-zero--external--network-blueviolet.svg)](manifest.json)
[![Permissions](https://img.shields.io/badge/permissions-least--privilege-green.svg)](manifest.json)

**OSN Guard** is a hardened, production-ready Manifest V3 Chrome extension engineered to safeguard user privacy, data integrity, and identity across Online Social Networks (OSNs) such as Twitter/X, Facebook, LinkedIn, Reddit, Threads, Bluesky, Instagram, YouTube comments, and interactive web applications.

It provides zero-latency, on-device client-side protection against Personal Identifiable Information (PII) leaks, phishing links, IDN homoglyph / punycode spoofing, cryptocurrency drainers, modern Quishing (QR-code phishing), zero-width character evasion, and insecure data transmission — all operating with **zero external dependencies** and an airtight Content Security Policy blocking all external network connections.

---

## Architectural Highlights & Engineering Design

```
                     ┌──────────────────────────────────────────────┐
                     │          OSN Guard Service Worker            │
                     │              (background.js)                 │
                     │  - Persistent tab threat store (MV3 session) │
                     │  - Orphaned tab storage reconciliation       │
                     │  - Internal IPC sender validation            │
                     │  - Serialized global statistics queue        │
                     │  - Context menu on-demand inspector          │
                     └──────────────────────┬───────────────────────┘
                                            │ chrome.runtime messages
                                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Target Web Page / OSN Feed                    │
│                                                                  │
│  ┌─────────────────────────┐      ┌───────────────────────────┐  │
│  │   Content Script        │      │   Interactive Composer    │  │
│  │     (content.js)        │      │   - Real-time PII guard   │  │
│  │   - 10ms frame budget   │◄────►│   - Floating alert banner │  │
│  │   - Batched DOM rAF/rIC │      │   - Luhn / ISO 7064 checks│  │
│  │   - Shared body tooltip │      │   - Zero-reflow detection │  │
│  └────────────┬────────────┘      └───────────────────────────┘  │
│               │                                                  │
│               ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Core Detection Engines                   │ │
│  │  1. url-analyzer.js (Safe registries, Punycode, TLD, IPs)   │ │
│  │  2. pii-analyzer.js (Cards, IBAN, SSN, API tokens, ReDoS)   │ │
│  │  3. scam-analyzer.js (Zero-width evasion, Quishing, Drainers)│ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 1. Zero External Dependencies & Strict CSP
OSN Guard relies exclusively on native web standards and modern JavaScript. Its Content Security Policy strictly prohibits external network connectivity:
```http
default-src 'self'; connect-src 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
```
No analytics beacons, no remote scripts, and no third-party CDNs. All UI fonts use the system font stack (`system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`).

### 2. Least-Privilege Manifest V3 Security
* **Zero Host Permissions**: Does not request overprivileged `"host_permissions": ["<all_urls>"]`. Declarative content injection is scoped exclusively to `"content_scripts"`.
* **Minimal Extension Permissions**: Only requests `storage` (local state and session caching), `activeTab` (contextual inspection), and `contextMenus` (on-demand scanning).
* **IPC Sender Verification**: Background service worker strictly verifies `sender.id === chrome.runtime.id` on all internal message handlers.

### 3. Frame-Budgeted DOM Performance (Zero Reflow)
Infinite-scrolling social media feeds (e.g., 500+ post nodes) are processed in frame-budgeted batches (`BATCH_TIME_BUDGET_MS = 10`) scheduled via `requestIdleCallback` (fallback `setTimeout`). Geometric reads (`getBoundingClientRect`, scroll positions) and style mutations are strictly separated into two distinct phases, eliminating layout thrashing and keeping all tasks well below 16ms (60 FPS).

### 4. Shared Non-Clipped Floating Tooltips
Traditional browser extension badges embedded within parent cards often get clipped when social feeds declare `overflow: hidden` or stacking contexts. OSN Guard renders a shared, dynamically positioned viewport overlay (`position: fixed; z-index: 2147483647`) attached directly to `document.body`, ensuring tooltips remain 100% visible and unclipped.

### 5. Service Worker Lifecycle & Orphaned Tab Reconciliation
Manifest V3 service workers terminate after inactivity. OSN Guard stores ephemeral per-tab threat data in `chrome.storage.session` (surviving worker dormancy). Stale keys are cleaned up on tab navigation (`chrome.tabs.onUpdated`), tab closure (`chrome.tabs.onRemoved`), and actively reconciled on browser startup (`chrome.runtime.onStartup`) against active tab IDs.

---

## Core Protection Capabilities

### 1. PII Leak Protection & ReDoS Defense
* **Payment Cards (Luhn Algorithm Mod 10)**: Detects 13-to-19 digit card numbers validated via the authentic Luhn checksum algorithm. Filters out sequential or all-zero sequences.
* **International Bank Account Numbers (IBAN)**: Detects international bank account formats with strict **ISO 7064 Mod-97** checksum verification.
* **US Social Security Numbers (SSN)**: Validates against prohibited area, group, and serial number rules (`000`, `666`, `900-999`, etc.).
* **Modern API Secrets & Private Keys**: Detects leaked OpenAI (`sk-...`), Anthropic (`sk-ant-...`), GitHub personal access tokens (`ghp_...` and modern `github_pat_...`), Stripe secret keys (`sk_live_...`, `rk_live_...`), Slack tokens (`xoxb-...`), Google/Firebase API keys (`AIza...`), AWS Access Keys (`AKIA...`), database URIs, JWT tokens, and PEM private keys (PGP, DSA, ENCRYPTED).
* **ReDoS Prevention Engine**: Static regular expression validator (`isSafeRegexPattern`) inspects custom rules for catastrophic backtracking (nested quantifiers like `(a+)+`, `([0-9]+)*`, `(foo|bar+)+`, `(a+){2,}`) and bounds pattern lengths to 250 characters.
* **LRU Regex Compilation Cache**: Caches compiled RegExp instances (up to 100 entries) with `lastIndex = 0` auto-reset across keystrokes.
* **Live Interactive PII Sandbox**: Options page preview sandbox with real-time text masking, custom regex testing, and single-click sanitized clipboard copy with fallback.

### 2. URL Reputation & Phishing Scanner
* **Embedded Authority Userinfo Spoofing**: Intercepts classic phishing lures containing fake credentials in the authority (`https://google.com@phishing-target.com`).
* **IDN Homograph & Mixed-Script Detection**: Intercepts spoofed Unicode/Punycode domains (`xn--...`) and Latin-Cyrillic / Latin-Greek mixed-script confusable homoglyphs.
* **Obfuscated IP Hostnames**: Identifies IPv4, IPv6 (`[::1]`), dotted-octal (`0177.0.0.1`), dotted-hex (`0x7f.0.0.1`), and integer dword (`2130706433`) host notations.
* **Dangerous Executable & Script Downloads**: Detects direct links to executables and dropper scripts (`.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.msi`, `.hta`, `.apk`, `.iso`).
* **URL Shortener Destination Obscurity**: Detects URL shortener links (`bit.ly`, `tinyurl.com`, `is.gd`, `rb.gy`, `t.ly`) and compound risk combinations.
* **Open Redirect Heuristics**: Detects external redirection parameters (`?redirect=`, `?url=`, `?next=`) and recursively inspects destination URLs.
* **High-Abuse Disposable TLDs**: Flags risky low-cost TLDs (`.xyz`, `.cc`, `.info`, `.click`, `.top`, `.buzz`, `.sbs`, `.cfd`, `.beauty`, etc.).
* **Developer Intranet & Port Whitelist**: Supports exact hosts, subdomains, wildcards (`*.corp.com`), port specifications (`localhost:3000`), and private subnet ranges (`192.168.*`, `10.*`).

### 3. Scam & Fraud Content Filter
* **Zero-Width Character Evasion Defense**: Strips invisible zero-width characters (ZWSP `\u200B`, ZWNJ `\u200C`, ZWJ `\u200D`, LRM/RLM `\u200E`/`\u200F`, and BOM `\uFEFF`) used by modern threat actors to evade naive keyword matching.
* **Modern Quishing Heuristics**: Detects modern QR code phishing vectors (mandatory 2FA/authenticator setup lures, phone camera scanning instructions, mailbox/password expiration alerts, and HR/payroll open enrollment lures).
* **Recovery Phrase Honeypot & Theft**: Detects 12-word and 24-word seed phrase theft lures, fake leaked wallet drops, and deceptive restore prompts.
* **Web3 / Crypto Drainer Signatures**: Detects requests tricking users into signing Permit2 batch allowances, `setApprovalForAll`, `increaseAllowance`, and raw `eth_sign` payloads.
* **Social Engineering Scams**: Detects romance grooming / pig-butchering investment redirects, fake invoice / auto-renewal refund scams, and family emergency impersonation.

### 4. Form Action & Insecure Transmission Inspector
* **Mixed-Content Submissions**: Warns when an unencrypted HTTP form action (`action="http://..."`) is present on an HTTPS website.
* **Malicious URI Schemes**: Flags dangerous execution schemes (`javascript:`, `data:`) in form action targets.
* **Cross-Origin Credential Theft**: Flags password and payment forms posting credentials to external unverified domains.

### 5. Quick Actions & Incident Auditing
* **Context Menus**: Right-click any link to "Scan link with OSN Guard" or any text to "Analyze text for scams/PII" with non-blocking toast alerts (input text capped at 5,000 characters).
* **Security Audit Event Log**: Rolling 50-event incident history in Options UI with sanitized entries, timestamps, and single-click JSON export.
* **Accessible Keyboard Interaction**: Badges support full keyboard navigation (`Tab`, `Enter`, `Space` toggle, and `Escape` dismiss) with WCAG-compliant ARIA attributes.
* **Hardened Configuration Backup / Import**: JSON backup importer validates schemas, sanitizes rule names, prevents prototype pollution (`__proto__`), and blocks ReDoS patterns.

---

## Project Structure

```
osn-safety-scanner/
├── .github/
│   └── workflows/ci.yml       # Automated CI matrix (Node 18/20/22 on Ubuntu & Windows)
├── manifest.json              # Manifest V3 configuration (Least-privilege, strict CSP)
├── background.js              # Service worker (tab threat store, badge sync, IPC validation, audit log)
├── content.js                 # Batched DOM scanner (10ms frame budget), tooltips, PII banners, ARIA
├── content.css                # Tooltip, badge, toast notification, and focus-visible styles
├── core/
│   ├── url-analyzer.js        # URL safety engine, IDN homoglyphs, IP obfuscation, shorteners
│   ├── pii-analyzer.js        # Multi-pattern PII detector, Luhn check, ISO 7064 IBAN, ReDoS linter
│   └── scam-analyzer.js       # Zero-width evasion stripper, Quishing engine, Web3 drainer detector
├── popup/
│   ├── popup.html             # Glassmorphic safety dashboard UI
│   ├── popup.js               # Reactive score calculator, shield toggles, in-place rescan
│   └── popup.css              # Dashboard styling, accent variables, SVG radial gauge
├── options/
│   ├── options.html           # Settings UI (PII sandbox, whitelist, audit log, metrics)
│   ├── options.js             # Options controller, sandbox redactor, ReDoS checks, schema validator
│   └── (shared styling)
├── scripts/
│   ├── pack.js                # Zero-dependency MS-DOS/DEFLATE extension zip packager
│   └── bench.js               # Zero-dependency performance benchmark suite (node:perf_hooks)
├── tests/
│   ├── dashboard-score.test.js# Dashboard scoring engine & safety status transition tests
│   ├── url-safety.test.js     # URL analyzer unit, IDN, shorteners, dangerous executables
│   ├── pii-detector.test.js   # PII, Luhn algorithm, IBAN ISO 7064, LRU cache, ReDoS test suite
│   ├── scam-detector.test.js  # Scam, quishing, zero-width evasion, Web3 drainer tests
│   ├── storage-sync.test.js   # Whitelist wildcard, backup schema & ReDoS rejection tests
│   ├── pack.test.js           # Extension packager & zip structure tests
│   ├── bench.test.js          # Benchmark suite unit tests
│   └── e2e/
│       ├── extension-lifecycle.test.js # Headless browser extension lifecycle & UI E2E test
│       └── cdp-client.js      # Zero-dependency Chrome DevTools Protocol client
├── test-page.html             # Interactive browser sandbox for manual extension verification
└── package.json               # Scripts, static check scripts, and project metadata
```

---

## Performance Benchmarks

OSN Guard achieves microsecond-level execution latency to prevent any disruption to social feed scrolling:

| Component | Throughput | Average Latency |
| :--- | :--- | :--- |
| **URL Safety Analyzer** | ~100,000+ ops/sec | 0.0099 ms / op |
| **PII Detection Engine** | ~117,000+ ops/sec | 0.0085 ms / op |
| **PII Masking & Redaction** | ~120,000+ ops/sec | 0.0083 ms / op |
| **Scam & Fraud Classifier** | ~47,000+ ops/sec | 0.0213 ms / op |

*Measured on standard workstation hardware via `npm run bench`.*

---

## Running Automated Tests & Verification

OSN Guard uses Node.js's native test runner (`node:test` and `node:assert/strict`) with **zero third-party dependencies**:

```bash
# 1. Run static syntax verification across all source, script, and test files
npm run check

# 2. Run complete unit test suite (100 tests across 22 suites)
npm test

# 3. Run performance benchmarks
npm run bench

# 4. Run automated headless Chrome/Edge E2E lifecycle tests
npm run test:e2e

# 5. Build production Chrome Web Store distribution archive
npm run pack
```

---

## Loading the Extension in Chrome / Edge / Brave

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `osn-safety-scanner` directory.
5. Open [`test-page.html`](test-page.html) in your browser to test all shields in action.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
