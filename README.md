# OSN Guard 🛡️

> **Autonomous, real-time client-side privacy & phishing shield for the social web — 100% offline, zero network egress, zero dependencies.**

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](manifest.json)
[![Manifest](https://img.shields.io/badge/Manifest-V3-success.svg)](manifest.json)
[![Browsers](https://img.shields.io/badge/browsers-Chrome%20%7C%20Firefox%20%7C%20Safari-orange.svg)](scripts/pack.js)
[![CI Matrix](https://img.shields.io/badge/CI-Node%2018%20%7C%2020%20%7C%2022-blue.svg)](.github/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-241%20passing-brightgreen.svg)](tests/)
[![Benchmarks](https://img.shields.io/badge/benchmarks-160k%2B%20ops%2Fsec-orange.svg)](scripts/bench.js)
[![Security](https://img.shields.io/badge/CSP-zero--network--egress-blueviolet.svg)](manifest.json)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## ⚡ What Happens in Real Time (At a Glance)

OSN Guard intercepts accidental data leaks and deceptive threats in the page DOM **before data leaves your device**:

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│ 1. PRE-SUBMISSION PII INTERCEPTION (Social Comment / AI Composer)                 │
│                                                                                   │
│  User types: "Here is the test card 4532 0154 9876 3214 and token sk-live-51A..." │
│                                                                                   │
│  ⚠️ [OSN GUARD SHIELD ACTIVATED]                                                  │
│  • Leaked Payment Card (Luhn Mod-10 Verified)                                     │
│  • Leaked Stripe Secret Key (High-Entropy Token)                                   │
│  [🛡️ Redact & Sanitize]  [📋 Copy Cleaned]  [✕ Dismiss]                           │
├───────────────────────────────────────────────────────────────────────────────────┤
│ 2. FEED PHISHING & CRYPTO SCAM SCANNER (60 FPS Infinite Scroll)                   │
│                                                                                   │
│  Feed link: "https://аpple.com/login"  ──► 🚨 [IDN Homoglyph / Punycode Spoof]    │
│  Feed post: "Elon giveaway doubling"   ──► 🚨 [Aho-Corasick Multi-Pattern Scam]   │
│  Feed QR:   [Embedded QR Image]        ──► 🚨 [Visual Quishing Phishing Target]   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 30-Second Quickstart (Zero Dependencies)

OSN Guard requires only native Node.js (v18, v20, or v22) — **no `npm install` required**.

```bash
# 1. Clone repository
git clone https://github.com/RohanKhadke20/OSN_Extension.git
cd OSN_Extension

# 2. Run test suite (241 tests pass in < 2.0s)
npm test

# 3. Build standalone packages for Chrome, Firefox, & Safari
npm run pack:all
```

To load unpacked in your browser:
1. Open `chrome://extensions/` -> Enable **Developer mode**.
2. Click **Load unpacked** -> Select the `OSN_Extension` directory.
3. Open [`test-page.html`](test-page.html) to test all security shields live in an interactive sandbox.

---

## 📖 Deep-Dive Engineering Case Study

For a comprehensive breakdown of the hard technical problems solved, algorithms designed, and architectural trade-offs made, read:
👉 **[Architecture & Systems Engineering Deep Dive (docs/DESIGN.md)](docs/DESIGN.md)**

---

## Architectural Highlights & Engineering Design


```
                     ┌──────────────────────────────────────────────┐
                     │          OSN Guard Service Worker            │
                     │       (src/background/service-worker.js)     │
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
│  │ (src/content/scanner.js)│      │   - Real-time PII guard   │  │
│  │   - 10ms frame budget   │◄────►│   - Floating alert banner │  │
│  │   - Batched DOM rAF/rIC │      │   - Luhn / ISO 7064 checks│  │
│  │   - Shared body tooltip │      │   - Zero-reflow detection │  │
│  └────────────┬────────────┘      └───────────────────────────┘  │
│               │                                                  │
│               ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │             Core Compatibility & Threat Engines             │ │
│  │  1. src/core/compat.js (OSNCompat cross-browser shim)       │ │
│  │  2. src/core/threat-config.js (Canonical DEFAULT_CONFIG)   │ │
│  │  3. src/core/url-analyzer.js (Safe registries, Punycode)   │ │
│  │  4. src/core/pii-analyzer.js (Cards, IBAN, SSN, ReDoS safe) │ │
│  │  5. src/core/scam-analyzer.js (Aho-Corasick, Quishing)      │ │
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

### 6. Reliability, Self-Healing & Ethical Growth (Phase 2 Hardening)
* **Extension Invalidation Teardown**: When the extension is reloaded or updated, orphaned content scripts automatically disconnect mutation observers, cancel pending animation frames, and purge event listeners without throwing uncaught exceptions.
* **Pathological DOM Bounding**: Hard caps on links (`MAX_PAGE_LINKS_LIMIT = 500`) and feed cards (`MAX_PAGE_CONTAINERS_LIMIT = 200`) with zero-allocation direct indexing prevent browser lockup on giant 10,000-node DOM trees.
* **Storage Schema Self-Healing**: Automatically repairs corrupted or `NaN` counters, invalid booleans, and malformed arrays upon service worker startup without altering valid user rules.
* **Pre-Reset Undo Rollback**: Factory reset and stats clearing create an encrypted local snapshot with a 10-second undo window.
* **Local-Only Ethical Review Prompt**: Frequency-capped, zero-telemetry rating banner requiring at least 3 days retention and 5 threats or 50 links scanned, with a 14-day deferral cooldown.
* **Cross-Browser Packaging Pipeline**: Zero-dependency MS-DOS/DEFLATE packager generating certified packages for Chromium MV3, Firefox Gecko Event Pages, and Safari Web Extensions.

### 7. Advanced Engine & Enterprise Governance (Phase 3)
* **Visual Quishing (QR Phishing) Interception**: Frame-budgeted image inspection utilizing native `window.BarcodeDetector` (with automatic fallback to QR payload attributes). Decodes QR destinations in social cards/embedded images and immediately overlays visual warning badges if destinations point to malicious or unverified sites.
* **Aho-Corasick Multi-Pattern Trie Automaton**: Linear-time `O(n + m)` string matching trie replacing legacy loop scanning in `src/core/scam-analyzer.js`. Precompiles keyword failure transitions at startup, yielding **210,000+ ops/sec throughput** (0.005 ms/op) for real-time feed processing.
* **Chrome Enterprise Managed Storage Policy**: Fully compliant Chrome Enterprise schema (`managed_schema.json`) supporting corporate endpoint deployment via GPO / Google Admin Console. Automatically syncs `chrome.storage.managed` into local state, enforcing mandatory corporate whitelist domains, proprietary custom PII rules, and locking protection shields against employee tampering.

---

## Project Structure

```
osn-safety-scanner/
├── .github/
│   └── workflows/ci.yml       # Automated CI matrix (Node 18/20/22 on Ubuntu & Windows)
├── dist/                      # Multi-browser distribution packages (Chrome, Firefox, Safari)
├── docs/                      # Authoritative project documentation & research
│   ├── RESEARCH.md            # WebExtensions MV3 standards, browser matrix, & CVE analysis
│   ├── DECISIONS.md           # Architecture Decision Records (ADR-001 through ADR-006)
│   ├── CHANGELOG.md           # Keep a Changelog version history (v1.0.0 through v1.3.0)
│   ├── API_REFERENCE.md       # Full API contracts, IPC protocol, & function signatures
│   ├── DEVELOPMENT.md         # Developer onboarding & unpacked extension setup guide
│   ├── COMPATIBILITY.md       # Cross-browser shim architecture & manifest variance
│   ├── THREAT_MODEL.md        # STRIDE threat model & attack surface analysis
│   ├── STORE_LISTING.md       # Chrome Web Store & Firefox AMO listing copy
│   ├── ROADMAP.md             # Strategic technical roadmap (v1.4 to v2.0)
│   └── PROJECT_ENGINEERING_BASELINE.md # Engineering baseline assessment
├── manifest.json              # Manifest V3 configuration (Least-privilege, strict CSP)
├── managed_schema.json        # Chrome Enterprise Managed Storage policy schema
├── src/                       # Production extension source code
│   ├── assets/icons/          # Extension toolbar & store icons (PNG & SVG)
│   ├── background/
│   │   └── service-worker.js  # MV3 Service worker (session store, badge sync, IPC, self-healing)
│   ├── content/
│   │   ├── scanner.js         # Batched DOM scanner, visual quishing, memory bounds
│   │   └── scanner.css        # Tooltip, badge, alert banners, & toast styles
│   ├── core/
│   │   ├── compat.js          # Cross-browser shim & Promise/callback bridge (OSNCompat)
│   │   ├── threat-config.js   # Canonical threat configuration data & deepFreeze
│   │   ├── url-analyzer.js    # URL safety engine, IDN homoglyphs, IP obfuscation, shorteners
│   │   ├── pii-analyzer.js    # Multi-pattern PII detector, Luhn, ISO 7064 IBAN, ReDoS linter
│   │   └── scam-analyzer.js   # Aho-Corasick trie, zero-width evasion, Quishing, Web3 drainers
│   └── ui/
│       ├── popup/             # Popup dashboard markup, styles, & reactive gauge
│       └── options/           # Options configuration UI, PII sandbox, & audit log
├── scripts/
│   ├── pack.js                # Zero-bundler multi-target packager (Chrome, Firefox, Safari)
│   └── bench.js               # Zero-dependency performance benchmark suite
├── tests/
│   ├── compat.test.js         # Cross-browser shim unit tests (5 tiers, 100 tests)
│   ├── threat-config.test.js  # Threat configuration immutability & factory tests
│   ├── dashboard-score.test.js# Dashboard scoring engine & safety status transition tests
│   ├── url-safety.test.js     # URL analyzer unit, IDN, shorteners, dangerous executables
│   ├── pii-detector.test.js   # PII, Luhn algorithm, IBAN ISO 7064, LRU cache, ReDoS test suite
│   ├── scam-detector.test.js  # Aho-Corasick automaton, scam, quishing, zero-width evasion
│   ├── storage-sync.test.js   # Enterprise managed policy sync, whitelist wildcard, self-healing
│   ├── review-prompt.test.js  # Ethical review prompt eligibility test suite
│   ├── pack.test.js           # Multi-target extension packager & zip structure tests
│   ├── bench.test.js          # Benchmark suite unit tests
│   └── e2e/
│       ├── extension-lifecycle.test.js # Headless browser lifecycle & DOM burst E2E
│       └── cdp-client.js      # Zero-dependency Chrome DevTools Protocol client
├── test-page.html             # Interactive browser sandbox for manual extension verification
└── package.json               # Scripts, static check scripts, and project metadata
```

---

## Performance Benchmarks

OSN Guard achieves microsecond-level execution latency to prevent any disruption to social feed scrolling:

| Component | Throughput | Average Latency |
| :--- | :--- | :--- |
| **URL Safety Analyzer** | ~116,000+ ops/sec | 0.0086 ms / op |
| **PII Detection Engine** | ~137,000+ ops/sec | 0.0073 ms / op |
| **PII Masking & Redaction** | ~147,000+ ops/sec | 0.0068 ms / op |
| **Scam & Fraud Classifier (Aho-Corasick)** | ~217,000+ ops/sec | 0.0046 ms / op |

*Measured on standard workstation hardware via `npm run bench`.*

---

## Running Automated Tests & Verification

OSN Guard uses Node.js's native test runner (`node:test` and `node:assert/strict`) with **zero third-party dependencies**:

```bash
# 1. Run static syntax verification across all source, script, and test files
npm run check

# 2. Run complete unit test suite (241 tests across 55 suites)
npm test

# 3. Run performance benchmarks
npm run bench

# 4. Run automated headless Chrome/Edge E2E lifecycle & pathological burst tests
npm run test:e2e

# 5. Build multi-target production distribution archives
npm run pack:chrome     # Builds dist/osn-guard-safety-privacy-shield-v1.3.0.zip
npm run pack:firefox    # Builds dist/osn-guard-safety-privacy-shield-firefox-v1.3.0.zip
npm run pack:safari     # Builds dist/osn-guard-safety-privacy-shield-safari-v1.3.0.zip
npm run pack:all        # Builds all three browser targets simultaneously
```

---

## Loading the Extension in Chrome / Edge / Brave

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `osn-safety-scanner` directory.
5. Open [`test-page.html`](test-page.html) in your browser to test all shields in action.

---

## Community & Contributing

We welcome community contributions! Please read our guidelines before submitting issues or pull requests:

* **[Contributing Guidelines](CONTRIBUTING.md)**: Setup instructions, coding standards, and PR workflows.
* **[Code of Conduct](CODE_OF_CONDUCT.md)**: Contributor Covenant v2.1 standards.
* **[Security Policy](SECURITY.md)**: Responsible vulnerability disclosure process.
* **[Changelog](CHANGELOG.md)**: Release history and version notes.
* **[Architecture Decision Records](docs/DECISIONS.md)**: Structural and technical decision rationale.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

