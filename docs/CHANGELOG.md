# Changelog

All notable changes to the OSN Guard project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Authoritative continuous security & dependency research baseline in `docs/RESEARCH.md`.
- Comprehensive Architecture Decision Records (ADRs 001–006) in `docs/DECISIONS.md`.
- Exhaustive module and IPC interface reference in `docs/API_REFERENCE.md`.
- Developer onboarding and local multi-browser extension loading guide in `docs/DEVELOPMENT.md`.

### Changed
- Synchronized all documentation (`docs/COMPATIBILITY.md`, `docs/PROJECT_ENGINEERING_BASELINE.md`, `docs/ROADMAP.md`, root `README.md`, and `PROJECT.md`) to eliminate architectural drift and reflect the current `src/` modular layout and 241 unit test suite.

---

## [1.3.0] - 2026-09-13

### Added
- **Cross-Browser Compatibility Shim (`src/core/compat.js`):**
  - Dependency-free UMD module exporting `OSNCompat` to `globalThis` and `module.exports`.
  - Bidirectional namespace unification between `chrome.*` and `browser.*`.
  - Dual Callback / Promise bridge (`promisifyOrCallback`) supporting synchronous returns and async callback/Promise workflows.
  - Transparent ephemeral storage fallbacks (`storage.session` prefixed on `storage.local` where native session is absent).
  - Safe managed storage stubs (`storage.managed`) preventing uncaught promise rejections on unmanaged endpoints.
  - Action/browserAction and contextMenus/menus normalization.
  - Browser-aware review store and internal scheme resolvers (`chrome-extension://`, `moz-extension://`, `safari-web-extension://`).
- **Data-Driven Threat Configuration Engine (`src/core/threat-config.js`):**
  - Canonical `DEFAULT_THREAT_CONFIG` with deeply frozen structures for URL heuristics, PII thresholds, and scam detection rules.
  - Factory instantiation pattern (`createUrlEngine`, `createPiiEngine`, `createScamEngine`) allowing dynamic overrides while preserving backwards-compatible default instances.
- **Micro-Quantized Scam Keyword Trie (`src/core/scam-analyzer.js`):**
  - Implemented Aho-Corasick multi-pattern trie automaton for simultaneous keyword evaluation in linear time O(n + m).
  - Verified benchmark throughput exceeding 200,000 operations per second.
- **Enterprise Managed Policy Synchronization:**
  - Added `managed_schema.json` supporting `forcedWhitelistedDomains`, `mandatoryCustomPiiRules`, and `enforcedShields`.
  - Service worker policy listener merging enterprise rules into local storage state seamlessly.
- **Multi-Target Zero-Bundler Packaging Pipeline (`scripts/pack.js`):**
  - Node.js built-in packaging script using `node:zlib` and raw DEFLATE to build standalone ZIP archives for Chrome, Firefox, and Safari in `dist/`.
  - Dynamic target-specific manifest generation (Firefox Event Page `background.scripts` array with dependency order; Gecko ID injection; Safari minimum versioning).
- **Comprehensive Test Expansion:**
  - Expanded automated test coverage to 241 unit tests across 55 test suites and 6 headless E2E tests with 100% pass rate.

### Changed
- Reorganized codebase from a flat root directory into a conventional `src/` modular structure (`src/core/`, `src/background/`, `src/content/`, `src/ui/options/`, `src/ui/popup/`, `src/assets/icons/`).
- Updated manifest entries, service worker `importScripts`, HTML script tags, and test paths to reflect the `src/` hierarchy.

---

## [1.2.0] - 2026-09-10

### Added
- **Quishing (QR Code Phishing) Visual Engine (`src/content/scanner.js`):**
  - Integrated native browser `BarcodeDetector` API for client-side QR code extraction from feed images (`<img>`, `<svg>`, `canvas`).
  - Extracted URL targets evaluated offline through `OSNUrlAnalyzer` before user scans with external devices.
- **Zero-Width Evasion Defense (`src/core/scam-analyzer.js`):**
  - Detection and sanitization of invisible Unicode evasion characters: Zero-Width Space (`\u200B`), Zero-Width Non-Joiner (`\u200C`), Zero-Width Joiner (`\u200D`), Byte Order Mark (`\uFEFF`), and directional marks (LRM/RLM).
- **Ethical Review Prompt Engine (`src/ui/popup/popup.js`):**
  - Local-only, zero-telemetry review prompt eligibility evaluator with usage threshold (>= 5 threats or >= 50 links), retention gate (>= 3 days installed), and 14-day frequency cooldown.
- **Rolling Security Audit Log (`src/background/service-worker.js`):**
  - Ephemeral audit buffer (capped at 50 events) with domain anonymization, JSON export, and clear controls in the options UI.

---

## [1.1.0] - 2026-09-08

### Added
- **Cooperative DOM Scan Batching (`src/content/scanner.js`):**
  - 10ms frame-budget scheduler using `requestIdleCallback` (with `setTimeout` fallback) and batch limits (30 containers, 50 links per tick) ensuring smooth 60 FPS scrolling.
- **ReDoS Static Validation & Regex Caching (`src/core/pii-analyzer.js`):**
  - `isSafeRegexPattern()` static analyzer rejecting catastrophic backtracking patterns, excessive lengths, and nested quantifiers in custom PII rules.
  - LRU-capped compilation cache for custom regular expressions.
- **Storage Self-Healing & Reconciliation (`src/background/service-worker.js`):**
  - `sanitizeAndRepairStorage()` restoring corrupted or missing schema fields on startup.
  - `reconcileOrphanedTabs()` pruning storage keys for closed or crashed tabs across service worker sleep cycles.
- **Prototype Pollution Defenses:**
  - Enforced `isPollutionKey()` blocking `__proto__`, `constructor`, and `prototype` in backup JSON imports and object utilities.
- **Native CDP Headless Test Automation:**
  - Automated extension lifecycle and UI rendering verification using Chrome DevTools Protocol via native Node.js HTTP/WebSocket primitives.

---

## [1.0.0] - 2026-09-01

### Added
- Initial public release of OSN Guard for Chromium Manifest V3.
- Core URL safety engine evaluating safe registries, phishing keywords, punycode/IDN homographs, raw IP hosts, userinfo credentials, and external open redirects.
- Core PII analyzer intercepting sensitive data in social post composers with ISO 7064 Mod-97 IBAN, Luhn Mod-10 payment cards, and US SSN validation.
- Core scam classifier detecting cryptocurrency doubling lures, wallet drainers, urgent account threats, and tech support imposters.
- Insecure HTTP form action detection on HTTPS pages.
- Dark-themed popup dashboard featuring animated circular safety score gauge and real-time shield toggles.
- Options configuration page featuring domain whitelist editor, custom PII rule manager, live sandbox preview, and settings export/import.
- Strict Content Security Policy (`connect-src 'none'`) guaranteeing zero network egress and complete on-device privacy.
