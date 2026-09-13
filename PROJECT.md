# Project: OSN Guard Multi-Target Adaptability Platform

## Architecture
OSN Guard (`osn-safety-scanner`) is a browser security extension protecting users on social networking and web platforms against phishing, scam lures, quishing, malicious redirects, and PII leakage.

```
+-----------------------------------------------------------------------------------------------+
|                                      Web Browser Contexts                                     |
|                                                                                               |
|  [ Content Script (src/content/scanner.js) ] [ Toolbar Popup (src/ui/popup/popup.js) ]       |
|   - 10ms frame-budget DOM scan                - Status, shields toggle, threat stats          |
|   - ReDoS-safe PII input guard                - Browser-aware review & internal link routing  |
|   - QR code quishing inspection                                                               |
|          |                                              |                                     |
|          | (chrome.runtime.sendMessage)                 | (chrome.storage / runtime)          |
|          v                                              v                                     |
|  +-----------------------------------------------------------------------------------------+  |
|  |             Cross-Browser Compatibility Shim Layer (src/core/compat.js)                 |  |
|  |  - Bidirectional chrome.* <-> browser.* namespace unification                            |  |
|  |  - Dual Callback / Promise bridge for asynchronous extension methods                   |  |
|  |  - Storage session & managed fallbacks; Action/browserAction normalization               |  |
|  |  - Browser-aware internal scheme & review store URL resolver                            |  |
|  +-----------------------------------------------------------------------------------------+  |
|                                         |                                                     |
|                                         v                                                     |
|  [ Background Coordinator (src/background/service-worker.js) ] <---> [ Options (options.js) ]|
|   - Service Worker (Chrome/Safari)                  - Managed policy display                  |
|   - Non-persistent Event Page (Firefox)             - Whitelist & Custom PII editor           |
|   - Session reconciliation & IPC validation         - Live detection sandbox preview          |
|                                         |                                                     |
|                                         v                                                     |
|  +-----------------------------------------------------------------------------------------+  |
|  |             Data-Driven Threat Detection Engines (src/core/*.js)                        |  |
|  |  - src/core/threat-config.js: Canonical signatures, defaults, deepFreeze                |  |
|  |  - src/core/url-analyzer.js:  Heuristics, TLDs, Punycode, Redirects (OSNUrlAnalyzer)    |  |
|  |  - src/core/pii-analyzer.js:  Built-ins, ReDoS-validated custom rules (OSNPiiAnalyzer)  |  |
|  |  - src/core/scam-analyzer.js: Aho-Corasick linear keyword matching (OSNScamAnalyzer)    |  |
|  +-----------------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------------+
```

## Feature Inventory
Every feature from the Survey phase is mapped to an assigned milestone:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Cross-Browser Compatibility Shim | Unified, zero-dependency shim (`src/core/compat.js`) bridging `chrome.*` and `browser.*` namespaces with dual callback and Promise support across background, content, popup, and options scripts. | M1 | ORIGINAL_REQUEST §R1 |
| F2 | Storage API Degradation & Fallbacks | Transparent fallbacks for `storage.session` (prefixed `storage.local` or memory fallback where missing in Firefox/Safari) and `storage.managed` (safe no-op `{}` returning empty object where undefined). | M1 | Survey 1 & 3 |
| F3 | UI & Browser Lifecycle Normalization | Normalization of `action` vs `browserAction`, `contextMenus` vs `menus`, cross-browser internal URL detection (`chrome://`, `moz-extension://`, `safari-web-extension://`), and dynamic review store URL resolution. | M1 | Survey 1 |
| F4 | Data-Driven URL Safety Engine | Decouple safe domains, suspicious domains, TLDs, phishing keywords, shorteners, and thresholds in `src/core/url-analyzer.js` via `src/core/threat-config.js` and factory pattern. | M2 | ORIGINAL_REQUEST §R2 |
| F5 | Data-Driven Scam & Quishing Classifier | Decouple 15 scam categories in `src/core/scam-analyzer.js` into configurable data structures via `src/core/threat-config.js`, precompiling Aho-Corasick automaton to guarantee >= 100k ops/sec. | M2 | ORIGINAL_REQUEST §R2 |
| F6 | Data-Driven PII Detection Engine | Decouple built-in PII patterns and severity thresholds in `src/core/pii-analyzer.js` into configurable data structures, enforcing static ReDoS validation on all dynamic rules. | M2 | ORIGINAL_REQUEST §R2 |
| F7 | Multi-Target Build & Manifest Variance | Ensure `scripts/pack.js` produces valid standalone ZIP packages and manifests for Chromium MV3, Firefox Gecko Event Pages (`background.scripts` ordered dependencies), and Safari WebExtensions without bundlers. | M3 | ORIGINAL_REQUEST §R1, §R3 |
| F8 | Cross-Browser Architecture Documentation | Author comprehensive `docs/COMPATIBILITY.md` detailing cross-browser compatibility architecture, API shim patterns, manifest variance matrix, and lifecycle behavior across browsers. | M3 | ORIGINAL_REQUEST §R1 |
| F9 | Multi-Target Quality Verification & Test Suite | Implement automated unit tests for shim (`tests/compat.test.js`) and threat config (`tests/threat-config.test.js`), verify 100% pass of 241 unit tests and 6 E2E tests, and verify scam classifier benchmark >= 100k ops/sec. | M4 | ORIGINAL_REQUEST §R4 |
| F10 | Static Security & Forensic Integrity Verification | Static security pass on CSP (`connect-src 'none'`), least-privilege permissions (`storage`, `activeTab`, `contextMenus`), IPC sender verification, prototype pollution defenses, ReDoS safety, and deliver final before/after audit status table. | M4 | ORIGINAL_REQUEST §R4 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Cross-Browser Compatibility Shim Architecture | Create `src/core/compat.js`, integrate across `manifest.json`, `src/background/service-worker.js`, `src/content/scanner.js`, `src/ui/popup/`, `src/ui/options/`. | none | COMPLETED |
| M2 | Data-Driven Detection Engine Adaptability | Decouple hardcoded threat rules and thresholds via `src/core/threat-config.js` in `src/core/url-analyzer.js`, `src/core/pii-analyzer.js`, and `src/core/scam-analyzer.js`. Maintain default facades and benchmark performance. | M1 | COMPLETED |
| M3 | Multi-Target Build, Manifest Variance & Documentation | Update `scripts/pack.js` and packaging tests for `src/core/compat.js`, author `docs/COMPATIBILITY.md`, verify standalone artifacts in `dist/`. | M1, M2 | COMPLETED |
| M4 | E2E Verification, Performance Budgets & Forensic Audit | Pass 100% of unit tests (241 tests across 55 suites), pass 6 E2E tests, verify `npm run bench` (scam classifier >= 100k ops/s), complete forensic audit pass. | M1, M2, M3 | COMPLETED |

## Interface Contracts

### Compatibility Shim (`src/core/compat.js`) ↔ Extension Components
- **Global Exports**: `globalThis.OSNCompat`, `globalThis.chrome`, `globalThis.browser`.
- **Signatures**:
  - `OSNCompat.isFirefox`: boolean
  - `OSNCompat.isSafari`: boolean
  - `OSNCompat.isChromium`: boolean
  - `OSNCompat.isInternalUrl(url: string): boolean` (matches `chrome://`, `chrome-extension://`, `moz-extension://`, `safari-web-extension://`, `safari://`, `about:`, `edge://`)
  - `OSNCompat.getStoreReviewUrl(browserEngine?: string): string`
  - `OSNCompat.promisifyOrCallback(fn, context, ...args)`
- **Behavior**: When invoked with a callback function as the final argument, routes to native API with callback; when invoked without a callback, returns a native `Promise`.

### Data-Driven Threat Config (`src/core/threat-config.js`)
- **Exports**: `DEFAULT_THREAT_CONFIG`, `deepFreeze`.
- **Behavior**: Canonical, deeply frozen configurations for url, pii, and scam engines.

### Data-Driven URL Analyzer (`src/core/url-analyzer.js`)
- **Factory**: `OSNUrlAnalyzer.create(userConfig?: Object): Object`
- **Default Facade**: `OSNUrlAnalyzer.analyzeUrlSafety(urlString: string, whitelistedDomains?: string[]): Object`

### Data-Driven Scam Analyzer (`src/core/scam-analyzer.js`)
- **Factory**: `OSNScamAnalyzer.create(userConfig?: Object): Object`
- **Default Facade**: `OSNScamAnalyzer.detectScamContent(text: string): Object`
- **Algorithm**: Aho-Corasick linear-time multi-pattern trie automaton matching 216+ keywords in `O(n + m)` time.

### Data-Driven PII Analyzer (`src/core/pii-analyzer.js`)
- **Factory**: `OSNPiiAnalyzer.create(userConfig?: Object): Object`
- **Default Facade**: `OSNPiiAnalyzer.detectPii(text: string, customPatterns?: Array<{ name: string, pattern: string }>): Array<Object>`
- **Validation**: Every custom regex pattern must pass `OSNPiiAnalyzer.isSafeRegexPattern(pattern)` before inclusion.

## Code Layout & Component Structure
- **`src/core/compat.js`**: Cross-browser compatibility shim and Promise/callback bridge.
- **`src/core/threat-config.js`**: Centralized canonical threat configuration and schema constants.
- **`src/core/url-analyzer.js`, `src/core/pii-analyzer.js`, `src/core/scam-analyzer.js`**: Data-driven detection engines.
- **`src/background/service-worker.js`**: MV3 service worker coordinator, session reconciliation, and IPC validation.
- **`src/content/scanner.js`, `src/content/scanner.css`**: Cooperative DOM scanner, Quishing detector, and alert tooltips.
- **`src/ui/popup/*`, `src/ui/options/*`**: Extension popup dashboard and configuration interfaces.
- **`scripts/pack.js`**: Zero-bundler multi-target packager (Chrome, Firefox, Safari).
- **`docs/`**: Single source of truth documentation (`RESEARCH.md`, `DECISIONS.md`, `CHANGELOG.md`, `API_REFERENCE.md`, `DEVELOPMENT.md`, `COMPATIBILITY.md`).
- **`tests/`**: Automated unit test suites, performance benchmarks, and CDP headless integration tests.
