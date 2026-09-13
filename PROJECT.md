# Project: OSN Guard Multi-Target Adaptability Platform

## Architecture
OSN Guard (`osn-safety-scanner`) is a browser security extension protecting users on social networking and web platforms against phishing, scam lures, quishing, malicious redirects, and PII leakage.

```
+-----------------------------------------------------------------------------------------------+
|                                      Web Browser Contexts                                     |
|                                                                                               |
|  [ Content Script (content.js) ]           [ Toolbar Popup (popup/popup.js) ]                 |
|   - 10ms frame-budget DOM scan              - Status, shields toggle, threat stats            |
|   - ReDoS-safe PII input guard              - Browser-aware review & internal link routing    |
|   - QR code quishing inspection                                                               |
|          |                                            |                                       |
|          | (chrome.runtime.sendMessage)               | (chrome.storage / runtime)            |
|          v                                            v                                       |
|  +-----------------------------------------------------------------------------------------+  |
|  |             Cross-Browser Compatibility Shim Layer (core/compat.js)                     |  |
|  |  - Bidirectional chrome.* <-> browser.* namespace unification                            |  |
|  |  - Dual Callback / Promise bridge for asynchronous extension methods                   |  |
|  |  - Storage session & managed fallbacks; Action/browserAction normalization               |  |
|  |  - Browser-aware internal scheme & review store URL resolver                            |  |
|  +-----------------------------------------------------------------------------------------+  |
|                                         |                                                     |
|                                         v                                                     |
|  [ Background Coordinator (background.js) ] <---> [ Options & Sandbox UI (options.js) ]       |
|   - Service Worker (Chrome/Safari)                  - Managed policy display                  |
|   - Non-persistent Event Page (Firefox)             - Whitelist & Custom PII editor           |
|   - Session reconciliation & IPC validation         - Live detection sandbox preview          |
|                                         |                                                     |
|                                         v                                                     |
|  +-----------------------------------------------------------------------------------------+  |
|  |             Data-Driven Threat Detection Engines (core/*.js)                            |  |
|  |  - core/url-analyzer.js:  Heuristics, TLDs, Punycode, Redirects (createUrlEngine)       |  |
|  |  - core/pii-analyzer.js:  Built-ins, ReDoS-validated custom rules (createPiiEngine)    |  |
|  |  - core/scam-analyzer.js: Aho-Corasick linear keyword matching (createScamEngine)      |  |
|  +-----------------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------------+
```

## Feature Inventory
Every feature from the Survey phase is mapped to an assigned milestone:

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Cross-Browser Compatibility Shim | Unified, zero-dependency shim (`core/compat.js`) bridging `chrome.*` and `browser.*` namespaces with dual callback and Promise support across background, content, popup, and options scripts. | M1 | ORIGINAL_REQUEST §R1 |
| F2 | Storage API Degradation & Fallbacks | Transparent fallbacks for `storage.session` (prefixed `storage.local` or memory fallback where missing in Firefox/Safari) and `storage.managed` (safe no-op `{}` returning empty object where undefined). | M1 | Survey 1 & 3 |
| F3 | UI & Browser Lifecycle Normalization | Normalization of `action` vs `browserAction`, `contextMenus` vs `menus`, cross-browser internal URL detection (`chrome://`, `moz-extension://`, `safari-web-extension://`), and dynamic review store URL resolution. | M1 | Survey 1 |
| F4 | Data-Driven URL Safety Engine | Decouple 40 safe domains, 12 suspicious domains, 23 TLDs, 15 phishing keywords, 18 shorteners, 15 extensions, and thresholds in `core/url-analyzer.js` into data-driven configuration structures and `createUrlEngine` factory. | M2 | ORIGINAL_REQUEST §R2 |
| F5 | Data-Driven Scam & Quishing Classifier | Decouple 15 scam categories (216 keywords, 7 patterns) in `core/scam-analyzer.js` into configurable data structures with `createScamEngine`, precompiling Aho-Corasick automaton to guarantee >= 100k ops/sec. | M2 | ORIGINAL_REQUEST §R2 |
| F6 | Data-Driven PII Detection Engine | Decouple 9 built-in PII patterns and severity thresholds in `core/pii-analyzer.js` into configurable data structures with `createPiiEngine`, enforcing static ReDoS validation on all dynamic rules. | M2 | ORIGINAL_REQUEST §R2 |
| F7 | Multi-Target Build & Manifest Variance | Ensure `scripts/pack.js` produces valid standalone ZIP packages and manifests for Chromium MV3, Firefox Gecko Event Pages (`background.scripts` ordered dependencies), and Safari WebExtensions without bundlers. | M3 | ORIGINAL_REQUEST §R1, §R3 |
| F8 | Cross-Browser Architecture Documentation | Author comprehensive `docs/COMPATIBILITY.md` detailing cross-browser compatibility architecture, API shim patterns, manifest variance matrix, and lifecycle behavior across browsers. | M3 | ORIGINAL_REQUEST §R1 |
| F9 | Multi-Target Quality Verification & Test Suite | Implement automated unit tests for shim (`tests/compat.test.js`) and data-driven engines (`tests/data-driven.test.js`), verify 100% pass of existing 135+ unit tests and 6 E2E tests, and verify scam classifier benchmark >= 100k ops/sec. | M4 | ORIGINAL_REQUEST §R4 |
| F10 | Static Security & Forensic Integrity Verification | Static security pass on CSP (`connect-src 'none'`), least-privilege permissions (`storage`, `activeTab`, `contextMenus`), IPC sender verification, prototype pollution defenses, ReDoS safety, and deliver final before/after audit status table. | M4 | ORIGINAL_REQUEST §R4 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Cross-Browser Compatibility Shim Architecture | Create `core/compat.js`, integrate across `manifest.json`, `background.js`, `content.js`, `popup/popup.html`, `options/options.html`, `popup/popup.js`, `options/options.js`. | none | PLANNED |
| M2 | Data-Driven Detection Engine Adaptability | Decouple hardcoded threat rules and thresholds in `core/url-analyzer.js`, `core/pii-analyzer.js`, and `core/scam-analyzer.js`. Maintain default facades and benchmark performance. | M1 | PLANNED |
| M3 | Multi-Target Build, Manifest Variance & Documentation | Update `scripts/pack.js` and packaging tests for `core/compat.js`, author `docs/COMPATIBILITY.md`, verify standalone artifacts in `dist/`. | M1, M2 | PLANNED |
| M4 | E2E Verification, Performance Budgets & Forensic Audit | Pass 100% of unit tests (including new compat and data-driven tests), pass 6 E2E tests, verify `npm run bench` (scam classifier >= 100k ops/s), complete forensic audit pass. | M1, M2, M3 | PLANNED |

## Interface Contracts

### Compatibility Shim (`core/compat.js`) ↔ Extension Components
- **Global Exports**: `globalThis.OSNCompat`, `globalThis.chrome`, `globalThis.browser`.
- **Signatures**:
  - `OSNCompat.isFirefox`: boolean
  - `OSNCompat.isSafari`: boolean
  - `OSNCompat.isChromium`: boolean
  - `OSNCompat.isInternalUrl(url: string): boolean` (matches `chrome://`, `chrome-extension://`, `moz-extension://`, `safari-web-extension://`, `safari://`, `about:`, `edge://`)
  - `OSNCompat.getStoreReviewUrl(extensionId: string): string`
  - `OSNCompat.promisifyOrCallback(fn, context, args, callbackIndex)`
- **Behavior**: When invoked with a callback function as the final argument, routes to native API with callback; when invoked without a callback, returns a native `Promise`.

### Data-Driven URL Analyzer (`core/url-analyzer.js`)
- **Factory**: `OSNUrlAnalyzer.createUrlEngine(config?: Partial<UrlEngineConfig>): UrlEngine`
- **Default Facade**: `OSNUrlAnalyzer.analyzeUrlSafety(urlString: string, whitelistedDomains?: string[], _depth?: number, config?: Partial<UrlEngineConfig>): UrlSafetyResult`
- **Config Contract**:
  ```typescript
  interface UrlEngineConfig {
    safeDomains?: string[];
    suspiciousDomains?: string[];
    suspiciousTlds?: string[];
    phishingKeywords?: string[];
    shortenerDomains?: string[];
    dangerousFileExtensions?: string[];
    highRiskExecutableExtensions?: string[];
    dangerousSchemes?: string[];
    redirectParamNames?: string[];
    thresholds?: {
      phishingKeywordsThreshold?: number;
      excessiveSubdomainDepth?: number;
      maxRedirectDepth?: number;
      criticalHeuristicCount?: number;
    };
  }
  ```

### Data-Driven Scam Analyzer (`core/scam-analyzer.js`)
- **Factory**: `OSNScamAnalyzer.createScamEngine(rules?: ScamRule[], options?: ScamEngineOptions): ScamEngine`
- **Default Facade**: `OSNScamAnalyzer.detectScamContent(text: string, config?: Partial<ScamEngineConfig>): ScamDetectionResult`
- **Config Contract**:
  ```typescript
  interface ScamRule {
    id: string;
    category: string;
    severity: "critical" | "warning";
    keywords: string[];
    patterns?: RegExp[];
    reason: string;
    enabled?: boolean;
  }
  ```

### Data-Driven PII Analyzer (`core/pii-analyzer.js`)
- **Factory**: `OSNPiiAnalyzer.createPiiEngine(patterns?: PiiPattern[], options?: PiiEngineOptions): PiiEngine`
- **Default Facade**: `OSNPiiAnalyzer.detectPii(text: string, customPatterns?: CustomPattern[], config?: Partial<PiiEngineConfig>): PiiDetectionResult`
- **Validation**: Every custom regex pattern must pass `OSNPiiAnalyzer.isSafeRegexPattern(pattern)` before inclusion.

## Code Layout & Exclusive Write Ownership
- **`core/compat.js`**: Owned exclusively by M1 Worker.
- **`core/url-analyzer.js`, `core/pii-analyzer.js`, `core/scam-analyzer.js`**: Owned exclusively by M2 Worker.
- **`background.js`, `content.js`, `popup/*`, `options/*`**: Modified for M1 shim injection.
- **`scripts/pack.js`, `docs/COMPATIBILITY.md`**: Owned exclusively by M3 Worker.
- **`tests/compat.test.js`, `tests/data-driven.test.js`, `tests/manifest-variance.test.js`**: Owned exclusively by E2E Testing Track / Test Writer.
