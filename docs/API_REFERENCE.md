# OSN Guard — Architecture & API Reference

**Document ID:** OSN-API-REF-001  
**Version:** 1.3.0  
**Scope:** Complete internal API specifications, function signatures, IPC message schemas, and architectural contracts for OSN Guard across all runtime contexts.  

---

## Table of Contents

1. [Architectural Overview & Context Boundaries](#1-architectural-overview--context-boundaries)
2. [Core Modules (`src/core/`)](#2-core-modules-srccore)
   - [2.1 `src/core/compat.js` (`OSNCompat`)](#21-srccorecompatjs-osncompat)
   - [2.2 `src/core/threat-config.js` (`OSNThreatConfig`)](#22-srccorethreat-configjs-osnthreatconfig)
   - [2.3 `src/core/url-analyzer.js` (`OSNUrlAnalyzer`)](#23-srccoreurl-analyzerjs-osnurlanalyzer)
   - [2.4 `src/core/pii-analyzer.js` (`OSNPiiAnalyzer`)](#24-srccorepii-analyzerjs-osnpiianalyzer)
   - [2.5 `src/core/scam-analyzer.js` (`OSNScamAnalyzer`)](#25-srccorescam-analyzerjs-osnscamanalyzer)
3. [Background Coordinator (`src/background/service-worker.js`)](#3-background-coordinator-srcbackgroundservice-workerjs)
   - [3.1 IPC Message Protocol](#31-ipc-message-protocol)
   - [3.2 Tab Lifecycle & Storage Reconciliation](#32-tab-lifecycle--storage-reconciliation)
   - [3.3 Storage Self-Healing Schema](#33-storage-self-healing-schema)
4. [Content Script Scanner (`src/content/scanner.js`)](#4-content-script-scanner-srccontentscannerjs)
   - [4.1 Frame Budget Scheduler & Batching Limits](#41-frame-budget-scheduler--batching-limits)
   - [4.2 Composer PII Interception](#42-composer-pii-interception)
   - [4.3 Quishing (QR Phishing) Visual Engine](#43-quishing-qr-phishing-visual-engine)
5. [User Interface Controllers (`src/ui/`)](#5-user-interface-controllers-srcui)
   - [5.1 Popup Dashboard (`src/ui/popup/popup.js`)](#51-popup-dashboard-srcuipopuppopupjs)
   - [5.2 Options Configuration & Sandbox (`src/ui/options/options.js`)](#52-options-configuration--sandbox-srcuioptionsoptionsjs)

---

## 1. Architectural Overview & Context Boundaries

OSN Guard operates across four distinct extension execution boundaries:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Extension Runtime Contexts                        │
│                                                                             │
│  ┌───────────────────────┐                    ┌──────────────────────────┐  │
│  │ Content Script        │                    │ Extension Pages (UI)     │  │
│  │ (src/content/         │                    │ (src/ui/popup/, options/)│  │
│  │  scanner.js)          │                    │                          │  │
│  │ Context: Untrusted DOM│                    │ Context: Privileged Page │  │
│  └───────────┬───────────┘                    └────────────┬─────────────┘  │
│              │                                             │                │
│              │ chrome.runtime.sendMessage (IPC)            │ chrome.storage │
│              ▼                                             ▼                │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Background Service Worker / Event Page                                │  │
│  │ (src/background/service-worker.js)                                    │  │
│  │ Context: Privileged Service Worker / Event Script                     │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Shared Detection & Compatibility Engines (`src/core/`)                │  │
│  │ - compat.js (OSNCompat shim & dual Promise/callback bridge)           │  │
│  │ - threat-config.js (DEFAULT_THREAT_CONFIG & deepFreeze)               │  │
│  │ - url-analyzer.js (Safety heuristics, punycode, TLDs, redirects)      │  │
│  │ - pii-analyzer.js (ISO 7064, Luhn, SSN, ReDoS validation)             │  │
│  │ - scam-analyzer.js (Aho-Corasick linear trie, zero-width evasion)     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

All shared modules in `src/core/` are authored as Universal Module Definition (UMD) closures, enabling execution in browser pages, service workers, and Node.js testing harnesses without compilation or bundling.

---

## 2. Core Modules (`src/core/`)

### 2.1 `src/core/compat.js` (`OSNCompat`)

The cross-browser compatibility shim normalizes API differences across Chromium, Firefox Gecko, and Apple Safari.

#### Exports
- In Browser: `globalThis.OSNCompat`, `globalThis.chrome`, `globalThis.browser`
- In Node.js: `module.exports`

#### Properties & Methods
- `OSNCompat.isFirefox: boolean`  
  Read-only getter. Returns `true` if the executing engine is Mozilla Firefox Gecko.
- `OSNCompat.isSafari: boolean`  
  Read-only getter. Returns `true` if the executing engine is Apple Safari WebKit.
- `OSNCompat.isChromium: boolean`  
  Read-only getter. Returns `true` if the executing engine is Chromium-based (Chrome, Edge, Brave, Opera).
- `OSNCompat.isInternalUrl(url: string): boolean`  
  Returns `true` if `url` matches browser-internal schemes (`chrome://`, `chrome-extension://`, `moz-extension://`, `safari-web-extension://`, `about:`, `edge://`).
- `OSNCompat.getStoreReviewUrl(browserEngine?: string): string`  
  Returns the canonical store listing URL for user reviews based on detected browser engine (`chrome.google.com/webstore`, `addons.mozilla.org`, or Apple App Store).
- `OSNCompat.promisifyOrCallback(fn: Function, thisArg?: any, ...args: any[]): Promise<any> | any`  
  Executes an asynchronous browser API function. If the last argument is a callback, attaches it and forwards results; otherwise, returns a native `Promise`. Synchronous return values and synchronous exceptions are captured and handled gracefully.
- `OSNCompat.createSessionStorageFallback(backingStorage?: Object): Object`  
  Creates a standards-compliant `storage.session` drop-in replacement routing keys with prefix `__osn_session_` through `storage.local` when native `storage.session` is unavailable.
- `OSNCompat.createManagedStorageFallback(): Object`  
  Creates a safe `storage.managed` drop-in replacement returning `{}` for all queries without rejecting promises when running in unmanaged environments.
- `OSNCompat.setLastError(message: string): void`  
  Manually sets `chrome.runtime.lastError`.
- `OSNCompat.clearLastError(): void`  
  Clears any active `lastError`.
- `OSNCompat.getLastError(): { message: string } | null`  
  Retrieves current error state.
- `OSNCompat.init(targetGlobal?: Object): void`  
  Performs bidirectional namespace binding, action normalization (`action` ↔ `browserAction`), and menu normalization (`contextMenus` ↔ `menus`).

---

### 2.2 `src/core/threat-config.js` (`OSNThreatConfig`)

Provides canonical, deeply frozen threat data, signature sets, and detection thresholds used across all analyzers.

#### Exports
- In Browser: `globalThis.OSNThreatConfig`
- In Node.js: `module.exports`

#### Public Members
- `OSNThreatConfig.DEFAULT_THREAT_CONFIG: Object` (Deeply frozen)
  - `url`:
    - `safeDomains: string[]` — Top trusted social networks, tech platforms, and encyclopedias.
    - `suspiciousDomains: string[]` — Known phishing, fake login, and token-drop domains.
    - `suspiciousTlds: string[]` — Disposable or high-abuse TLDs (`.zip`, `.mov`, `.top`, `.tk`, etc.).
    - `phishingKeywords: string[]` — High-risk lures (`login`, `verify`, `wallet`, `airdrop`, etc.).
    - `shortenerDomains: string[]` — URL shortening services (`bit.ly`, `t.co`, `tinyurl.com`, etc.).
    - `dangerousExtensions: string[]` — Executable and script download file extensions (`.exe`, `.scr`, `.bat`, etc.).
    - `highRiskExecutableExtensions: string[]` — Critical executable formats triggering immediate blocking.
  - `pii`:
    - `thresholds`:
      - `minEntropy: number` (default: `3.8`) — Shannon entropy threshold for high-entropy API secrets.
      - `tokenMinLength: number` (default: `32`) — Minimum length for generic secret token scanning.
  - `scam`:
    - `rules: Array<{ id: string, category: string, severity: 'critical' | 'warning', keywords: string[], reason: string, patterns?: RegExp[] }>` — 15 structured threat rule definitions.
- `OSNThreatConfig.deepFreeze(obj: Object): Object`  
  Recursively applies `Object.freeze()` to an object graph, preventing runtime mutation or prototype poisoning.

---

### 2.3 `src/core/url-analyzer.js` (`OSNUrlAnalyzer`)

Evaluates destination URLs for phishing indicators, deceptive punycode, raw IP hosts, open redirects, and unsafe protocols.

#### Exports & Factories
- Default Instance: `OSNUrlAnalyzer` (browser global or CommonJS export)
- Factory Method: `OSNUrlAnalyzer.create(userConfig?: Object): Object`

#### API Methods
- `analyzeUrlSafety(rawUrl: string, whitelistedDomains?: string[]): { safe: boolean, reason: string, severity?: 'critical' | 'warning', details?: string[] }`  
  Evaluates a URL against safe registries, custom whitelists, homoglyphs, and threat heuristics.
- `isDomainWhitelisted(domain: string, whitelist: string[]): boolean`  
  Checks domain against whitelist, supporting wildcards (e.g. `*.example.com`) and subdomains.
- `isSafeDomain(domain: string): boolean`  
  Checks domain against trusted top-platform registry.
- `isRawIpAddress(hostname: string): boolean`  
  Flags IPv4, IPv6, octal, hex, and dword hostname encodings.
- `hasMixedScriptConfusables(domain: string): boolean`  
  Detects mixed-script homoglyphs (e.g. Cyrillic 'а' replacing Latin 'a').
- `isUrlShortener(domain: string): boolean`  
  Returns `true` if domain is a known URL shortening intermediary.
- `getDangerousFileExtension(urlObj: URL): string | null`  
  Extracts dangerous file extension from path if present.

---

### 2.4 `src/core/pii-analyzer.js` (`OSNPiiAnalyzer`)

Inspects input text for Personally Identifiable Information (PII) and secret credentials before network transmission.

#### Exports & Factories
- Default Instance: `OSNPiiAnalyzer`
- Factory Method: `OSNPiiAnalyzer.create(userConfig?: Object): Object`

#### API Methods
- `detectPii(text: string, customRules?: Array<{ name: string, pattern: string, severity?: string }>): Array<{ type: string, name: string, match: string, index: number, severity: 'critical' | 'warning', reason: string }>`  
  Scans text against built-in patterns (payment cards, SSN, IBAN, email, phone, JWTs, private keys) and validated custom regexes.
- `maskPii(text: string, detectedItems: Array<{ type: string, name: string, match: string }>): string`  
  Redacts sensitive values with structured masking (e.g. `****-****-****-1234`, `[REDACTED_API_KEY]`).
- `luhnCheck(numStr: string): boolean`  
  Validates payment card numbers via ISO/IEC 7812 Luhn Mod-10 algorithm.
- `isValidSSN(ssnStr: string): boolean`  
  Validates US Social Security Numbers, checking against invalid area codes (`000`, `666`, `900–999`) and group codes.
- `isValidIBAN(ibanStr: string): boolean`  
  Validates International Bank Account Numbers via ISO 7064 Mod-97 checksum.
- `isSafeRegexPattern(patternStr: string): boolean`  
  Static analyzer rejecting catastrophic backtracking patterns, excessive lengths (> 250 chars), and nested quantifiers.
- `getCompiledCustomRegex(patternStr: string): RegExp | null`  
  Retrieves or compiles validated regex from the LRU cache (capped at 100 entries).
- `clearCustomRegexCache(): void`  
  Flushes the custom regex cache.
- `getCustomRegexCacheSize(): number`  
  Returns the current number of cached compiled patterns.

---

### 2.5 `src/core/scam-analyzer.js` (`OSNScamAnalyzer`)

Detects financial fraud, social engineering lures, wallet drainers, and quishing lures using an Aho-Corasick multi-pattern trie automaton.

#### Exports & Factories
- Default Instance: `OSNScamAnalyzer`
- Factory Method: `OSNScamAnalyzer.create(userConfig?: Object): Object`

#### API Methods
- `detectScamContent(text: string): { flagged: boolean, id?: string, category?: string, reason?: string, severity?: 'critical' | 'warning', matchedKeyword?: string, containsZeroWidth?: boolean, zeroWidthObfuscation?: boolean, allMatches?: Object[] }`  
  Sanitizes zero-width characters, runs Aho-Corasick linear keyword search, evaluates secondary regex patterns, and surfaces highest-severity threat.
- `buildAhoCorasick(rules: Object[]): Object`  
  Constructs the root trie with failure links (BFS) and output dictionaries from rule keywords.
- `searchAhoCorasick(text: string, trieRoot: Object): Map<string, { rule: Object, matchedTerm: string }>`  
  Performs simultaneous multi-keyword matching across text in linear time `O(n + m)`.

---

## 3. Background Coordinator (`src/background/service-worker.js`)

### 3.1 IPC Message Protocol

The background worker enforces origin verification (`sender.id === chrome.runtime.id`) on all incoming messages.

| Action (`message.action`) | Sender Context | Parameters | Response Payload | Behavior / Effect |
|---|---|---|---|---|
| `reportThreats` | Content Script | `{ threats: Object[], statsUpdate?: Object }` | `{ status: "success" }` | Updates tab record in `storage.session`, adjusts action badge text and color, serializes global stats, appends to audit log. |
| `getThreatsForTab` | Popup / UI | `{ tabId: number }` | `{ url: string, threats: Object[] }` | Retrieves threats recorded for the specified tab from `storage.session`. |
| `checkUrlSafety` | Options / Context Menu | `{ url: string }` | `{ safe: boolean, reason: string, ... }` | Runs `OSNUrlAnalyzer.analyzeUrlSafety()` against effective whitelist. |
| `getManagedPolicy` | Options / Popup | none | `{ managed: Object }` | Returns enterprise policy settings from `chrome.storage.managed`. |
| `incrementPiiBlocked` | Content Script | none | `{ status: "success" }` | Increments `piiBlockedCount` in global stats queue. |
| `rescanTab` | Popup Dashboard | `{ tabId: number }` | `{ status: "success", result?: any }` | Dispatches `triggerRescan` message to target tab content script. |

---

### 3.2 Tab Lifecycle & Storage Reconciliation

- `reconcileOrphanedTabs()`: Queries active tabs via `chrome.tabs.query({}, ...)` and deletes all `tab_<id>` keys from `storage.session` corresponding to closed tabs.
- `throttledReconcileOrphanedTabs()`: Throttles reconciliation to once every 3 minutes (`RECONCILE_THROTTLE_MS = 180000`) on `chrome.tabs.onActivated`.
- `chrome.tabs.onUpdated`: Clears tab storage and resets badge text to `""` when `changeInfo.status === "loading"`.
- `chrome.tabs.onRemoved`: Clears tab session key immediately upon tab closure.

---

### 3.3 Storage Self-Healing Schema

`sanitizeAndRepairStorage(data)` validates and heals `chrome.storage.local`:
- `shields`: Validates `{ pii: boolean, url: boolean, content: boolean, security: boolean }`.
- `stats`: Validates `{ linksScanned: int >= 0, piiBlockedCount: int >= 0, threatsDetected: int >= 0, sitesProtected: int >= 0 }`.
- `whitelistedDomains`: Enforces array of trimmed strings (`length <= 100`).
- `customPiiPatterns`: Enforces array of valid `{ name, pattern }` objects.
- `auditLog`: Caps entries to `MAX_AUDIT_LOG_ENTRIES = 50`.
- `reviewState`: Enforces `{ dismissed: boolean, completed: boolean, lastPromptedAt: number }`.

---

## 4. Content Script Scanner (`src/content/scanner.js`)

### 4.1 Frame Budget Scheduler & Batching Limits

To maintain 60 FPS scrolling on heavy feeds, DOM scanning runs cooperatively:
- `BATCH_TIME_BUDGET_MS = 10` (10ms execution limit per frame tick).
- `MAX_CONTAINERS_PER_BATCH = 30` containers per batch.
- `MAX_LINKS_PER_BATCH = 50` links per batch.
- Hard tab session caps: `MAX_PAGE_LINKS_LIMIT = 500`, `MAX_PAGE_CONTAINERS_LIMIT = 200`, `MAX_PAGE_IMAGES_LIMIT = 50`.
- Utilizes `requestIdleCallback` with fallback to `setTimeout(..., 16)`.

---

### 4.2 Composer PII Interception

- Listens for `input` and `paste` events across `textarea`, `input[type="text"]`, `input[type="search"]`, and `[contenteditable="true"]`.
- Processes input directly via debounced frame-budgeted tasks (300ms for typing, 50ms for paste).
- Evaluates `detectPii()`; if sensitive data is detected, renders a floating warning banner adjacent to the composer displaying the detected PII type, severity badge, and a one-click "Mask & Redact" button.

---

### 4.3 Quishing (QR Phishing) Visual Engine

- Checks `"BarcodeDetector" in window`.
- Selects `<img>`, `<svg>`, and `<canvas>` elements within social post containers.
- Decodes QR code targets via `qrBarcodeDetector.detect(imgElement)` without network egress.
- Passes decoded raw string into `OSNUrlAnalyzer.analyzeUrlSafety()`; if unsafe, flags as critical Quishing threat and attaches warning badge.

---

## 5. User Interface Controllers (`src/ui/`)

### 5.1 Popup Dashboard (`src/ui/popup/popup.js`)

- Queries active tab via `chrome.tabs.query({ active: true, currentWindow: true }, ...)`.
- Fetches tab threats via `getThreatsForTab` and renders dynamic circular gauge:
  - Base score: 100
  - Deduction: -25 per critical threat, -10 per warning threat (clamped to `[0, 100]`).
  - Score >= 80: Green (`#10b981`), 50–79: Amber (`#f59e0b`), < 50: Red (`#ef4444`).
- Evaluates `isReviewPromptEligible(data, currentTime)`:
  - Usage threshold: `>= 5` threats detected OR `>= 50` links scanned.
  - Install age: `>= 3` days.
  - Frequency cooldown: 14 days if deferred.

---

### 5.2 Options Configuration & Sandbox (`src/ui/options/options.js`)

- Domain Whitelist CRUD: Validates domain strings, supports wildcard prefixes (`*.domain.com`), prevents duplicates.
- Custom PII Manager: Validates regex via `OSNPiiAnalyzer.isSafeRegexPattern()` before persisting.
- Enterprise Policy Integration: Disables editing of managed domains and mandatory rules pushed via `storage.managed`.
- Live PII Sandbox: Interactive text area providing real-time PII detection feedback and redaction preview.
- Settings Backup & Portability: Exports JSON configuration; imports and sanitizes external backups with prototype-pollution guards.
- Security Audit Log Viewer: Displays rolling threat events; supports JSON export and log clearance.
