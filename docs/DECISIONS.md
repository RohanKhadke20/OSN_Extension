# OSN Guard — Architecture Decision Records (ADRs)

**Repository:** `RohanKhadke20/OSN_Extension` (`D:\Practice\osn-safety-scanner`)  
**Maintained By:** Principal Software Architect & Core Engineering Team  
**Status:** Canonical & Active Architectural Log  

This document logs all principal architectural decisions governing the design, implementation, packaging, and security constraints of OSN Guard. Each record follows the structured Architecture Decision Record (ADR) standard: **Context**, **Decision**, **Consequences**, and **Status**.

---

## Index of Architectural Decisions

- [ADR-001: Zero-Dependency & Zero-Network-Egress Invariant (`connect-src 'none'`)](#adr-001-zero-dependency--zero-network-egress-invariant-connect-src-none)
- [ADR-002: Dual-Runtime Universal Module Definition (UMD) Architecture](#adr-002-dual-runtime-universal-module-definition-umd-architecture)
- [ADR-003: Cross-Browser Compatibility Shim (`OSNCompat`) & Dual Callback/Promise Bridge](#adr-003-cross-browser-compatibility-shim-osncompat--dual-callbackpromise-bridge)
- [ADR-004: Data-Driven Threat Configuration Engine (`DEFAULT_THREAT_CONFIG` & Factory Patterns)](#adr-004-data-driven-threat-configuration-engine-default_threat_config--factory-patterns)
- [ADR-005: Conventional `src/` Codebase Reorganization](#adr-005-conventional-src-codebase-reorganization)
- [ADR-006: Multi-Target Zero-Bundler Packaging Pipeline (`scripts/pack.js`)](#adr-006-multi-target-zero-bundler-packaging-pipeline-scriptspackjs)

---

### ADR-001: Zero-Dependency & Zero-Network-Egress Invariant (`connect-src 'none'`)

#### Status
**Accepted & Enforced** (Immutable)

#### Context
Browser extensions inspecting personal data, social media feeds, and webpage links represent high-value attack targets. Supply-chain attacks via compromised npm dependencies (e.g., event-stream, ua-parser-js) and unauthorized data exfiltration via background telemetry or tracking pixels represent existential risks to user privacy. Many privacy extensions paradoxically send visited URLs or threat reports back to cloud-hosted telemetry services, exposing user browsing habits to external servers.

#### Decision
1. OSN Guard shall have **zero third-party runtime npm dependencies**. The extension core, background worker, content scripts, and options UI must be authored entirely using standard ECMAScript and native Web APIs.
2. The Content Security Policy (CSP) shall strictly mandate `connect-src 'none'`. Under no circumstances shall network requests (`fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, WebRTC) be permitted from any extension execution context.
3. All threat detection, URL analysis, PII scanning, and scam classification must run **100% locally on the client device**.

#### Consequences
- **Positive:**
  - Complete elimination of supply-chain injection vulnerabilities in production distribution packages.
  - Provable, cryptographic privacy guarantee: zero chance of user data leakage over the network.
  - Frictionless Web Store and AMO review approval due to least-privilege CSP and absence of obfuscated third-party bundles.
- **Negative / Constraints:**
  - Threat signatures and rules must be pre-bundled or configured locally by the user/enterprise administrator via `storage.managed`, rather than updated on-the-fly via remote APIs.
  - Algorithms must be highly optimized in pure JavaScript to achieve sub-millisecond execution without relying on native C++ npm bindings.

---

### ADR-002: Dual-Runtime Universal Module Definition (UMD) Architecture

#### Status
**Accepted & Active**

#### Context
OSN Guard's detection engines (`url-analyzer.js`, `pii-analyzer.js`, `scam-analyzer.js`, `threat-config.js`, `compat.js`) must operate seamlessly in two radically different environments:
1. **Browser Runtime (Client):** Loaded sequentially via `<script>` tags in popup and options HTML pages, via `importScripts()` in the Chromium background service worker, or via `content_scripts` manifest declarations.
2. **Node.js Automated Test Runner (CI/CD):** Imported via CommonJS `require()` by `node --test` suites (`tests/*.test.js`) without requiring Babel, Webpack, Rollup, or Vite transpilation.

#### Decision
Implement the Universal Module Definition (UMD) pattern with a closure wrapper across all shared modules in `src/core/`:
```javascript
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.OSNModuleName = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  // Engine implementation
  return { ... };
});
```

#### Consequences
- **Positive:**
  - Zero build step required to execute unit test suites directly with standard Node.js (`node --test`).
  - Browser scripts attach directly to `globalThis` (`self`) without pollution or bundler overhead.
  - Rapid test execution (241 unit tests run in < 2 seconds).
- **Negative / Constraints:**
  - Requires strict discipline to avoid ES6 module syntax (`import` / `export`) in core modules until browser extensions and Node.js test runners uniformly standardize unbundled native ESM support across all targets.

---

### ADR-003: Cross-Browser Compatibility Shim (`OSNCompat`) & Dual Callback/Promise Bridge

#### Status
**Accepted & Active**

#### Context
Chromium, Mozilla Firefox, and Apple Safari exhibit fundamental discrepancies in their WebExtension implementations:
- Chromium adheres to the `chrome.*` namespace using callback-based APIs (with partial Promise support in modern versions).
- Mozilla Firefox adheres to the W3C `browser.*` namespace and enforces native Promise-returning functions.
- Safari supports both namespaces with version-dependent limitations.
- Firefox and older Safari builds lack native `chrome.storage.session`, which is critical for ephemeral tab-isolated threat state persistence across service worker dormancy cycles.

#### Decision
Create an isolated compatibility layer at `src/core/compat.js` exporting the `OSNCompat` module:
1. **Namespace Unification:** At parse time, perform bidirectional aliasing between `globalThis.chrome` and `globalThis.browser`.
2. **Dual Callback/Promise Bridge (`promisifyOrCallback`):** Wrap asynchronous API calls so they can be consumed interchangeably with callbacks `(result) => { ... }` or Promises `await apiCall()`.
3. **Transparent Storage Fallbacks:**
   - Implement `createSessionStorageFallback` using prefixed `storage.local` keys (`__osn_session_tab_*`) when native `storage.session` is missing.
   - Implement `createManagedStorageFallback` returning safe empty schema stubs when enterprise policy storage is unavailable.
4. **Action & Menu Normalization:** Map `chrome.action` ↔ `browser.browserAction` and `chrome.contextMenus` ↔ `browser.menus`.
5. **URL Scheme Normalization:** Provide `isInternalUrl(url)` recognizing `chrome://`, `chrome-extension://`, `moz-extension://`, `safari-web-extension://`, `about:`, and `edge://`.

#### Consequences
- **Positive:**
  - Application code in `background`, `content`, `popup`, and `options` is written against a unified API without conditional branching per browser.
  - Multi-browser packaging functions from a single unified codebase.
- **Negative / Constraints:**
  - `compat.js` must always be evaluated as the first script in every context (manifest `content_scripts`, `importScripts`, HTML `<script>` tags).

---

### ADR-004: Data-Driven Threat Configuration Engine (`DEFAULT_THREAT_CONFIG` & Factory Patterns)

#### Status
**Accepted & Active**

#### Context
Prior to v1.3.0, threat rules, regex patterns, scam keywords, and detection thresholds were hardcoded as private constants inside `url-analyzer.js`, `pii-analyzer.js`, and `scam-analyzer.js`. This tightly coupled detection logic to algorithmic code, preventing runtime customization, enterprise policy injection, and isolated unit testing of novel threat categories.

#### Decision
1. Establish `src/core/threat-config.js` as the canonical source of truth, exporting `DEFAULT_THREAT_CONFIG` deeply frozen with `deepFreeze()`.
2. Decouple each analyzer into a factory pattern:
   - `OSNUrlAnalyzer(userConfig)` / `OSNUrlAnalyzer.create(userConfig)`
   - `OSNPiiAnalyzer(userConfig)` / `OSNPiiAnalyzer.create(userConfig)`
   - `OSNScamAnalyzer(userConfig)` / `OSNScamAnalyzer.create(userConfig)`
3. When invoked without arguments, factory instances fall back seamlessly to `DEFAULT_THREAT_CONFIG`, preserving 100% backwards-compatible facade behavior.
4. Enforce strict static ReDoS safety validation (`isSafeRegexPattern()`) on any user-provided or enterprise-injected regular expression.

#### Consequences
- **Positive:**
  - Threat rules and thresholds can be configured dynamically without modifying core engine logic.
  - Custom rules can be injected via Enterprise MDM (`managed_schema.json`) or imported via JSON backup.
  - Benchmarks and test suites can instantiate clean, isolated engine instances with custom rule matrices.
- **Negative / Constraints:**
  - Analyzers must perform input validation and array-to-Set/RegExp conversions during instantiation.

---

### ADR-005: Conventional `src/` Codebase Reorganization

#### Status
**Accepted & Active**

#### Context
Early iterations of OSN Guard maintained a flat root directory containing `background.js`, `content.js`, `content.css`, `core/`, `popup/`, and `options/`. As the project expanded to support multi-browser packaging, automated benchmarking, end-to-end testing, and enterprise schemas, the root directory became cluttered, impeding maintainability, static analysis, and packaging isolation.

#### Decision
Reorganize the extension codebase into a clean, conventional `src/` modular layout:
```text
src/
├── assets/icons/         # Extension toolbar and store icons
├── background/           # Service worker background coordinator
├── content/              # Content scripts, CSS overlays, tooltips
├── core/                 # Shared detection engines, compat shim, threat config
└── ui/
    ├── options/          # Options page markup, styles, and controller
    └── popup/            # Toolbar popup markup, styles, and gauge controller
```

#### Consequences
- **Positive:**
  - Clear separation of concerns between extension source code (`src/`), build scripts (`scripts/`), distribution packages (`dist/`), automated tests (`tests/`), and documentation (`docs/`).
  - Simplifies packaging filters in `scripts/pack.js` (`INCLUDED_PATTERNS = ["manifest.json", "managed_schema.json", "README.md", "src"]`).
  - Standardizes file path conventions across development, testing, and distribution.
- **Negative / Constraints:**
  - All relative paths in `manifest.json`, HTML `<script>` tags, and `importScripts()` had to be updated atomically across the entire repository.

---

### ADR-006: Multi-Target Zero-Bundler Packaging Pipeline (`scripts/pack.js`)

#### Status
**Accepted & Active**

#### Context
Distributing WebExtensions across the Chrome Web Store, Mozilla Add-ons (AMO), and Apple App Store / Safari typically relies on complex build toolchains (Webpack, Vite, Rollup, web-ext) introducing hundreds of megabytes of `node_modules` dependencies and non-deterministic bundle outputs. This violates OSN Guard's zero-dependency invariant and complicates independent security auditing.

#### Decision
Develop a standalone packaging script `scripts/pack.js` using Node.js standard built-ins (`node:fs`, `node:path`, `node:zlib`):
1. **Pure Built-in Zip Generation:** Implement standard PKZIP archive encoding using `zlib.deflateRawSync` and standard MS-DOS timestamping.
2. **Target-Specific Manifest Transformation:**
   - **Chrome:** Uses root `manifest.json` directly.
   - **Firefox:** Transforms `background.service_worker` to `background.scripts` array (ordered: `compat.js` → `threat-config.js` → `url-analyzer.js` → `pii-analyzer.js` → `scam-analyzer.js` → `service-worker.js`), injects `browser_specific_settings.gecko.id`, and sets `strict_min_version: "109.0"`.
   - **Safari:** Injects `browser_specific_settings.safari.strict_min_version: "15.4"`.
3. **Deterministic Output:** Sort file entries alphabetically and normalize path separators to forward slashes.

#### Consequences
- **Positive:**
  - Produces byte-reproducible, standalone `.zip` packages for Chrome, Firefox, and Safari in `dist/` with a single command (`npm run pack:all`).
  - Zero external npm packages required for distribution packaging.
  - Packaging completes in < 200 milliseconds.
- **Negative / Constraints:**
  - Advanced manifest variations must be explicitly handled in `scripts/pack.js` transformation logic.
