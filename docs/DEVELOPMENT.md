# OSN Guard — Developer Setup & Contributor Guide

**Document ID:** OSN-DEV-GUIDE-001  
**Version:** 1.3.0  
**Status:** Active  

This guide provides setup instructions, testing workflows, benchmark commands, packaging procedures, and unpacked extension debugging guidelines for OSN Guard across Chromium, Firefox, and Safari.

---

## 1. Environment Prerequisites

- **Node.js:** Version `18.x`, `20.x`, or `22.x` (LTS recommended).
- **Package Manager:** `npm` (bundled with Node.js).
- **Browsers (for manual & E2E verification):**
  - Google Chrome (or Chromium / Brave / MS Edge)
  - Mozilla Firefox (109+)
  - Apple Safari (15.4+ on macOS)
- **Zero Runtime Dependencies:**
  - OSN Guard does not use third-party runtime npm packages. All source code in `src/` relies exclusively on native modern ECMAScript and browser Web APIs.

Verify your environment:
```bash
node -v   # Must be >= 18.0.0
npm -v
```

---

## 2. Repository Layout

```text
D:\Practice\osn-safety-scanner\
├── .github/workflows/    # CI matrix automation (Node 18/20/22 on Ubuntu & Windows)
├── dist/                 # Distribution ZIP packages and target-specific manifests
├── docs/                 # Single source of truth documentation repository
├── scripts/              # Standalone Node.js automation (packager, benchmarks)
├── src/                  # Production extension source code
│   ├── assets/icons/     # Extension icons (16, 48, 128 px PNG + SVG)
│   ├── background/       # Service worker background coordinator
│   ├── content/          # Content script, CSS overlays, tooltips
│   ├── core/             # Shared detection engines, compat shim, threat config
│   └── ui/               # Popup dashboard and Options management pages
├── tests/                # Node.js automated test suites (unit + CDP E2E)
├── managed_schema.json   # Managed storage policy schema for Chrome Enterprise
├── manifest.json         # Base Chromium Manifest V3 configuration
└── package.json          # Node script commands (zero external runtime dependencies)
```

---

## 3. Verification & Testing Commands

All verification commands execute through native Node.js built-ins without bundlers or transpilers.

### 3.1 Static Syntax & Import Check
Validates that all production source files, scripts, and test files are syntactically valid JavaScript:
```bash
npm run check
```

### 3.2 Unit Test Suite
Executes all 241 unit tests across 55 test suites using Node's native test runner (`node --test`):
```bash
npm test
```
*Run tests in watch mode during development:*
```bash
npm run test:watch
```

### 3.3 End-to-End (E2E) Headless Browser Tests
Launches a headless Chromium instance, loads the unpacked extension from `src/`, and verifies service worker activation, popup rendering, content script injection, and Quishing detection via the Chrome DevTools Protocol (CDP):
```bash
npm run test:e2e
```
*(Requires Chromium or Google Chrome in system PATH).*

### 3.4 Performance Benchmarks
Executes high-iteration throughput benchmarks across all core engines:
```bash
npm run bench
```
**Performance Budgets:**
- URL Safety Analyzer: `>= 80,000 ops/sec` (Achieved: ~116,000 ops/s)
- PII Detection Engine: `>= 80,000 ops/sec` (Achieved: ~137,000 ops/s)
- PII Masking & Redaction: `>= 80,000 ops/sec` (Achieved: ~147,000 ops/s)
- Scam Classifier (Aho-Corasick): `>= 100,000 ops/sec` (Achieved: ~217,000 ops/s)

---

## 4. Multi-Target Packaging

Build distribution-ready archives using the built-in zero-dependency packager (`scripts/pack.js`):

```bash
# Package all targets (Chrome, Firefox, Safari)
npm run pack:all

# Package individual targets
npm run pack:chrome
npm run pack:firefox
npm run pack:safari
```

Packaging outputs are stored in `dist/`:
- `dist/osn-guard-safety-privacy-shield-v1.3.0.zip` (Chrome Web Store ready)
- `dist/osn-guard-safety-privacy-shield-firefox-v1.3.0.zip` (Firefox AMO ready)
- `dist/osn-guard-safety-privacy-shield-safari-v1.3.0.zip` (Xcode import ready)
- `dist/manifest-chrome.json`, `dist/manifest-firefox.json`, `dist/manifest-safari.json`

---

## 5. Loading the Extension Locally for Testing

### 5.1 Google Chrome / Chromium / Edge / Brave

1. Open your browser and navigate to `chrome://extensions` (or `edge://extensions`, `brave://extensions`).
2. Toggle **Developer mode** on in the upper-right corner.
3. Click **Load unpacked**.
4. Select the repository root directory: `D:\Practice\osn-safety-scanner`.
5. The extension will appear with its shield icon in the toolbar.
6. Open `test-page.html` in the browser to interactively test link scanning, PII interception, and scam banners.

### 5.2 Mozilla Firefox

1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select `dist/manifest-firefox.json` (generate first via `npm run pack:firefox`).
4. Alternatively, use Mozilla's `web-ext` runner if installed globally:
   ```bash
   npx web-ext run --source-dir .
   ```
5. Inspect the background event page logs by clicking **Inspect** on the loaded add-on.

### 5.3 Apple Safari (macOS)

1. Enable the Develop menu in Safari: **Safari > Settings > Advanced > Show features for web developers**.
2. Under the **Develop** menu, check **Allow Unsigned Extensions**.
3. Convert the extension for Xcode if needed:
   ```bash
   xcrun safari-web-extension-converter D:\Practice\osn-safety-scanner
   ```
4. Build and run the project in Xcode to install the extension into Safari.

---

## 6. Coding Standards & Invariants

When contributing changes to OSN Guard, you must observe these strict operational rules:

1. **Zero New Runtime Dependencies:** Only use modern native JavaScript and standard Web APIs.
2. **Zero Network Egress:** Never add network fetch calls or telemetry endpoints. Maintain `connect-src 'none'`.
3. **Least Privilege:** Do not request additional permissions in `manifest.json` beyond `{ storage, activeTab, contextMenus }`.
4. **Zero Drift:** Whenever code is modified, update corresponding documentation in `docs/` in the same commit batch.
5. **Continuous Verification:** Run `npm run check`, `npm test`, and `npm run bench` before committing.
