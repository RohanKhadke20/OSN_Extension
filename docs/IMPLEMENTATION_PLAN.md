# OSN Guard - Master Implementation Plan & Production Readiness Roadmap

**Document ID:** OSN-PLAN-001  
**Target Version:** `1.3.0`  
**Status:** READY_FOR_EXECUTION  
**Branch:** `main`  

---

## Task Matrix Overview

| Task ID | Phase | Priority | Title | Affected Modules | Dependencies | Status | Validation Method |
| ------- | ----- | -------- | ----- | ---------------- | ------------ | ------ | ----------------- |
| **TSK-01** | Phase 1 | **P1 (Critical)** | Create production extension icons & register in manifest | `manifest.json`, `assets/icons/` | None | **COMPLETED** | `npm run check`, icon validation |
| **TSK-02** | Phase 1 | **P1 (Critical)** | Add comprehensive repository `.gitignore` | `.gitignore` | None | **COMPLETED** | `git status` check |
| **TSK-03** | Phase 1 | **P2 (Important)** | Declare explicit Content Security Policy in manifest | `manifest.json` | None | **COMPLETED** | `npm run check`, CSP verified |
| **TSK-04** | Phase 2 | **P2 (Important)** | Add custom regex compilation caching in PII engine | `core/pii-analyzer.js`, `tests/pii-detector.test.js` | None | **PENDING** | `npm test` |
| **TSK-05** | Phase 2 | **P2 (Important)** | Implement node batch capping for generic web DOMs | `content.js` | None | **PENDING** | `npm run check`, test sandbox load |
| **TSK-06** | Phase 3 | **P2 (Important)** | Build zero-dependency distribution packaging script | `scripts/pack.js`, `package.json` | TSK-01 | **PENDING** | `npm run pack` generates valid `.zip` |
| **TSK-07** | Phase 4 | **P3 (Improvement)** | Add automated headless browser E2E test harness | `tests/e2e/`, `package.json` | TSK-06 | **PENDING** | `npm run test:e2e` |

---

## Detailed Task Specifications

### TSK-01: Create Production Extension Icons
- **Objective:** Create crisp SVG and PNG icon assets in required resolutions (`16x16`, `48x48`, `128x128`) featuring the OSN Guard shield motif, and register them in `manifest.json` under both `"icons"` and `"action.default_icon"`.
- **Files Affected:**
  - `assets/icons/icon-16.png`
  - `assets/icons/icon-48.png`
  - `assets/icons/icon-128.png`
  - `assets/icons/icon.svg`
  - `manifest.json`
- **Acceptance Criteria:**
  - `manifest.json` contains valid `"icons"` and `"action.default_icon"` mappings.
  - Browser displays custom shield icon in extensions bar and developer management page.
- **Validation:** `npm run check` passes; extension loads unpacked without missing icon warnings.

---

### TSK-02: Add Comprehensive `.gitignore`
- **Objective:** Ensure no development artifacts, operating system metadata, or distribution archives can be accidentally committed to Git.
- **Files Affected:**
  - `.gitignore`
- **Acceptance Criteria:**
  - Excludes `node_modules/`, `*.zip`, `.DS_Store`, `Thumbs.db`, `.vscode/`, `.idea/`, and test coverage directories.
- **Validation:** `git status` confirms untracked temporary files are ignored.

---

### TSK-03: Declare Explicit Content Security Policy
- **Objective:** Explicitly configure extension page CSP in `manifest.json` to lock down execution and pass Chrome Web Store automated security reviews.
- **Files Affected:**
  - `manifest.json`
- **Acceptance Criteria:**
  - Includes `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self';" }`.
- **Validation:** `npm run check` passes; extension loads in Chrome without CSP errors.

---

### TSK-04: Custom Regex Compilation Caching
- **Objective:** Avoid recreating `new RegExp(cp.pattern, "g")` on every keystroke in `detectPii()` by implementing a Map cache keyed by `pattern + "_" + flags`.
- **Files Affected:**
  - `core/pii-analyzer.js`
  - `tests/pii-detector.test.js`
- **Acceptance Criteria:**
  - Repeated calls with the same custom regex reuse compiled `RegExp` object with `lastIndex = 0`.
  - All existing 63 unit tests continue to pass.
- **Validation:** `npm test` passes.

---

### TSK-05: Node Batch Capping on Generic DOMs
- **Objective:** Cap the maximum number of text containers scanned per mutation cycle to 50 nodes, queueing remainder to avoid frame drops on massive websites.
- **Files Affected:**
  - `content.js`
- **Acceptance Criteria:**
  - Fast typing and rapid scrolling maintain 60 FPS without layout thrashing.
  - Scanning stops cleanly when tab navigates.
- **Validation:** `npm run check` passes.

---

### TSK-06: Zero-Dependency Distribution Packager
- **Objective:** Add `scripts/pack.js` using Node.js built-in compression to generate `dist/osn-guard-v1.2.0.zip` ready for Chrome Web Store upload.
- **Files Affected:**
  - `scripts/pack.js`
  - `package.json`
- **Acceptance Criteria:**
  - `npm run pack` generates a valid `.zip` containing only production files (excluding `tests/`, `.github/`, `docs/`, `test-page.html`).
- **Validation:** Inspect `.zip` archive structure and verify it loads in Chrome.
