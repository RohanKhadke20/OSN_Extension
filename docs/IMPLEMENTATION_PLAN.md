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
| **TSK-04** | Phase 2 | **P2 (Important)** | Add custom regex compilation caching in PII engine | `core/pii-analyzer.js`, `tests/pii-detector.test.js` | None | **COMPLETED** | `npm test` |
| **TSK-05** | Phase 2 | **P2 (Important)** | Implement node batch capping for generic web DOMs | `content.js` | None | **COMPLETED** | `npm run check`, test sandbox load |
| **TSK-06** | Phase 3 | **P2 (Important)** | Build zero-dependency distribution packaging script | `scripts/pack.js`, `package.json` | TSK-01 | **COMPLETED** | `npm run pack` generates valid `.zip` |
| **TSK-07** | Phase 4 | **P3 (Improvement)** | Add automated headless browser E2E test harness | `tests/e2e/`, `package.json` | TSK-06 | **COMPLETED** | `npm run test:e2e` |
| **TSK-08** | Phase 5 | **P2 (Important)** | Obfuscated IP notation & mixed-script IDN detection | `core/url-analyzer.js`, `tests/url-safety.test.js` | None | **COMPLETED** | `npm test` |
| **TSK-09** | Phase 5 | **P2 (Important)** | URL shortener identification & destination obscurity heuristic | `core/url-analyzer.js`, `tests/url-safety.test.js` | None | **COMPLETED** | `npm test` |
| **TSK-10** | Phase 5 | **P2 (Important)** | Modern social engineering & scam detector expansion | `core/scam-analyzer.js`, `tests/scam-detector.test.js` | None | **COMPLETED** | `npm test` |
| **TSK-11** | Phase 5 | **P3 (Improvement)** | CSS isolation hardening and box-sizing reset protection | `content.css` | None | **COMPLETED** | `npm run check`, visual inspection |
| **TSK-12** | Phase 6 | **P2 (Important)** | Context menu quick analysis engine for links and text | `manifest.json`, `background.js`, `content.js` | TSK-08 | **COMPLETED** | `npm run check`, E2E test |
| **TSK-13** | Phase 6 | **P2 (Important)** | Interactive PII Redactor & Sanitizer preview sandbox | `options/options.html`, `options/options.js` | TSK-04 | **COMPLETED** | `npm run check`, `npm test` |
| **TSK-14** | Phase 6 | **P3 (Improvement)** | Tab Threat Notification & Toast Alert Dispatcher | `content.js`, `content.css` | TSK-11 | **COMPLETED** | `npm run check`, E2E test |
| **TSK-15** | Phase 7 | **P2 (Important)** | Form Action & Insecure Submission Inspector | `content.js`, `core/url-analyzer.js` | None | **COMPLETED** | `npm run check`, E2E test |
| **TSK-16** | Phase 7 | **P2 (Important)** | Live Threat Counter Badge Reactive Tab-Switch Sync | `background.js` | None | **COMPLETED** | `npm run check`, E2E test |
| **TSK-17** | Phase 7 | **P3 (Improvement)** | Zero-dependency core performance benchmark suite | `scripts/bench.js`, `package.json` | None | **COMPLETED** | `npm run bench` |
| **TSK-18** | Phase 8 | **P2 (Important)** | Suspicious executable & script download link heuristic | `core/url-analyzer.js`, `tests/url-safety.test.js` | None | **COMPLETED** | `npm test` |
| **TSK-19** | Phase 8 | **P2 (Important)** | Web3 / Crypto drainer approval signature detection | `core/scam-analyzer.js`, `tests/scam-detector.test.js` | None | **COMPLETED** | `npm test` |
| **TSK-20** | Phase 8 | **P3 (Improvement)** | Accessible keyboard interaction for badge tooltips | `content.js`, `content.css` | TSK-11 | **COMPLETED** | `npm run check`, E2E test |
| **TSK-21** | Phase 9 | **P1 (Critical)** | GitHub Actions CI/CD validation & packaging pipeline | `.github/workflows/ci.yml` | TSK-06, TSK-17 | **PENDING** | Workflow execution |
| **TSK-22** | Phase 9 | **P2 (Important)** | Security audit event log buffer & telemetry exporter | `background.js`, `options/options.html`, `options/options.js` | None | **PENDING** | `npm run check`, E2E test |
| **TSK-23** | Phase 9 | **P2 (Important)** | Developer intranet & localhost port whitelist expansion | `core/url-analyzer.js`, `tests/url-safety.test.js` | None | **PENDING** | `npm test` |

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

---

### TSK-07: Automated Headless Browser E2E Test Suite
- **Objective:** Build zero-dependency Chrome DevTools Protocol (CDP) test harness (`tests/e2e/cdp-client.js`, `tests/e2e/extension-lifecycle.test.js`) verifying service worker registration, options page, popup UI, and content script injection.
- **Files Affected:**
  - `tests/e2e/cdp-client.js`
  - `tests/e2e/extension-lifecycle.test.js`
  - `package.json`
  - `.github/workflows/ci.yml`
- **Acceptance Criteria:**
  - Runs headless browser without third-party npm dependencies.
  - Successfully tests options page, popup page, and content script injection on interactive HTML page.
- **Validation:** `npm run test:e2e` passes.

---

### TSK-08: Obfuscated IP Notation & Mixed-Script IDN Detection
- **Objective:** Extend `core/url-analyzer.js` to detect dotted-octal (`0177.0.0.1`), dotted-hex (`0x7f.0.0.1`), mixed-base IPv4 representations, and mixed-script Unicode homoglyphs.
- **Files Affected:**
  - `core/url-analyzer.js`
  - `tests/url-safety.test.js`
- **Acceptance Criteria:**
  - Obfuscated octal/hex IP hostnames are flagged as raw IP threats.
  - Mixed-script hostnames (e.g. Cyrillic/Greek characters interspersed with Latin) are flagged as critical homograph threats.
- **Validation:** `npm test` passes.

---

### TSK-09: URL Shortener Identification & Obscurity Heuristic
- **Objective:** Maintain a curated registry of major URL shortening services (`SHORTENER_DOMAINS`) in `core/url-analyzer.js` and flag obfuscated links with informative safety warnings.
- **Files Affected:**
  - `core/url-analyzer.js`
  - `tests/url-safety.test.js`
- **Acceptance Criteria:**
  - Detects shortened links (`bit.ly`, `tinyurl.com`, `is.gd`, etc.) and returns structured warning heuristic.
- **Validation:** `npm test` passes.

---

### TSK-10: Modern Social Engineering & Scam Expansion
- **Objective:** Expand `core/scam-analyzer.js` to recognize emerging modern threats: Pig-Butchering romance grooming lures, Fake Invoice / Auto-Renewal refund schemes, and Family Emergency deepfake/impersonation scams.
- **Files Affected:**
  - `core/scam-analyzer.js`
  - `tests/scam-detector.test.js`
- **Acceptance Criteria:**
  - Successfully flags romance scam redirection, fake Geek Squad/McAfee renewal invoices, and emergency cash requests.
- **Validation:** `npm test` passes.

---

### TSK-11: Content CSS Isolation & Box-Sizing Hardening
- **Objective:** Fortify `content.css` against host website stylesheet contamination by applying explicit `box-sizing: border-box !important;`, `letter-spacing: normal !important;`, and `text-transform: none !important;` to OSN Guard overlays.
- **Files Affected:**
  - `content.css`
- **Acceptance Criteria:**
  - Injected badges, tooltips, and alert banners maintain consistent dimensions and layout regardless of host page CSS resets.
- **Validation:** `npm run check`, E2E test verification.

---

### TSK-12: Context Menu Quick Analysis Engine
- **Objective:** Add Chrome Context Menu integrations (`"contextMenus"` permission) allowing users to right-click any hyperlink ("Scan link with OSN Guard") or highlighted text ("Analyze text for scams/PII"), triggering immediate evaluation and visual feedback.
- **Files Affected:**
  - `manifest.json`
  - `background.js`
  - `content.js`
  - `tests/e2e/extension-lifecycle.test.js`
- **Acceptance Criteria:**
  - Context menu items are registered upon installation/startup.
  - Clicking a menu item evaluates the target link or text and dispatches an immediate toast/modal alert in the active tab.
- **Validation:** `npm run check`, `npm run test:e2e`.

---

### TSK-13: Interactive PII Redactor & Sanitizer Sandbox
- **Objective:** Build an interactive PII sanitization sandbox in the options UI (`options/options.html`, `options/options.js`), enabling users to paste arbitrary text, test custom regex patterns against it, view live redactions, and copy sanitized outputs.
- **Files Affected:**
  - `options/options.html`
  - `options/options.js`
  - `tests/storage-integration.test.js`
- **Acceptance Criteria:**
  - Real-time text sanitization with masked PII previews.
  - Direct integration with `core/pii-analyzer.js` custom regex definitions.
- **Validation:** `npm run check`, `npm test`, E2E options page verification.

---

### TSK-14: Tab Threat Notification & Toast Alert Dispatcher
- **Objective:** Implement a lightweight, accessible floating toast alert dispatcher within `content.js` and `content.css` to notify users when critical actions occur (e.g., clicking a confirmed phishing link, right-click scan results).
- **Files Affected:**
  - `content.js`
  - `content.css`
- **Acceptance Criteria:**
  - Non-blocking auto-dismissing toast messages with accessible close triggers.
- **Validation:** `npm run check`, `npm run test:e2e`.

---

### TSK-15: Form Action & Insecure Submission Inspector
- **Objective:** Extend form scanning in `content.js` to evaluate `form.action` target URLs through `core/url-analyzer.js`, identifying credential theft endpoints, unencrypted HTTP form posts on HTTPS origins (mixed content), and dangerous URI schemes in form actions.
- **Files Affected:**
  - `content.js`
  - `core/url-analyzer.js`
  - `tests/e2e/extension-lifecycle.test.js`
- **Acceptance Criteria:**
  - Insecure and phishing form actions display warning badges adjacent to form submit buttons.
  - Mixed-content submissions (HTTPS page posting to HTTP action) are flagged as critical security threats.
- **Validation:** `npm run check`, `npm run test:e2e`.

---

### TSK-16: Live Threat Counter Badge Reactive Tab-Switch Sync
- **Objective:** Add `chrome.tabs.onActivated` listener in `background.js` to immediately sync `chrome.action.setBadgeText` and badge background color when switching between browser tabs, ensuring real-time threat counts reflect the current active tab without delay.
- **Files Affected:**
  - `background.js`
- **Acceptance Criteria:**
  - Switching to a tab with threats updates the toolbar badge immediately to match the active tab's session threat count.
  - Switching to a clean tab clears the badge immediately.
- **Validation:** `npm run check`, E2E test.

---

### TSK-17: Zero-Dependency Core Performance Benchmark Suite
- **Objective:** Build a zero-dependency performance benchmarking script (`scripts/bench.js`) using Node.js `node:perf_hooks` measuring throughput (URLs/sec, PII regex evaluations/sec, scam rule matches/sec) and asserting execution within latency budgets.
- **Files Affected:**
  - `scripts/bench.js`
  - `package.json`
- **Acceptance Criteria:**
  - `npm run bench` runs and outputs operations per second and latency percentiles (p50, p95, p99).
- **Validation:** `npm run bench` passes without dependencies.

---

### TSK-18: Suspicious Executable & Script Download Link Heuristic
- **Objective:** Detect dangerous file extensions (`.exe`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.ps1`, `.msi`, `.hta`, `.apk`, `.iso`, `.jar`) in URL paths, especially from unknown, suspicious, or unencrypted hosts, alerting users before downloading potentially malicious executables.
- **Files Affected:**
  - `core/url-analyzer.js`
  - `tests/url-safety.test.js`
- **Acceptance Criteria:**
  - URLs ending in risky executable/script extensions trigger warning or critical security flags with actionable explanation.
  - Safe whitelist hosts and normal benign file extensions (`.pdf`, `.png`, `.jpg`, `.html`) are not flagged.
- **Validation:** `npm test` with dedicated test cases.

---

### TSK-19: Web3 / Crypto Drainer Approval Signature Detection
- **Objective:** Modernize `core/scam-analyzer.js` to recognize crypto drainer social engineering tactics requesting dangerous off-chain or on-chain approvals, such as `Permit2` batch signatures, `setApprovalForAll`, `increaseAllowance`, and blind `eth_sign` requests.
- **Files Affected:**
  - `core/scam-analyzer.js`
  - `tests/scam-detector.test.js`
- **Acceptance Criteria:**
  - Social engineering lures tricking users into signing unlimited token approvals or Permit2 messages are flagged with critical severity.
  - Legitimate discussions without high-urgency claim/verify lures remain unaffected.
- **Validation:** `npm test` with dedicated test cases.

---

### TSK-20: Accessible Keyboard Interaction for Badge Tooltips
- **Objective:** Enhance DOM overlays in `content.js` and `content.css` so that badges are focusable via keyboard (`tabindex="0"`, `role="button"` or `role="region"`, `aria-label`, `aria-expanded`) and users can toggle tooltips with `Enter` or `Space` keys, or dismiss them with `Escape`.
- **Files Affected:**
  - `content.js`
  - `content.css`
  - `tests/e2e/extension-lifecycle.test.js`
- **Acceptance Criteria:**
  - Badges can receive keyboard focus and display accessible tooltips without requiring mouse hover.
  - `Escape` key dismisses any open tooltip.
- **Validation:** `npm run check`, `npm run test:e2e`.

---

### TSK-21: GitHub Actions CI/CD Validation & Packaging Pipeline
- **Objective:** Establish continuous integration via `.github/workflows/ci.yml` automating lint/syntax checks (`npm run check`), test execution (`npm test`), performance benchmarks (`npm run bench`), and distribution packaging (`npm run pack`), uploading the packed `.zip` bundle as an artifact on releases and push to `main`.
- **Files Affected:**
  - `.github/workflows/ci.yml`
- **Acceptance Criteria:**
  - Standard multi-OS matrix (Ubuntu, Windows) testing Node.js 18.x and 20.x.
  - Validates all repository quality gates and packages the Chrome Web Store zip bundle.
- **Validation:** Syntax check on YAML workflow, manual or pull-request trigger.

---

### TSK-22: Security Audit Event Log Buffer & Telemetry Exporter
- **Objective:** Add an in-memory & local-storage-backed rolling audit log buffer (capped at 50 events) in `background.js` capturing threat detections (timestamp, threat type, severity, host domain), and expose a dedicated "Audit Log & Incident History" table in `options/options.html` and `options/options.js` with CSV/JSON export and clear controls.
- **Files Affected:**
  - `background.js`
  - `options/options.html`
  - `options/options.js`
  - `tests/e2e/extension-lifecycle.test.js`
- **Acceptance Criteria:**
  - Security threats reported from content script or context menu append structured events to `auditLog` in `chrome.storage.local`.
  - Options UI renders the audit table with severity badges and allows downloading log file as JSON.
- **Validation:** `npm run check`, E2E test.

---

### TSK-23: Developer Intranet & Localhost Port Whitelist Expansion
- **Objective:** Enhance `core/url-analyzer.js` `isDomainWhitelisted` to support port specifications (e.g. `localhost:3000`, `127.0.0.1:8080`, `myapp.local:5173`) and private subnet wildcards (e.g. `192.168.*`, `10.*`), preventing false alarms on local development web servers.
- **Files Affected:**
  - `core/url-analyzer.js`
  - `tests/url-safety.test.js`
- **Acceptance Criteria:**
  - Port-specific domain entries match URLs with the corresponding port.
  - Private IP prefixes match developer intranet hosts.
- **Validation:** `npm test` with dedicated test suite.


