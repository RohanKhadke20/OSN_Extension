# OSN Guard — Production-Hardening Scope & Boundary Contract

> **Target Repository:** `osn-safety-scanner` (OSN Guard)  
> **Dedicated Branch:** `audit/production-hardening` (branched from `audit/teamwork-adaptability`)  
> **Integrity Mode:** Zero-Dependency, Zero-Network-Egress (`connect-src 'none'`), Least-Privilege WebExtension

---

## 1. Directory & File Reorganization Scope

The codebase will be reorganized into a clean, conventional, framework-appropriate `src/` modular layout while maintaining 100% zero-bundler vanilla compatibility.

### 1.1 Old-Path -> New-Path Migration Map

| Old Path | New Path | Description |
|---|---|---|
| `background.js` | `src/background/service-worker.js` | Service worker & background event coordinator |
| `content.js` | `src/content/scanner.js` | DOM batch scanner & Quishing detector |
| `content.css` | `src/content/scanner.css` | Injected overlay & badge stylesheets |
| `core/compat.js` | `src/core/compat.js` | Cross-browser namespace shim & promise bridge |
| `core/threat-config.js` | `src/core/threat-config.js` | Data-driven threat signatures & threshold config |
| `core/url-analyzer.js` | `src/core/url-analyzer.js` | URL safety evaluation engine |
| `core/pii-analyzer.js` | `src/core/pii-analyzer.js` | PII leakage detection & masking engine |
| `core/scam-analyzer.js` | `src/core/scam-analyzer.js` | Aho-Corasick scam & fraud classifier |
| `popup/` | `src/ui/popup/` | Extension toolbar popup UI (`popup.html`, `popup.js`, `popup.css`) |
| `options/` | `src/ui/options/` | Settings & rule management page (`options.html`, `options.js`, `options.css`) |
| `assets/` | `src/assets/` | Extension icons & media assets |

---

## 2. Protected Files & Invariant Contracts (Must NOT Break)

The following files, root endpoints, and distribution contracts are strictly preserved:

1. **Repository Root Manifests:**
   - `manifest.json` remains at repository root, updated to reference `src/...` paths for direct, unpackaged developer-mode extension loading.
   - `managed_schema.json` remains at repository root for Chrome Enterprise policy registration.
2. **Distribution Packaging (`scripts/pack.js`):**
   - Multi-target packager updated to package from `src/` with output archives (`dist/osn-guard-*.zip`) maintaining identical naming and manifest transforms for Chrome, Firefox, and Safari.
3. **CI / Automation Workflows:**
   - `.github/workflows/*` must continue passing cleanly on Node 18, 20, 22 on Ubuntu and Windows.
   - Zero runtime dependencies, zero external bundlers, zero network egress.
4. **CLI Contract:**
   - `npm run check`, `npm test`, `npm run test:e2e`, `npm run bench`, `npm run pack:all` must remain 100% functional with zero regressions.

---

## 3. High-Priority Risk Areas

The bug sweep and security audit will focus on:

1. **IPC Verification & Async Message Boundaries:**
   - Comprehensive `sender.id === chrome.runtime.id` verification across all handlers.
   - Async `sendResponse` return boolean safety and unhandled Promise rejections in `runtime.onMessage`.
2. **Storage Quota & State Recovery:**
   - Handling `MAX_ITEMS` and quota-exceeded rejections.
   - Resilient fallback and self-healing for corrupted local and session storage.
3. **DOM Scanning Memory & Invalidation Safety:**
   - MutationObserver cleanup on context invalidation.
   - Memory leak bounds on high-frequency social media feeds.
4. **Strict Input Sanitization & Prototype Pollution Defense:**
   - Defense-in-depth on backup import/export schemas, context menu inputs (5,000-char cap), and review prompt eligibility calculations.
   - Deep freeze and `hasOwn` prototype guards on all threat config and compat layers.

---

## 4. Execution Batching Strategy

The hardening pass will execute in 4 discrete, independently verifiable batches:

- **Batch 1:** File/Folder Reorganization, Import Reference Updates, and Manifest/Packager Migration.
- **Batch 2:** Comprehensive Bug Sweep (Unhandled Async, Exception Boundaries, DOM Cleanup, Storage Recovery).
- **Batch 3:** Security Audit & Hardening (IPC Verification, CSP Invariants, Sanitization, ReDoS Prevention).
- **Batch 4:** Persistent Rules Definition (`.agents/rules/` / docs), Compatibility Matrix Verification, and Full Test Suite Confirmation.
