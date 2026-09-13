# OSN Guard — Cross-Browser Compatibility Guide

> **Branch:** `docs/continuous-ops` · **Shim:** `src/core/compat.js` · **Version:** 1.3.0

This document describes how OSN Guard runs across Chromium MV3, Firefox Gecko,
and Safari WebExtensions from a **single unified source tree** — zero bundlers,
zero runtime dependencies.

---

## Table of Contents

1. [Browser Support Matrix](#1-browser-support-matrix)
2. [Compatibility Shim Architecture](#2-compatibility-shim-architecture)
3. [Namespace Unification](#3-namespace-unification)
4. [Dual Callback / Promise Bridge](#4-dual-callback--promise-bridge)
5. [Storage API Fallbacks](#5-storage-api-fallbacks)
6. [Manifest Differences per Target](#6-manifest-differences-per-target)
7. [Lifecycle Behaviour Across Browsers](#7-lifecycle-behaviour-across-browsers)
8. [Content Script Loading Order](#8-content-script-loading-order)
9. [Building & Packaging for Each Target](#9-building--packaging-for-each-target)
10. [Testing the Shim](#10-testing-the-shim)
11. [Auditor Before/After Status Table](#11-auditor-beforeafter-status-table)

---

## 1. Browser Support Matrix

| Feature | Chrome MV3 | Firefox (Gecko) | Safari WebExtension |
|---|---|---|---|
| Manifest version | **3** | **2** (emulated as MV3-style) | **3** |
| Background context | Service Worker | Persistent Event Page | Service Worker |
| `chrome.*` namespace | ✅ Native | ⚠️ Polyfilled by shim | ⚠️ Polyfilled by shim |
| `browser.*` namespace | ⚠️ Aliased by shim | ✅ Native | ✅ Native |
| `storage.session` | ✅ Native | ❌ → prefix-fallback on `local` | ⚠️ Partial → prefix-fallback |
| `storage.managed` | ✅ Native (Chrome Enterprise) | ⚠️ Limited → in-memory stub | ❌ → in-memory stub |
| `storage.local` | ✅ | ✅ | ✅ |
| `contextMenus` | ✅ (`chrome.contextMenus`) | ✅ (`browser.menus`) → aliased | ✅ |
| `action` (MV3) | ✅ | ✅ | ✅ |
| `browserAction` (MV2 compat) | Aliased by shim | ✅ Native → aliased | Aliased by shim |
| `BarcodeDetector` (QR quishing) | ✅ Chrome 83+ | ❌ Not supported | ✅ Safari 17.4+ |
| Callback-style APIs | ✅ | ⚠️ Promise-only (wrapped) | ⚠️ Promise-only (wrapped) |
| Promise-style APIs | ✅ Chrome 96+ | ✅ | ✅ |

---

## 2. Compatibility Shim Architecture

The shim lives at **`src/core/compat.js`** (828 lines) and is loaded as the
**first** script in every browser context — content scripts, extension pages,
and (via `importScripts`) the service worker background.

### Design Principles

- **Zero dependencies.** Pure ES5-compatible JavaScript; no transpiler, no
  bundler, no external packages.
- **Self-initializing IIFE.** The module wraps itself in a UMD-style factory
  that exports `OSNCompat` to `globalThis.OSNCompat` (browser) or
  `module.exports` (Node.js test runner).
- **Non-destructive patching.** The shim only fills gaps — it never overwrites
  a working native API.
- **Prototype-pollution defense.** All object property accesses use
  `Object.prototype.hasOwnProperty.call(obj, key)` (aliased as `hasOwn`) and
  a `isPollutionKey` guard blocking `__proto__`, `constructor`, and `prototype`.

### Module Sections

| Section | Lines | Responsibility |
|---|---|---|
| 1. Prototype Utilities | 38–45 | `hasOwn`, `isPollutionKey` guards |
| 2. Engine Detection | 51–62 | `detectEngine()` → `{ isFirefox, isSafari, isChromium }` |
| 3. URL Resolvers | 68–118 | `INTERNAL_URL_PREFIXES`, `isInternalUrl`, `getStoreReviewUrl` |
| 4. lastError Management | 124–187 | `setLastError`, `clearLastError`, `getLastError` |
| 5. Promise Bridge | 193–312 | `promisifyOrCallback` — dual callback/Promise mode |
| 6. Storage Fallbacks | 318–622 | `createSessionStorageFallback`, `createManagedStorageFallback` |
| 7. Method Wrapping | 628–676 | `wrapMethod`, `normalizeAction`, `normalizeMenus` |
| 8. Namespace Sync | 682–789 | `init()` — bidirectional `chrome.*` ↔ `browser.*` unification |
| 9. Public API Export | 798–827 | `OSNCompat` object exposed to consumers |

---

## 3. Namespace Unification

### The Problem

Chromium exposes all APIs under `chrome.*` with **callback**-based signatures.
Firefox exposes APIs under `browser.*` with **Promise**-based signatures.
Safari supports both, but the available APIs depend on the OS version.

### The Solution

The shim's `init()` function runs at parse time and performs **bidirectional
aliasing**:

```
chrome.*  ←→  browser.*
```

1. If only `chrome` exists (Chromium): `browser = chrome`
2. If only `browser` exists (Firefox/Safari): `chrome = browser`
3. If both exist (some edge cases): sub-namespaces are cross-filled where one
   side is missing

**Sub-namespaces synchronized:** `runtime`, `storage`, `tabs`, `action`,
`contextMenus`, `menus`, `browserAction`

**Runtime properties synchronized:** `id`, `getURL`, `openOptionsPage`

After `init()` runs, all extension code can safely use either `chrome.*` or
`browser.*` and receive the same underlying API object.

---

## 4. Dual Callback / Promise Bridge

### The Problem

Chromium MV3's storage and tabs APIs accept optional callbacks. Firefox's
`browser.*` APIs return Promises only. Code that passes callbacks to Firefox
APIs receives a Promise back and the callback is silently ignored — this is
a source of subtle bugs.

### `promisifyOrCallback(fn, context, args, callbackIndex?)`

The bridge function inspects the call signature:

**With a callback argument:**
```
Caller: chrome.storage.local.get(keys, myCallback)
         ↓
Bridge: strips myCallback from args, passes interceptCallback to native fn
        interceptCallback reads lastError and invokes myCallback with (null, result) or (err)
        clearLastError() is called in both success and error paths
```

**Without a callback:**
```
Caller: await chrome.storage.local.get(keys)
         ↓
Bridge: wraps native fn call in a Promise
        interceptCallback resolves/rejects the Promise
        clearLastError() called in both paths
        trailing null/undefined args are trimmed before invocation
```

### Edge-Case Hardening (Round 2)

| Edge Case | Mitigation |
|---|---|
| Stale `lastError` on Promise settlement | `clearLastError()` called before `resolve()` and `reject()` in Promise path |
| `storage.clear(null)` — null arg passed | Trailing null/undefined trimmed via `while (callArgs[last] === null\|\|undefined) callArgs.pop()` |
| Prototype-polluted `__osnWrapped` | `hasOwn(original, "__osnWrapped")` uses `Object.prototype.hasOwnProperty.call`, immune to `Object.prototype.__osnWrapped = true` |
| Double invocation of callbacks | `invoked` boolean guard prevents re-entry |

---

## 5. Storage API Fallbacks

### `storage.session` — Chrome MV3 only

`storage.session` is a Chrome MV3-exclusive per-session in-memory area that is
cleared when the service worker terminates. Firefox MV2 and some Safari builds
do not expose it.

**Fallback strategy:** When `storage.session` is absent, the shim creates a
`localStorage`-prefixed emulation on `storage.local`:

```
Real key:   "myKey"
Stored as:  "__osn_session_:myKey"
```

All session keys are namespaced to avoid collisions with non-session data.
On full `get(null)`, only `__osn_session_:*` keys are returned, stripped of
the prefix.

If `storage.local` is also unavailable (extreme edge case), an in-memory
`memStore` object is used instead.

### `storage.managed` — Chrome Enterprise only

`storage.managed` is only reliably available on Chromium with an Enterprise
MDM policy (`managed_schema.json` registered in `manifest.json`). Firefox's
support is limited and requires explicit AMO approval; Safari does not support it.

**Fallback strategy:** An in-memory read-only stub that:
- `get()` returns an empty object `{}`
- `set()` / `remove()` / `clear()` throw `"storage.managed is read-only"` (preserving the real API's read-only contract)

Enterprise features gracefully degrade: IT-managed shields are simply not locked,
and the managed-policy banner is not shown when the fallback is active.

---

## 6. Manifest Differences per Target

OSN Guard uses a **single `manifest.json`** as the source of truth. The
packager (`scripts/pack.js`) generates per-target manifests in `dist/`:

### Chrome (`dist/manifest-chrome.json`)

```json
{
  "manifest_version": 3,
  "background": { "service_worker": "src/background/service-worker.js" },
  "storage": { "managed_schema": "managed_schema.json" }
}
```

No changes from source `manifest.json`.

### Firefox (`dist/manifest-firefox.json`)

The packager applies these transforms:

| Field | Transformation |
|---|---|
| `background.service_worker` | Replaced with `background.scripts: ["src/core/compat.js", "src/core/threat-config.js", "src/core/url-analyzer.js", "src/core/pii-analyzer.js", "src/core/scam-analyzer.js", "src/background/service-worker.js"]` (Event Page model) |
| `browser_specific_settings` | Added: `{ "gecko": { "id": "osn-guard@extension.local", "strict_min_version": "109.0" } }` |
| `storage.managed_schema` | Removed (not supported on AMO without review approval) |

Firefox Gecko minimum version **109.0** ensures MV3-compatible API surface
(event-driven background, `action` API instead of `browserAction`).

### Safari (`dist/manifest-safari.json`)

Safari WebExtension uses MV3 natively on Safari 15.4+ (macOS 12.3+,
iOS 15.4+). The packager:

| Field | Transformation |
|---|---|
| `background.service_worker` | Kept as-is (`src/background/service-worker.js`; Safari 15.4+ supports service workers) |
| `browser_specific_settings` | Added: `{ "safari": { "strict_min_version": "15.4" } }` |
| `storage.managed_schema` | Removed (Safari does not support managed storage schema) |

> **Note:** Safari WebExtension distribution requires Xcode wrapping via
> `xcrun safari-web-extension-converter`. The zip archive generated by
> `npm run pack:safari` contains the web extension source ready for import.

---

## 7. Lifecycle Behaviour Across Browsers

### Service Worker (Chrome, Safari)

```
Extension installed / updated
  → src/background/service-worker.js parsed (imports src/core/*.js via importScripts)
  → OSNCompat.init() runs synchronously
  → chrome.storage.session.get/set available natively
  → Service worker may be suspended after ~30s of inactivity
  → On next event: service worker respawned, init() runs again
```

**Important:** OSN Guard's `reconcileOrphanedTabs` and `ensureStorageIntegrity`
functions in `src/background/service-worker.js` are designed to run on every service worker wake-up
to heal state that may have been lost during suspension. The compat shim's
`storage.session` fallback is idempotent across spawns.

### Event Page (Firefox)

```
Extension installed / updated
  → src/background/service-worker.js loaded as an event page (persistent: false equivalent)
  → OSNCompat.init() runs synchronously
  → chrome.storage.session NOT available natively → shim prefix-fallback activated
  → Event page unloaded after idle, reloaded on next event
  → Same healing logic applies on each reload
```

### Content Scripts

Content scripts are injected into every page matching `<all_urls>` at
`document_end`. Load order is determined by the `js` array in `manifest.json`:

```
src/core/compat.js        ← shim must be first
src/core/threat-config.js ← default threat configuration data
src/core/url-analyzer.js  ← URL safety engine
src/core/pii-analyzer.js  ← PII detector
src/core/scam-analyzer.js ← Aho-Corasick scam classifier
src/content/scanner.js    ← DOM scanner, QR quishing detector
```

The shim runs at parse time (top-level IIFE), so all subsequent scripts have
`chrome.*` and `browser.*` both available by the time their own code runs.

---

## 8. Content Script Loading Order

All extension pages (`src/ui/popup/popup.html`, `src/ui/options/options.html`) declare scripts
in the same dependency order as the manifest `content_scripts` array:

```html
<script src="../../core/compat.js"></script>
<script src="../../core/threat-config.js"></script>
<script src="../../core/url-analyzer.js"></script>
<script src="../../core/pii-analyzer.js"></script>
<script src="../../core/scam-analyzer.js"></script>
<script src="popup.js"></script>  <!-- or options.js -->
```

The background service worker loads scripts via implicit service worker module
evaluation order (scripts listed in `background.service_worker` are evaluated
sequentially). For Firefox's event page, `background.scripts` preserves the
same order.

---

## 9. Building & Packaging for Each Target

### Prerequisites

- Node.js ≥ 18 (tested on 18, 20, 22)
- No other runtime dependencies

### Commands

```bash
# Syntax check all source files
npm run check

# Run all 241 unit tests
npm test

# Run E2E lifecycle tests (requires Chromium in PATH)
npm run test:e2e

# Run performance benchmarks
npm run bench

# Package for all targets (outputs to dist/)
npm run pack:all

# Package individual targets
node scripts/pack.js --target=chrome
node scripts/pack.js --target=firefox
node scripts/pack.js --target=safari
```

### Output Artifacts

```
dist/
├── manifest-chrome.json                            ← Chrome manifest
├── manifest-firefox.json                           ← Firefox manifest (transformed)
├── manifest-safari.json                            ← Safari manifest (transformed)
├── osn-guard-safety-privacy-shield-v1.3.0.zip      ← Chrome Web Store ready
├── osn-guard-safety-privacy-shield-firefox-v1.3.0.zip  ← AMO ready
└── osn-guard-safety-privacy-shield-safari-v1.3.0.zip   ← Xcode import ready
```

### Files Included in Every Package

```
manifest.json                 managed_schema.json           README.md
src/background/service-worker.js
src/content/scanner.js        src/content/scanner.css
src/core/compat.js            src/core/threat-config.js
src/core/url-analyzer.js      src/core/pii-analyzer.js      src/core/scam-analyzer.js
src/ui/popup/popup.html       src/ui/popup/popup.js         src/ui/popup/popup.css
src/ui/options/options.html   src/ui/options/options.js     src/ui/options/options.css
src/assets/icons/icon-16.png  src/assets/icons/icon-48.png  src/assets/icons/icon-128.png
```

---

## 10. Testing the Shim

The compatibility shim has its own isolated test suite at
**`tests/compat.test.js`** (100 tests, 27 suites) structured across 5 tiers:

| Tier | Focus | Tests |
|---|---|---|
| 1 | Engine detection, URL resolvers, internal URL guard | 14 |
| 2 | `setLastError` / `clearLastError` / `getLastError` lifecycle | 15 |
| 3 | `promisifyOrCallback` — dual mode, error propagation, sync throws | 22 |
| 4 | `storage.session` and `storage.managed` fallback correctness | 31 |
| 5 | Round 2 adversarial hardening (stale lastError, null args, prototype pollution) | 18 |

Run in isolation:
```bash
node --test tests/compat.test.js
```

Expected output: `tests 100, pass 100, fail 0`

---

## 11. Auditor Before/After Status Table

This table reflects the state before the `audit/teamwork-adaptability` branch
vs. the completed state of Milestones 1–3.

| Dimension | Before (main @ `2120326`) | After (`audit/teamwork-adaptability`) |
|---|---|---|
| **Security — CSP** | `connect-src 'none'` enforced | ✅ Unchanged |
| **Security — Permissions** | `{storage, activeTab, contextMenus}` | ✅ Unchanged — no additions |
| **Security — IPC** | `sender.id === chrome.runtime.id` verified | ✅ Unchanged |
| **Security — Prototype Pollution** | Guards in backup import, pii-analyzer | ✅ Extended: shim adds `hasOwn` + `isPollutionKey` guards globally |
| **Security — lastError hygiene** | Not tracked | ✅ NEW: `clearLastError()` on every callback/Promise settlement path |
| **Reliability — Cross-browser** | Chrome-only (no shim) | ✅ NEW: Firefox + Safari namespace unification, storage fallbacks |
| **Reliability — Service Worker** | `reconcileOrphanedTabs` on every wake-up | ✅ Unchanged |
| **Reliability — Storage.session** | Requires Chrome MV3 | ✅ NEW: Prefix-fallback on `storage.local` for Firefox/Safari |
| **Reliability — Storage.managed** | Requires Chrome Enterprise | ✅ NEW: In-memory read-only stub for non-Chrome targets |
| **Data Safety — PII Detection** | 100% coverage, LRU cache | ✅ Unchanged — config-driven thresholds added |
| **Data Safety — Scam Detection** | Aho-Corasick trie, ≥ 100k ops/s | ✅ Unchanged — trie rebuilt from config at init |
| **Architecture — Threat Rules** | Hardcoded in each analyzer | ✅ NEW: Centralized `src/core/threat-config.js`, data-driven override |
| **Architecture — Browser Target** | Single Chrome build | ✅ NEW: Unified source tree, 3 packaged targets |
| **Architecture — Extensibility** | Code changes required for new rules | ✅ NEW: Config-level rule/threshold injection, no code change needed |
| **Testing — Unit Tests** | Pre-refactor tests | ✅ 241 unit tests across 55 test suites (100% pass) |
| **Testing — E2E Tests** | 6 lifecycle tests | ✅ Unchanged (all 6 pass) |
| **Testing — Benchmarks** | Scam ≥ 100k ops/s | ✅ Unchanged — performance budgets met (> 200k ops/s) |
| **Compatibility — Chrome** | ✅ Web Store ready | ✅ Web Store ready (unchanged) |
| **Compatibility — Firefox** | ❌ Not packaged | ✅ AMO-ready zip, Event Page manifest generated |
| **Compatibility — Safari** | ❌ Not packaged | ✅ Safari zip, MV3 manifest generated |
| **Docs — Compatibility** | Not documented | ✅ NEW: `docs/COMPATIBILITY.md` (this document) |

---

*Maintained under continuous documentation operations on branch `docs/continuous-ops`.*
