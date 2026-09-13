# OSN Guard: Architecture & Systems Engineering Deep Dive

**Author:** Rohan Khadke  
**Scope:** Engineering decisions, algorithm design, client-side security sandboxing, and performance optimizations in OSN Guard (`osn-safety-scanner`).

---

## 1. Executive Summary & Core Engineering Constraints

OSN Guard is a privacy-first browser extension engineered to intercept sensitive data leaks, phishing links, Quishing vectors, cryptocurrency drainers, and malicious forms in real time on modern social feeds (X/Twitter, Reddit, LinkedIn, Facebook).

Building a real-time security scanner for the browser presents unique conflicting constraints:

```
                  ┌──────────────────────────────────────────────┐
                  │          CORE ENGINEERING TRILEMMA           │
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
                 ▼                                               ▼
   ┌───────────────────────────┐                   ┌───────────────────────────┐
   │ 🔒 ZERO PRIVACY LEAKAGE   │                   │ ⚡ 60 FPS ZERO-JANK DOM   │
   │ - CSP: connect-src 'none' │                   │ - 10ms frame budget       │
   │ - Zero cloud lookups      │                   │ - Aho-Corasick O(n + m)   │
   │ - Zero telemetry          │                   │ - Read/write decoupling   │
   └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         │
                                         ▼
                          ┌─────────────────────────────┐
                          │ 📦 ZERO RUNTIME DEPENDENCY  │
                          │ - Native ES2022 JavaScript  │
                          │ - Zero bundlers (No Webpack)│
                          │ - Pure Web Platform APIs    │
                          └─────────────────────────────┘
```

1. **Zero Network Egress (`connect-src 'none'`)**: Standard phishing detectors (e.g. Google Safe Browsing API) send visited URLs or hashes to a central server, exposing user browsing habits. OSN Guard must execute **100% of detection heuristics on-device**.
2. **Zero DOM Stutter (< 16ms frame budget)**: Social feeds dynamically render 500+ post containers and 1,000+ links via infinite scrolling. A naive nested loop scanner causes layout thrashing and dropped frames.
3. **Zero Third-Party Runtime Dependencies**: To eliminate supply-chain vulnerabilities and keep the bundle under 80 KB, all data structures, shims, packagers, and test harnesses are written in **pure native JavaScript**.

---

## 2. Deep Dive: High-Throughput Scam Detection with Aho-Corasick

### The Problem
Social engineering scams (crypto giveaways, wallet drainers, seed phrase theft, tech support scams) contain over 100 known threat keyword signatures.

In a naive implementation:
```js
// Naive approach: O(K * N * L) complexity
for (const rule of SCAM_RULES) {
  for (const kw of rule.keywords) {
    if (text.includes(kw)) { matches.push(rule); }
  }
}
```
For a 5,000-character social media post across 100 keywords, this involves repeated string scans, yielding excessive latency and garbage collection overhead when scanning hundreds of posts per second.

### The Solution: Aho-Corasick Multi-Pattern Trie Automaton
In `src/core/scam-analyzer.js`, OSN Guard constructs a compiled Trie automaton at extension startup with failure transition links.

```
       Root (state 0)
       /          \
     'c'          'w'
     /              \
   'l'              'a'
   /                  \
 'a'                  'l'
 /                      \
'i'                     'l'
 |                       |
'm' [Output: Rule 1]    'e'
                         |
                        't' [Output: Rule 2]
```

#### Trie Search Invariant:
* Scans input text in a **single linear pass** $O(n + m)$, where $n$ is text length and $m$ is total match count.
* Failure transitions allow instantaneous backtrack-free transitions between overlapping keyword prefixes (e.g. `"crypto"`, `"crypto drainer"`, `"drainer"`).
* **Benchmark Results**: Evaluates > 168,000 operations per second (0.0059 ms per evaluation), meeting high-throughput requirements with minimal CPU footprint.

---

## 3. Cooperative 10ms Frame-Budgeted DOM Scheduling

### The Layout Thrashing Trap
Content scripts scanning web pages often interleave DOM reads (`element.getBoundingClientRect()`, `element.textContent`) with DOM writes (`element.appendChild(badge)`). This forces the browser rendering engine to trigger synchronous layout recalculations (reflows).

### Two-Phase Cooperative Scheduler
In `src/content/scanner.js`:
1. **Geometric Read Phase**: Gathers candidate elements, text contents, and link URLs in a read-only batch.
2. **Heuristic Evaluation**: Runs pure memory-based regex and trie lookups with zero DOM touches.
3. **DOM Mutation Phase**: Batches all badge and tooltip updates within a `requestIdleCallback` (or `requestAnimationFrame`) window capped at `BATCH_TIME_BUDGET_MS = 10`.

```
Browser Render Loop (16.6ms)
├─ Animation / User Input (~4ms)
├─ OSN Guard Read & Heuristic Phase (~3ms)
├─ OSN Guard Batched DOM Mutation (~3ms)
└─ Idle / Repaint (~6.6ms)  ==> Smooth 60 FPS maintained
```

Furthermore, floating threat tooltips are mounted to a single shared overlay element attached directly to `document.body` (`position: fixed; z-index: 2147483647`). This eliminates CSS clipping caused by parent card `overflow: hidden` rules while preventing parent reflows.

---

## 4. ReDoS AST Static Analysis & Safe Regex Caching

### The Threat
Allowing users or enterprise policies to define custom PII detection regular expressions introduces the risk of **Regular Expression Denial of Service (ReDoS)**. An adversarial pattern with nested quantifiers (e.g. `(a+)+$` or `([0-9]+)*`) can cause exponential backtracking $O(2^n)$, freezing the browser tab indefinitely.

### Static Pattern Linter (`isSafeRegexPattern`)
In `src/core/pii-analyzer.js`, all user and enterprise regexes are statically validated before compilation:

1. **Length Bounding**: Pattern string length is hard-capped at 250 characters.
2. **Backtracking Signature Rejection**: Statically rejects nested quantifier combinations:
   - Nested plus/star quantifiers: `/\([^)]*(\+|\*)\)[+*]/`
   - Nested ranges: `/\([^)]*(\+|\*)\)\{\d+/`
   - Greedy overlapping alternates: `/\([^|)]+\|[^|)]+\)[+*]/`
3. **LRU Regex Compilation Cache**: Validated patterns are cached in an LRU compilation map (capped at 100 entries). Each execution automatically resets `lastIndex = 0` to prevent stateful regex matching bugs across keystrokes.

---

## 5. Cross-Browser Namespace Normalization (`OSNCompat`)

Chromium extensions use the `chrome.*` namespace with callback APIs and `storage.session`, while Firefox uses `browser.*` with native Promises, and Safari WebExtensions have varying storage capabilities.

Rather than importing heavyweight polyfills (e.g. `webextension-polyfill`), `src/core/compat.js` implements an 800-line, zero-dependency UMD compatibility bridge:

* **Bidirectional Proxy**: Exposes `OSNCompat` methods working seamlessly across `chrome.*` and `browser.*`.
* **Dual Promise/Callback Bridge**: `promisifyOrCallback(fn, args, callback)` detects caller style and returns a native Promise if no callback is supplied, while preserving callback execution.
* **Storage Session Fallback**: On platforms lacking native `storage.session` (older Gecko or standalone Safari webviews), `OSNCompat` transparently prefixes session keys (`__session_tab123_...`) into `storage.local` and cleans them on lifecycle events.
* **Prototype Pollution Guard**: All storage deserializers enforce `isPollutionKey()` blocking `__proto__`, `constructor`, and `prototype`.

---

## 6. Zero-Bundler Multi-Target Packaging Pipeline

Modern web extension development often relies on heavy toolchains (Webpack, Rollup, Vite) that produce bloated outputs, introduce dependency supply chain risks, and complicate security audits.

OSN Guard uses `scripts/pack.js` — a single 300-line native Node.js script using built-in `node:zlib`:
- Generates valid PKZIP archives with raw DEFLATE compression.
- Automatically tailors manifests for target platforms:
  - **Chrome**: Native Manifest V3 with service worker background.
  - **Firefox**: Gecko ID injection, Event Page background script array in explicit dependency order (`compat.js` -> `threat-config.js` -> `service-worker.js`).
  - **Safari**: Minimum version constraints and extension page path mapping.
- **Output**: Generates ~76 KB standalone archives ready for Chrome Web Store, Mozilla AMO, and Safari distribution in `< 250ms`.

---

## 7. Testing Discipline & Verification Architecture

```
                                ┌──────────────────────────────────────┐
                                │     Continuous Verification Gate     │
                                └──────────────────┬───────────────────┘
                                                   │
                ┌──────────────────────────────────┼──────────────────────────────────┐
                │                                  │                                  │
                ▼                                  ▼                                  ▼
 ┌─────────────────────────────┐    ┌─────────────────────────────┐    ┌─────────────────────────────┐
 │ 🧪 Unit & Integration Tests │    │ 🌐 Headless E2E Lifecycle   │    │ ⚡ Micro-Benchmarks         │
 │ - 241 tests / 55 suites     │    │ - Native CDP Client         │    │ - > 160k ops/sec throughput │
 │ - Node.js native test runner│    │ - Zero Puppeteer dependency │    │ - Sub-millisecond latency   │
 │ - Execution time: ~2.0s     │    │ - Full DOM burst simulation │    │ - Automated budget bounds   │
 └─────────────────────────────┘    └─────────────────────────────┘    └─────────────────────────────┘
```

The entire verification pipeline is built using Node.js's native `node:test` and `node:assert/strict` modules. Automated CI runs across **Node 18, 20, and 22** on both **Ubuntu and Windows** operating systems on every commit and pull request.
