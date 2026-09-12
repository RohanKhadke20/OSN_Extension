# OSN Guard — System Threat Model & Security Architecture

**Document Version:** 1.0.0  
**Classification:** Public Security Specification  
**Extension Target:** Google Chrome, Mozilla Firefox, Apple Safari (Manifest V3)  
**Last Updated:** September 2026

---

## 1. Executive Summary

OSN Guard is a local-first, privacy-preserving browser security extension engineered to protect users from social media scams, credential phishing, data leakage, and predatory cyber threats in real time.

Unlike traditional antivirus or telemetry-heavy browser extensions, OSN Guard operates under a strict **Zero Network Egress** security mandate: all lexical heuristics, threat classifiers, PII detectors, and regex matching engines execute exclusively on the local client thread without contacting remote servers.

This document formalizes the threat landscape, trust boundaries, protected assets, explicit non-goals, and defensive mitigations implemented across the extension codebase.

---

## 2. System Architecture & Trust Boundaries

The extension architecture consists of four distinct execution environments managed under the browser extension sandbox:

```
+-------------------------------------------------------------------------+
|                              HOST DEVICE                                |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                        BROWSER PROCESS                            |  |
|  |                                                                   |  |
|  |  +-----------------------+           +--------------------------+ |  |
|  |  |  Untrusted Web Page   |           |  Background Context      | |  |
|  |  |  (DOM, Inputs, Links) |           |  (Service Worker /       | |  |
|  |  |           |           |           |   Gecko Event Page)      | |  |
|  |  |           v           |           |             ^            | |  |
|  |  |  +-----------------+  |  IPC      |             |            | |  |
|  |  |  | Content Script  |--|-----------|-------------+            | |  |
|  |  |  | (content.js)    |  | (chrome.  |             v            | |  |
|  |  |  +-----------------+  |  runtime) |  +--------------------+  | |  |
|  |  +-----------------------+           |  | Local Storage      |  | |  |
|  |                                      |  | (chrome.storage)   |  | |  |
|  |  +-----------------------+           |  +--------------------+  | |  |
|  |  | Extension UI Pages    |           |             ^            | |  |
|  |  | (Popup & Options)     |-----------|-------------+            | |  |
|  |  +-----------------------+           +--------------------------+ |  |
|  |                                                                   |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
```

### Trust Boundary Definitions

1. **Untrusted Web Execution Boundary (Content Script <-> Page DOM):**
   - Untrusted web pages run arbitrary third-party JavaScript.
   - Content scripts execute in an **Isolated World**: page scripts cannot access extension JavaScript scopes or variables.
   - However, page scripts share the live DOM with the content script. DOM nodes, attributes, and input values must be treated as untrusted input.

2. **Internal Message Routing Boundary (Content Script <-> Background Worker):**
   - Communication occurs via `chrome.runtime.sendMessage()`.
   - The background worker validates sender identity (`sender.id === chrome.runtime.id`) to prevent external extensions or web pages from injecting forged IPC commands.

3. **Extension Configuration Boundary (Options / Storage):**
   - Stored configurations (`shields`, `whitelistedDomains`, `customPiiPatterns`, `auditLog`) persist in `chrome.storage.local` and ephemeral tab state in `chrome.storage.session`.
   - Imported configuration backups originate from arbitrary user files and must undergo rigorous schema validation before applying.

---

## 3. Assets Protected

| Asset | Description | Impact of Compromise |
| :--- | :--- | :--- |
| **User PII & Sensitive Input** | Passwords, credit cards (Luhn-checked), SSNs, IBANs, auth tokens (JWT), API secrets, database URIs typed into web forms. | Identity theft, credential harvesting, financial loss. |
| **Browsing Privacy** | URLs visited, domains browsed, pages analyzed, and threats intercepted. | De-anonymization, behavioral tracking. |
| **Extension Configuration** | Shield toggles, whitelisted domains, and custom regex detection patterns. | Evasion of protection, silent disabling of shields. |
| **Local Audit Event Log** | Rolling buffer of recent security detections and intercepted incidents. | Tampering with forensic records or tracking user history. |
| **Browser UI Stability** | Responsiveness of the browser tab and extension popup/options pages. | Denial of Service (ReDoS) freezing UI threads. |

---

## 4. Explicit Non-Goals & Architectural Limitations

To establish realistic expectations, the following items are formally designated as **Non-Goals** and architectural limitations:

### 4.1 Zero Network Egress Guarantee
- **Limitation:** OSN Guard operates with `connect-src: 'none'` and does not query remote threat intelligence databases (e.g., Google Safe Browsing API, VirusTotal).
- **Rationale:** Sending visited URLs or input hashes to a remote server would compromise user browsing privacy. OSN Guard relies strictly on deterministic, local lexical and structural heuristics.
- **Consequence:** Zero-day malicious domains that show no homograph, structural, or lexical anomalies cannot be identified prior to page content inspection.

### 4.2 Pre-DOM and Transport Layer Invisibility
- **Limitation:** OSN Guard runs as a DOM-level content script and background extension worker. It cannot inspect raw TCP/IP packets, TLS certificate chains, or low-level network protocol handshakes.
- **Consequence:** OSN Guard does not function as an operating-system firewall, VPN, or network IDS/IPS.

### 4.3 Endpoint Malware & Hardware Keyloggers
- **Limitation:** If the host machine is compromised with OS-level malware, rootkits, or physical keyloggers, keystrokes are intercepted at the hardware or kernel driver level before reaching the browser DOM.
- **Consequence:** Browser extensions cannot defend against compromised operating system kernels or firmware.

### 4.4 Same-Process In-Memory Browser Exploits
- **Limitation:** If an adversary achieves remote code execution (RCE) via a zero-day vulnerability in Chrome's V8 engine or WebKit/Gecko rendering pipeline, the extension sandbox may be bypassed.
- **Consequence:** OSN Guard relies on the underlying browser's process isolation and sandboxing guarantees.

---

## 5. Threat Actors & Threat Scenarios

### Actor 1: Untrusted Web Page / Phisher
- **Objective:** Harvest credentials, display deceptive cryptocurrency lures, execute quishing, or mislead users via IDN homographs.
- **Attack Vectors:**
  - Injecting visually identical Cyrillic/Greek characters into anchor links (`paypal.com` vs `pаypаl.com`).
  - Hiding secret recovery phrase lures within zero-width non-joiners or directional overrides.
  - Embedding malicious open-redirect URLs to evade basic domain filters.
- **Mitigation:**
  - Regex & Unicode Script Confusable matching (`hasMixedScriptConfusables`).
  - Zero-width character stripping before heuristic scoring (`normalizeScamText`).
  - Open-redirect parameter parsing and destination resolution.

### Actor 2: Adversary Providing Malicious Configuration / Pattern (ReDoS)
- **Objective:** Freeze the user's browser or cause tab crashes via Regular Expression Denial of Service (catastrophic backtracking).
- **Attack Vectors:**
  - Sharing crafted custom PII backup files or regex patterns like `(a+)+$` or `( a + ) +`.
- **Mitigation:**
  - Static AST/heuristic linter (`isSafeRegexPattern()`) rejects nested repeating quantifiers, variably quantified parenthetical groups, and whitespace-obfuscated backtracking patterns before compilation.
  - LRU pattern cache (`customRegexCache`) limits compiling instances and evicts stale patterns safely.

### Actor 3: Malicious File Import / Prototype Pollution
- **Objective:** Inject polluted properties into `Object.prototype` via JSON backup files, corrupting extension logic.
- **Attack Vectors:**
  - JSON backups containing `"__proto__"`, `"constructor"`, or `"prototype"` keys.
- **Mitigation:**
  - Strict schema filtering extracts only explicit, whitelisted primitive properties (`shields`, `whitelistedDomains`, `customPiiPatterns`).
  - No recursive deep-merge or unsafe property assignments (`updates.whitelistedDomains = parsed.whitelistedDomains.filter(...)`).

### Actor 4: Inter-Extension IPC Impersonation
- **Objective:** Trigger privileged actions (clearing logs, altering stats, manipulating badge counts) by sending forged messages to `background.js`.
- **Attack Vectors:**
  - Another extension installed in the browser sending `chrome.runtime.sendMessage(OSN_ID, ...)`.
- **Mitigation:**
  - Strict sender ID verification on every internal message:
    ```javascript
    if (sender && sender.id && chrome.runtime.id && sender.id !== chrome.runtime.id) {
      return false;
    }
    ```

---

## 6. STRIDE Threat Matrix & Defenses

| STRIDE Category | Threat Description | Severity | OSN Guard Defensive Control |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary extension impersonates content script to report false threats. | High | Internal `sender.id === chrome.runtime.id` verification in `background.js`. |
| **Tampering** | Malicious backup file modifies settings or injects polluted prototype properties. | High | Strict, schema-based extraction of valid primitives; prototype pollution defenses verified by unit tests. |
| **Repudiation** | User denies an incident occurred or malicious script wipes logs. | Low | Security incident log recorded in `chrome.storage.local` with rolling 50-item cap; exportable as JSON audit trail. |
| **Information Disclosure** | Visiting sensitive URLs or leaking typed passwords/PII to external telemetry. | Critical | Strict CSP `connect-src 'none'`; zero remote analytics; zero telemetry endpoints; local-only processing. |
| **Denial of Service** | Malicious regex pattern causes catastrophic backtracking (ReDoS) on form input. | High | Pre-compilation static linter `isSafeRegexPattern()` rejects nested quantifiers, variable bounds, and spaced evasion patterns. |
| **Elevation of Privilege** | Content script attempts to execute background-only APIs or load external scripts. | Critical | Manifest V3 isolated execution context; `script-src 'self'`; no `eval()`; no remotely hosted code. |

---

## 7. Data Safety & Resiliency Architecture

1. **Pre-Reset Snapshot & 10-Second Undo:**
   - Destructive actions ("Restore Factory Defaults" and "Reset Metrics Counter") automatically snapshot existing configuration and stats before modification.
   - Users are provided a 10-second inline "Undo" window to instantly restore previous configurations in case of accidental clicks.

2. **Dormant Tab Reconciliation:**
   - Manifest V3 background service workers frequently terminate after 30 seconds of inactivity.
   - When tabs close or crash while the service worker is dormant, orphaned tab keys (`tab_${id}`) are automatically pruned upon browser startup, extension install/update, and throttled tab activation (every 3 minutes).

3. **Frame-Budget & Input Throttling:**
   - Keystroke inspection in content scripts is debounced to avoid layout thrashing and input lag on low-power devices.
   - Input inspection ignores password fields (managed by password managers) and targets textareas, text inputs, and search bars.

---

## 8. Verification & Continuous Compliance

OSN Guard enforces these security controls via continuous automated testing:

- **Static Compliance:** Node.js syntax checks (`npm run check`) across all entry points.
- **Unit & Security Suites:** 108+ automated tests covering Luhn validation, IBAN checksums, SSN structure, URL homographs, IP hostnames, ReDoS evasion, prototype pollution, and tab reconciliation.
- **CI Matrix:** Multi-OS (Ubuntu, Windows) and multi-Node (18, 20, 22) GitHub Actions workflow running on all pull requests and branch pushes.
- **Packaging Integrity:** Automated packager (`scripts/pack.js`) verifying Manifest V3 compliance and building standalone packages for Chrome, Firefox, and Safari with zero cross-contamination.
