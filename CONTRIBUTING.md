# Contributing to OSN Guard

Thank you for your interest in contributing to **OSN Guard** (`osn-safety-scanner`)! We welcome contributions from the open-source community to improve privacy, phishing detection, and user security across the modern web.

---

## 🔒 Non-Negotiable Core Invariants

Before proposing any code change, all contributors must understand and preserve our non-negotiable security and architectural principles:

1. **Zero External Runtime Dependencies:**
   - The extension uses native modern JavaScript (ES2022) and Web Platform APIs exclusively.
   - Zero npm runtime or dev packages. Do not introduce bundlers (Webpack, Vite, Rollup), transpilers, or third-party libraries.
2. **Zero Network Egress:**
   - The extension operates under a strict Content Security Policy: `connect-src 'none'`.
   - The extension must NEVER make outbound network calls, send telemetry, report analytics, or contact remote heuristic backends. All heuristic and classification logic runs 100% client-side.
3. **Least Privilege Permissions:**
   - Manifest permissions are strictly limited to `{ storage, activeTab, contextMenus }`.
   - `host_permissions` are strictly disallowed (`host_permissions: none`).
4. **DOM-Based XSS Immunity:**
   - Never use `innerHTML`, `outerHTML`, or `document.write`.
   - All badge overlays, alerts, and tooltips must be constructed using native DOM API methods (`textContent`, `createElement`, `replaceChildren`).
5. **Dedicated Branch Model:**
   - Always work on a dedicated feature, fix, or audit branch (e.g. `feat/new-pattern`, `fix/url-edge-case`).
   - Never commit directly to `main`.

---

## 🛠️ Local Development & Environment Setup

OSN Guard requires only **Node.js (v18, v20, or v22)**. No `npm install` step is required because there are zero external dependencies.

### 1. Clone the Repository
```bash
git clone https://github.com/RohanKhadke20/OSN_Extension.git
cd OSN_Extension
```

### 2. Verify Static Syntax
```bash
npm run check
```
*Validates syntax across all source, script, and test files using Node's built-in syntax checker.*

### 3. Run Automated Unit Tests
```bash
npm test
```
*Runs the 241 unit and integration tests across 55 test suites using Node's native test runner (`node --test`).*

### 4. Run Performance Benchmarks
```bash
npm run bench
```
*Ensures throughput performance budgets are satisfied (Scam classifier throughput >= 100k ops/sec).*

### 5. Build Distribution Packages
```bash
npm run pack:all
```
*Generates standalone zip packages in `dist/` for Google Chrome, Mozilla Firefox, and Apple Safari.*

---

## 🌐 Loading Unpacked Extensions in Browsers

### Chromium (Google Chrome, Microsoft Edge, Brave)
1. Open `chrome://extensions/` (or `edge://extensions/`).
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the repository root directory (`OSN_Extension`).

### Mozilla Firefox
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select `dist/manifest-firefox.json` or `manifest.json`.

### Apple Safari
1. Enable the **Develop** menu in Safari Settings -> Advanced.
2. Under Develop -> Allow Unsigned Extensions.
3. Use `dist/manifest-safari.json` with Safari Web Extension Converter.

---

## 📐 Coding Standards & Design Patterns

- **Dual-Environment Modules:** Core modules in `src/core/` must operate both in the browser (globals `globalThis.OSN*`) and in Node.js test environments (`module.exports`).
- **Data-Driven Rules:** When adding new threat patterns or domain rules, add them to `src/core/threat-config.js` rather than hardcoding them into analyzer modules.
- **Regex Safety:** Any regular expression added to PII or scam detectors must be tested against ReDoS vulnerabilities and avoid nested quantifiers (`(a+)+`).

---

## 🚀 Pull Request Workflow

1. **Create an Issue:** Open a GitHub Issue using our [Issue Templates](https://github.com/RohanKhadke20/OSN_Extension/issues/new/choose) to discuss proposed changes.
2. **Create a Dedicated Branch:**
   ```bash
   git checkout -b feat/your-feature-name
   ```
3. **Write Tests:** Add unit test coverage in `tests/` for any new detection rule, parser, or UI behavior.
4. **Run Verification Gate:**
   ```bash
   npm run check && npm test && npm run bench && npm run pack:all
   ```
5. **Submit PR:** Use our [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md) and ensure all verification checkboxes are marked.

---

## 🤝 Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 🔒 Security Vulnerabilities

Please do not disclose security vulnerabilities publicly in GitHub Issues. Follow the reporting instructions in our [Security Policy](SECURITY.md).
