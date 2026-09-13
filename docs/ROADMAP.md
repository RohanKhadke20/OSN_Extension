# OSN Guard - Strategic Engineering Roadmap (v1.4 - v2.0)

**Document ID:** OSN-ROADMAP-002  
**Status:** Approved Architectural Blueprint  
**Maintainer:** Principal Software Architect & Browser Security Lead  
**Last Updated:** September 2026  

---

## 1. Vision & Core Tenets

OSN Guard is dedicated to delivering the fastest, most reliable, and completely private browser security shield in the world. As we progress from **v1.3.0** toward **v2.0.0**, all technical designs must adhere to four non-negotiable architectural tenets:

1. **Zero-Telemetry Guarantee:** No user data, visited URLs, inspected text, or telemetry packets may ever leave the user's device (`connect-src 'none'`).
2. **Deterministic & Auditable Heuristics:** Detection rules must be transparent, verifiable, and free from opaque remote inference dependencies.
3. **Sub-Millisecond Execution:** DOM inspection and PII validation must never cause visible frame drops (60 FPS minimum on infinite-scroll feeds).
4. **Zero Unaudited Runtime Dependencies:** No external third-party npm packages in production bundles; native browser and WebAssembly primitives only.

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 OSN Guard Evolution Path                │
                  └────────────────────────────┬────────────────────────────┘
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
       v1.4 (Q4 2026)                  v1.5 (Q1 2027)                  v1.6 (Q2 2027)
   Local Wasm Acceleration         Multi-Platform & Mobile         Enterprise Policy Sync
   - Wasm Levenshtein / SimHash    - Safari macOS / iOS / iPadOS   - chrome.storage.managed
   - Offline BarcodeDetector QR    - Firefox for Android           - IT Admin Whitelist Push
   - Sub-0.005 ms Link Matching    - Edge Add-ons Certification    - Tamper-Evident Auditing
               │                               │                               │
               └───────────────────────────────┼───────────────────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
       v1.7 (Q3 2027)                                                  v2.0 (Q4 2027)
   Global i18n & Regional PII                                      Declarative Zero-Trust
   - Aadhaar, PAN, SIN, NINO, Steuer-ID                            - Declarative Net Request (DNR)
   - Multilingual Scam Dictionaries                                - Download Magic-Byte Sniffing
   - chrome.i18n in 12 Locales                                     - Differential Privacy Aggregates
```

---

## 2. Release Milestones & Feature Specifications

### 🚀 Version 1.3.0 — Delivered Core Platform Milestones (September 2026)
**Delivered Capabilities:**
- **Micro-Quantized Scam Keyword Trie (`src/core/scam-analyzer.js`):**
  - Replaced sequential regex iteration with an Aho-Corasick multi-pattern trie automaton matching 216+ keywords in linear time `O(n + m)`.
  - Throughput benchmark exceeds 210,000 ops/sec.
- **Client-Side Quishing (QR Code Phishing) Visual Engine (`src/content/scanner.js`):**
  - Leverages native `BarcodeDetector` API for real-time QR extraction from post images without cloud upload.
  - Extracted destinations verified through `OSNUrlAnalyzer` offline.
- **Cross-Browser Compatibility Shim (`src/core/compat.js`):**
  - Unified `chrome.*` and `browser.*` namespaces with dual callback/Promise bridge, `storage.session` fallbacks, and internal URL routing.
- **Data-Driven Threat Configuration Engine (`src/core/threat-config.js`):**
  - Canonical `DEFAULT_THREAT_CONFIG` and factory patterns (`createUrlEngine`, `createPiiEngine`, `createScamEngine`).
- **Multi-Store Automated Zero-Bundler Release Pipeline (`scripts/pack.js`):**
  - Generates standalone distribution ZIPs for Chrome, Firefox AMO, and Safari in `dist/` using standard Node.js built-ins.
- **Enterprise Managed Policy Synchronization:**
  - Integrated `managed_schema.json` enabling IT administrators to enforce whitelists and mandatory PII rules via `chrome.storage.managed`.

---

### 🚀 Version 1.4 — Local WebAssembly (Wasm) Engine & Advanced Matchers
**Target Delivery:** Q4 2026  
**Primary Focus:** Performance Optimization & Advanced Multimodal Threat Extraction

- **High-Throughput WebAssembly Homoglyph & Edit Distance Matcher:**
  - Compile a lightweight, zero-dependency C/Rust string similarity library into a compact Wasm module (< 30 KB).
  - Implement SIMD-accelerated Levenshtein edit distance and Bitap fuzzy search against the top 10,000 global domain names.
  - Lower average domain comparison latency from `0.015 ms` to `< 0.003 ms` per anchor node.
- **Pure Wasm Offline QR Decoder Fallback:**
  - Compile a lightweight QR barcode reader to WebAssembly to provide fallback quishing decoding on browsers lacking native `BarcodeDetector` support (e.g. Firefox Gecko).

---

### 📱 Version 1.5 — Multi-Platform Ecosystem & Store Distribution
**Target Delivery:** Q1 2027  
**Primary Focus:** Store Distribution & Mobile Social Network Defense

- **Official Safari Extension for macOS, iOS & iPadOS:**
  - Package native macOS and iOS companion apps using Xcode Safari Web Extension Converter (`xcrun safari-web-extension-converter`).
  - Adapt popup UI to Apple Human Interface Guidelines (SF Pro typography, native liquid vibrancy, dark mode accent shifts).
  - Certify on the Apple App Store for Safari extension distribution.
- **Firefox for Android Support:**
  - Audit and tune DOM observers for mobile Gecko engines (`GeckoView`).
  - Optimize the touch hit-target dimensions in `popup.html` for mobile viewports (minimum 48x48 px touch targets).
- **Microsoft Edge Add-ons Certification:**
  - Publish official signed `.crx` packages to the Microsoft Partner Center for Edge Add-ons catalog availability.

---

### 🏢 Version 1.6 — Cryptographic Audit & Enterprise Diagnostics
**Target Delivery:** Q2 2027  
**Primary Focus:** Corporate Endpoints & Tamper-Evident Auditing

- **Cryptographically Sealed Audit Export:**
  - Enable one-click export of the local security event log, signed with a client-generated WebCrypto ECDSA key to provide tamper-evident compliance evidence during SOC 2 and ISO 27001 audits.
- **Silent Headless Self-Diagnostics:**
  - Implement a standardized diagnostics suite for enterprise IT helpdesks to confirm extension operational health without viewing user browsing histories.

---

### 🌐 Version 1.7 — Internationalized Heuristics & Regional PII Models
**Target Delivery:** Q3 2027  
**Primary Focus:** Global Linguistic Coverage & Regional Data Privacy Compliance

- **Expanded Regional PII Pattern Engine:**
  - **United Kingdom:** National Insurance Numbers (NINO) and National Health Service (NHS) 10-digit Mod-11 checksums.
  - **Canada:** Social Insurance Numbers (SIN) with Luhn algorithmic verification.
  - **Germany:** Steueridentifikationsnummer (Steuer-ID) with ISO 7064 Mod-11,10 check digits.
  - **India:** Aadhaar 12-digit Verhoeff algorithm verification and Permanent Account Number (PAN) syntax validation.
  - **Japan:** "My Number" Individual Identification Numbers with Mod-11 checksum.
  - **Australia:** Tax File Numbers (TFN) with weighted modulus-11 checks.
- **Multilingual Scam & Social Engineering Classifiers:**
  - Spanish, French, German, Japanese, Portuguese, and Simplified/Traditional Chinese dictionaries for romance scam redirection, fake delivery SMS lures, and urgent tax refund schemes.
- **Full UI Internationalization (`chrome.i18n`):**
  - Extract all hardcoded strings into `_locales/<lang>/messages.json`.
  - Provide complete translations for: English, Spanish, German, French, Japanese, Portuguese, Hindi, Korean, Italian, Dutch, Polish, and Ukrainian.

---

### 🛡️ Version 2.0 — Declarative Net Request (DNR) & Local Zero-Trust Sandbox
**Target Delivery:** Q4 2027  
**Primary Focus:** Deep Engine Hardening & Subresource Pre-Flight Blocking

- **Declarative Net Request (`chrome.declarativeNetRequest`) Migration:**
  - Transition from reactive DOM link analysis to proactive pre-flight network interception.
  - Compile known malicious domain blacklists into declarative static rulesets that block network connections at the browser socket level before TLS handshakes occur.
  - Maintain zero outbound requests while intercepting suspicious redirects and tracking beacons.
- **Download Magic-Byte File Sniffer:**
  - Implement pre-download inspection hooks (`chrome.downloads.onDeterminingFilename`) to inspect the first 64 bytes ("magic bytes") of downloaded files.
  - Detect dangerous file extension spoofing attacks (e.g., an executable PE binary disguised as `Invoice_2027.pdf` with disguised null-byte or double-extension tricks).
- **Client-Side Differential Privacy Aggregate Analytics (Strictly Opt-In):**
  - Allow privacy-conscious users to voluntarily contribute high-level aggregate metrics (e.g., number of threats intercepted per day across the community).
  - Utilize client-side local differential privacy (RAPPOR algorithm) with injected Gaussian noise to ensure zero personally identifiable data or visited URLs can ever be reconstructed.
  - Guaranteed `connect-src 'none'` remains the default for standard mode; opt-in features require explicit secondary user consent.

---

## 3. Engineering Metrics & Architectural Scorecard

| Milestone | Target Link Scan Latency | Max RAM Consumption | Test Coverage (Suites / Tests) | Supported Browser Engines |
| :--- | :--- | :--- | :--- | :--- |
| **v1.3 (Current)** | `< 0.02 ms` | `< 25 MB` | `25 Suites / 127 Tests` | Chromium MV3, Firefox Gecko |
| **v1.4 (Wasm)** | `< 0.005 ms` | `< 20 MB` | `28 Suites / 150 Tests` | Chromium MV3, Firefox Gecko |
| **v1.5 (Multi-Store)** | `< 0.005 ms` | `< 20 MB` | `32 Suites / 175 Tests` | Chromium, Firefox, Safari (macOS/iOS) |
| **v1.6 (Enterprise)** | `< 0.005 ms` | `< 22 MB` | `35 Suites / 200 Tests` | Chromium Managed, Edge Enterprise |
| **v1.7 (i18n)** | `< 0.006 ms` | `< 24 MB` | `40 Suites / 240 Tests` | All Supported Platforms |
| **v2.0 (Zero-Trust DNR)** | `< 0.002 ms` | `< 18 MB` | `50 Suites / 300+ Tests` | Full MV3 Standard Platforms |
