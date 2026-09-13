# E2E Test Infra: OSN Guard Multi-Target Platform

## Test Philosophy
- Opaque-box, requirement-driven, derived strictly from `ORIGINAL_REQUEST.md`.
- Zero runtime dependencies; utilizes native `node:test`, `node:assert`, and Node.js built-ins.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Interaction Testing + Real-World Workload Simulation.
- Progressive testability: Tests verify public interfaces and browser behaviors without coupling to internal private state.

## Feature Inventory
| # | Feature | Source (requirement) | Tier 1 | Tier 2 | Tier 3 |
|---|---------|---------------------|:------:|:------:|:------:|
| F1 | Cross-Browser Namespace Shim (`core/compat.js`) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| F2 | Storage Session & Managed Fallbacks | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| F3 | UI & Browser Lifecycle Normalization | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| F4 | Data-Driven URL Safety Engine | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| F5 | Data-Driven Scam Classifier | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| F6 | Data-Driven PII Detection Engine | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| F7 | Multi-Target Build & Manifest Variance | ORIGINAL_REQUEST §R1, §R3 | 5 | 5 | ✓ |
| F8 | Cross-Browser Documentation | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |

## Test Architecture
- **Test Runners**:
  - Unit & Integration: `node --test tests/*.test.js`
  - Lifecycle & Headless E2E: `node --test tests/e2e/*.test.js`
  - Syntax & Type Check: `node --check ...` (`npm run check`)
  - Throughput Benchmark: `node scripts/bench.js` (`npm run bench`)
  - Target Packaging: `node scripts/pack.js --target=all` (`npm run pack:all`)
- **Test File Layout**:
  - `tests/compat.test.js`: Shim namespace unification, callback/Promise duality, storage/action polyfills.
  - `tests/data-driven.test.js`: Custom rules, thresholds, ReDoS safety, throughput under custom configs.
  - `tests/pack.test.js`: Zip integrity, manifest variance across Chrome, Firefox, Safari.
  - `tests/e2e/*.test.js`: Real browser DOM scanning and threat mitigation.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Multi-Browser Navigation & Scan Simulation: Load mock page in simulated Firefox and Safari environments with unified shim. | F1, F2, F3 | High |
| 2 | Enterprise Managed Policy Injection: Custom whitelists and PII patterns pushed via managed storage and evaluated by data-driven engines. | F2, F4, F6 | High |
| 3 | Evasive Scam Detection: High-volume social media feed with mixed zero-width evasion and novel phishing lures tested against custom Aho-Corasick rules. | F5, F6 | High |
| 4 | Multi-Target Packaging Verification: Build Chrome, Firefox, Safari packages and verify manifest schema validity, permission invariants, and script load order. | F1, F7 | Medium |
| 5 | Live Benchmark & Frame Budget Stress: Sustained throughput benchmark confirming Scam Classifier exceeds 100k ops/sec and link batching remains within 10ms frame budget. | F4, F5 | High |

## Coverage Thresholds
- Tier 1: ≥5 per feature (Total ≥ 40 tests)
- Tier 2: ≥5 per feature boundary cases (Total ≥ 40 tests)
- Tier 3: Pairwise combinations across shim, engine configurations, and storage fallbacks (Total ≥ 10 tests)
- Tier 4: ≥5 realistic end-to-end workload scenarios
