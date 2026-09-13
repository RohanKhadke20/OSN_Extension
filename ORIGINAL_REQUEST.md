# Original User Request

## Initial Request — 2026-09-13T03:33:15Z

Advance OSN Guard (`osn-safety-scanner`) from a single-browser tool into an adaptable, multi-target, self-verifying browser extension platform supporting Chromium Manifest V3, Firefox Gecko Event Pages, and Safari WebExtensions without compromising its zero-dependency, zero-network-egress (`connect-src 'none'`), and least-privilege security posture.

Working directory: `D:\Practice\osn-safety-scanner`
Integrity mode: demo

## Requirements

### R1. Cross-Browser Namespace Compatibility & Shim Architecture
- Provide a unified, dependency-free cross-browser compatibility shim (`chrome.*` vs `browser.*` namespace unification) across background, content, popup, and options scripts.
- Ensure the extension builds and packages cleanly for Chromium, Firefox, and Safari from a single unified source tree without introducing bundlers or external dependencies.
- Document the cross-browser compatibility model, API shim patterns, and manifest variance in `docs/COMPATIBILITY.md`.

### R2. Data-Driven Detection Engine Adaptability
- Decouple hardcoded threat rules, signatures, and thresholds in `core/url-analyzer.js`, `core/pii-analyzer.js`, and `core/scam-analyzer.js` into configurable, data-driven structures.
- Allow new threat patterns and threshold adjustments to be configured via data without requiring code changes, while preserving default detection behavior and sub-millisecond evaluation throughput.

### R3. Strict Non-Negotiable Security & Architectural Invariants
- Zero new runtime dependencies; use native modern JavaScript and browser APIs exclusively.
- Zero network egress (`connect-src 'none'`), zero telemetry beacons, zero remote scripts.
- Zero permission expansion beyond `{ storage, activeTab, contextMenus }` and existing managed schema.
- Dedicated branch `audit/teamwork-adaptability`; zero direct commits to `main`.
- Maintain all prior security and performance invariants: 10ms frame-budget DOM batching, service worker session storage reconciliation, ReDoS static validation, prototype-pollution defenses, and IPC sender verification.

### R4. Multi-Target Quality Verification & Auditor Review Matrix
- All changes must be backed by automated tests; run full static syntax checks, unit tests, and performance benchmarks for all targets.
- The Auditor must conduct a comprehensive static security pass on the final multi-target state (CSP, permissions, IPC validation, sanitization) and deliver a before/after audit status table covering Security, Reliability, Data Safety, Architecture, Testing, and Compatibility.

## Acceptance Criteria

### Build & Packaging Compliance
- [ ] `npm run check` passes with 0 syntax or lint errors across all source, script, and test files.
- [ ] `npm run pack:all` (or individual pack commands) generates valid, standalone packages for Chrome, Firefox, and Safari in `dist/`.
- [ ] Multi-browser manifests contain no unnecessary permissions or network privileges.

### Regression Safety & Performance
- [ ] 100% of existing unit tests (135+ tests across 27 suites) and E2E lifecycle tests (6 tests) pass without regression.
- [ ] New unit tests verify compatibility shim behavior across `chrome.*` and `browser.*` namespaces and data-driven rule configuration paths.
- [ ] `npm run bench` completes meeting all performance budgets (Scam classifier throughput >= 100k ops/sec).

### Deliverables & PR Readiness
- [ ] Dedicated PR branch `audit/teamwork-adaptability` is cleanly prepared with atomic, well-documented commits.
- [ ] `docs/COMPATIBILITY.md` is authored explaining the shim design, manifest differences, and lifecycle behavior across browsers.
- [ ] Auditor produces a final before/after comparison table embedded in the PR deliverable report.

## Follow-up — 2026-09-13T11:31:06Z

Establish and execute an ongoing, parallel research and documentation operation for OSN Guard (`osn-safety-scanner`) to maintain real-time security intelligence and zero-drift documentation.

Working directory: `D:\Practice\osn-safety-scanner`
Integrity mode: demo

## Requirements

### R1. Continuous Security & Dependency Research Subagent
- Track current best practices, WebExtensions MV3 standards across Chromium, Firefox Gecko, and Safari WebExtensions.
- Track security advisories, CVEs, and breaking changes for extension runtime APIs and platform specifications.
- Restrict web lookups strictly to verifying specific claims, APIs, or CVEs — zero speculative browsing.
- Always record precise citation metadata (source URL, retrieval timestamp, author/authority) and flag any findings that contradict existing repository assumptions or architectural invariants.

### R2. Single-Source-of-Truth Documentation Subagent
- Maintain the `/docs` directory as the authoritative reference: architecture overview, component interactions, setup instructions, API/function references, and an active `CHANGELOG.md`.
- Enforce zero-drift updates: whenever any code change is made, update corresponding documentation in the exact same commit/batch.
- Maintain `docs/DECISIONS.md` using lightweight Architecture Decision Record (ADR) format (Context, Decision, Consequences, Status) capturing *why* choices were made.

### R3. Multi-Role Coordination & Safety Guardrails
- Enforce Worker (research/authoring), Reviewer (accuracy & code-parity verification), Critic (staleness & redundancy prevention), and Auditor (security & privacy gatekeeper) roles.
- Work on dedicated feature/docs branches (e.g. `docs/continuous-ops`), never committing directly to `main`.
- Auditor gate: verify zero sensitive data (tokens, API keys, private endpoints, internal credentials) are committed to documentation.
- Mandatory checkpoint before restructuring the `/docs` directory layout or deleting any existing documentation file.

## Acceptance Criteria

### Research Intelligence Quality
- [ ] Research findings log citations with verifiable sources and ISO timestamps.
- [ ] Any identified breaking changes or CVEs are mapped directly to affected repository modules.

### Documentation Completeness & Parity
- [ ] `/docs` contains architecture overview, module references (`src/core/*`, `src/background/*`, `src/content/*`, `src/ui/*`), setup guidelines, and up-to-date `CHANGELOG.md`.
- [ ] `docs/DECISIONS.md` records all architectural decisions in structured ADR format.
- [ ] Documentation accurately reflects the recent `src/` modular reorganization and multi-browser compatibility shim.

### Security & Branching Compliance
- [ ] Zero secrets, private tokens, or internal credentials committed to documentation or docs logs.
- [ ] All research and documentation commits remain on a dedicated branch with atomic, topic-isolated commit messages.

