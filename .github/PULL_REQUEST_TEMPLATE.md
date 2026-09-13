## Description

Please provide a concise description of the changes in this pull request and the rationale behind them.

Closes #(issue)

---

## Type of Change

- [ ] 🐛 Bug fix (non-breaking fix for an issue)
- [ ] 💡 New detection rule / heuristic enhancement
- [ ] ⚡ Performance optimization (latency / throughput improvement)
- [ ] 🌐 Cross-browser compatibility improvement (Chrome, Firefox, Safari)
- [ ] 📝 Documentation update / sync
- [ ] 🧪 Testing enhancement (unit / e2e / bench)

---

## 🔒 Security & Architectural Invariants Verification

All pull requests must strictly satisfy these core invariants:

- [ ] **Zero New Runtime Dependencies:** No new npm packages added to `package.json`.
- [ ] **Zero Network Egress:** Manifest Content Security Policy strictly preserves `connect-src 'none'`.
- [ ] **Least Privilege Permissions:** Permissions strictly confined to `{ storage, activeTab, contextMenus }` with `host_permissions: none`.
- [ ] **DOM XSS Immunity:** Uses native DOM APIs (`textContent`, `replaceChildren`) with zero `innerHTML` / `eval()`.
- [ ] **Prototype Pollution Guard:** Object utilities and backup parsers guard against `__proto__`, `constructor`, and `prototype`.
- [ ] **Dedicated Branch:** PR branch is branched from `main` (never committed directly to `main`).

---

## 🧪 Quality Verification Checklist

Please run and confirm all local verification suites pass:

- [ ] `npm run check` (0 syntax errors across all files)
- [ ] `npm test` (241/241 automated unit & integration tests passing across 55 suites)
- [ ] `npm run test:e2e` (6/6 headless browser tests passing)
- [ ] `npm run bench` (Scam classifier throughput >= 100k ops/sec)
- [ ] `npm run pack:all` (Chrome, Firefox, and Safari packages generated cleanly in `dist/`)
- [ ] Documentation updated in the exact same commit if public interfaces or options changed (`README.md`, `docs/*`, `CHANGELOG.md`)

---

## Additional Notes

Add any additional context, benchmarks, or browser-specific testing notes here.
