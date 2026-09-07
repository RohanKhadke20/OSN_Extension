# Security Policy

## Supported Versions

Only the latest active release branch receives security patches and vulnerability mitigations.

| Version | Supported |
| --- | --- |
| 1.3.x | Yes |
| < 1.3.0 | No (End of Life) |

---

## Threat Model & Security Commitments

OSN Guard is designed under zero-trust, local-only client-side execution principles:

1. **Zero Outbound Network Requests**:
   The extension communicates with zero external analytics, telemetry, or remote heuristic services. All URL, PII, and scam classifications occur 100% locally on the device.

2. **Strict Content Security Policy (CSP)**:
   Declared explicitly in manifest.json:
   ```json
   "content_security_policy": {
     "extension_pages": "script-src 'self'; object-src 'self';"
   }
   ```
   Inline script execution and eval() are strictly prohibited.

3. **DOM-Based XSS Immunity**:
   Untrusted text and URL data from web pages are never injected using innerHTML. All badges, alerts, and tooltips are constructed using native DOM API methods (textContent, createElement, replaceChildren).

4. **Isolated Web Context**:
   Content scripts run in Chrome isolated world, preventing web page scripts from inspecting extension memory, storage tokens, or custom PII regex patterns.

---

## Reporting a Vulnerability

We take the security and privacy of our users seriously. If you identify a security vulnerability or privacy bypass in OSN Guard, please report it responsibly.

### How to Report

- **Contact**: Open a private GitHub Security Advisory or email security maintainers.
- **Include**:
  - Detailed description of the vulnerability and attack scenario.
  - Minimal reproducible example or proof-of-concept (PoC).
  - Browser name, version, and OS environment.
  - Expected vs. actual behavior.

### Response Time & SLA

- **Initial Acknowledgment**: Within 48 hours.
- **Triage & Severity Assessment**: Within 5 business days.
- **Remediation & Patch Release**: Critical vulnerabilities patched within 14 business days.

We kindly request that you refrain from publicly disclosing the issue until a fix has been released.
