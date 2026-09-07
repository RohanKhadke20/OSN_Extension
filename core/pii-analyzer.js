/**
 * OSN Guard - PII Leak Detection Engine
 * Scans input text for sensitive personal data (emails, credit cards, phone numbers,
 * US SSNs, high-risk API keys, and custom user rules) before sharing online.
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.OSNPiiAnalyzer = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /**
   * Validates a numeric string against the Luhn algorithm (Mod 10)
   * @param {string} numStr - Digits only
   * @returns {boolean}
   */
  function luhnCheck(numStr) {
    if (!numStr || numStr.length < 2 || numStr.length > 30) {
      return false;
    }

    // Disallow all identical digits (e.g. 0000000000000000)
    if (/^(\d)\1+$/.test(numStr)) {
      return false;
    }

    let sum = 0;
    let shouldDouble = false;

    for (let i = numStr.length - 1; i >= 0; i--) {
      let digit = parseInt(numStr.charAt(i), 10);
      if (Number.isNaN(digit)) return false;

      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      shouldDouble = !shouldDouble;
    }

    return sum % 10 === 0;
  }

  /**
   * Validates if a string is a plausible US Social Security Number
   * @param {string} ssnStr - Format: XXX-XX-XXXX
   * @returns {boolean}
   */
  function isValidSSN(ssnStr) {
    const clean = ssnStr.replace(/\D/g, "");
    if (clean.length !== 9) return false;

    const area = parseInt(clean.substring(0, 3), 10);
    const group = parseInt(clean.substring(3, 5), 10);
    const serial = parseInt(clean.substring(5, 9), 10);

    // Area 000, 666, and 900-999 are invalid
    if (area === 0 || area === 666 || area >= 900) return false;
    // Group 00 is invalid
    if (group === 0) return false;
    // Serial 0000 is invalid
    if (serial === 0) return false;

    return true;
  }

  /**
   * Validates an International Bank Account Number (IBAN) using ISO 7064 Mod-97
   * @param {string} ibanStr - Raw IBAN string
   * @returns {boolean}
   */
  function isValidIBAN(ibanStr) {
    if (!ibanStr || typeof ibanStr !== "string") return false;
    const clean = ibanStr.replace(/[\s-]/g, "").toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(clean)) {
      return false;
    }
    // Rearrange: move country code and check digits to the end
    const rearranged = clean.slice(4) + clean.slice(0, 4);
    // Expand letters to digits (A=10, ..., Z=35)
    let numericStr = "";
    for (let i = 0; i < rearranged.length; i++) {
      const code = rearranged.charCodeAt(i);
      if (code >= 65 && code <= 90) {
        numericStr += (code - 55).toString();
      } else {
        numericStr += rearranged.charAt(i);
      }
    }
    // Piece-wise mod 97 to avoid 64-bit float precision errors
    let remainder = 0;
    for (let i = 0; i < numericStr.length; i += 7) {
      const chunk = remainder.toString() + numericStr.substring(i, i + 7);
      remainder = parseInt(chunk, 10) % 97;
    }
    return remainder === 1;
  }

  /**
   * Standard PII pattern definitions
   */
  const BUILTIN_PATTERNS = [
    {
      type: "email",
      name: "Email Address",
      severity: "warning",
      regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
    },
    {
      type: "creditCard",
      name: "Credit Card Info",
      severity: "critical",
      // Matches 13 to 19 digit card candidates with optional spaces or dashes
      regex: /\b(?:\d[ -]*?){13,19}\b/g,
      validate: (match) => {
        const cleanDigits = match.replace(/[\s-]/g, "");
        if (cleanDigits.length < 13 || cleanDigits.length > 19) return false;
        return luhnCheck(cleanDigits);
      }
    },
    {
      type: "iban",
      name: "Bank Account (IBAN)",
      severity: "critical",
      // Matches international IBAN structures with optional spaces/dashes
      regex: /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b/gi,
      validate: (match) => isValidIBAN(match)
    },
    {
      type: "ssn",
      name: "Social Security Number",
      severity: "critical",
      regex: /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g,
      validate: (match) => isValidSSN(match)
    },
    {
      type: "apiKey",
      name: "API Secret / Token",
      severity: "critical",
      // Detects OpenAI, Anthropic, GitHub classic & PAT, Stripe, Slack, Google API, AWS keys, and private keys
      regex: /\b(?:sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9-]{20,}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{60,95}|(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}|AIza[0-9A-Za-z\-_]{35}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)\b/g
    },
    {
      type: "phoneNumber",
      name: "Phone Number",
      severity: "warning",
      // Matches US & international phone formats: +1 (555) 123-4567, 555-123-4567, +44 20 7946 0958, +91 98765 43210, etc.
      regex: /(?:(?:\+|00)\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{4,5}\b/g,
      validate: (match) => {
        const digits = match.replace(/\D/g, "");
        // Avoid false positives for short digit sequences or all zeros
        if (digits.length < 10 || digits.length > 15) return false;
        if (/^(\d)\1+$/.test(digits)) return false;
        return true;
      }
    }
  ];

  /**
   * Analyzes text for personal identifiable information (PII) leaks
   * @param {string} text - User input string
   * @param {Array<{name: string, pattern: string, severity?: string}>} customPatterns - User defined rules
   * @returns {Array<{type: string, name: string, severity: "warning" | "critical", match: string}>}
   */
  function detectPii(text, customPatterns = []) {
    if (!text || typeof text !== "string" || text.trim().length < 5) {
      return [];
    }

    const detected = [];
    const seenMatches = new Set();

    // 1. Evaluate Built-in Patterns
    for (const rule of BUILTIN_PATTERNS) {
      // Reset regex state
      rule.regex.lastIndex = 0;
      const matches = text.match(rule.regex) || [];

      for (const rawMatch of matches) {
        const trimmedMatch = rawMatch.trim();
        if (seenMatches.has(trimmedMatch)) continue;

        // Skip sub-matches if already covered by an existing larger match (e.g. phone matched inside credit card)
        if (detected.some(d => d.match.includes(trimmedMatch))) continue;

        if (rule.validate && !rule.validate(trimmedMatch)) {
          continue;
        }

        seenMatches.add(trimmedMatch);
        detected.push({
          type: rule.type,
          name: rule.name,
          severity: rule.severity,
          match: trimmedMatch
        });
      }
    }

    // 2. Evaluate Custom User Patterns
    if (Array.isArray(customPatterns)) {
      customPatterns.forEach((cp, idx) => {
        if (!cp || !cp.pattern) return;

        try {
          const userRegex = new RegExp(cp.pattern, "g");
          const matches = text.match(userRegex) || [];

          for (const rawMatch of matches) {
            const trimmedMatch = rawMatch.trim();
            if (seenMatches.has(trimmedMatch)) continue;

            seenMatches.add(trimmedMatch);
            detected.push({
              type: `custom-${idx}`,
              name: cp.name || "Custom PII Mask",
              severity: cp.severity === "critical" ? "critical" : "warning",
              match: trimmedMatch
            });
          }
        } catch (err) {
          // Log or silently skip invalid user regex
          if (typeof console !== "undefined" && console.warn) {
            console.warn(`[OSN Guard] Invalid custom regex "${cp.pattern}":`, err.message);
          }
        }
      });
    }

    // Sort by severity (critical first)
    detected.sort((a, b) => (a.severity === "critical" ? -1 : 1));

    return detected;
  }

  return {
    detectPii,
    luhnCheck,
    isValidSSN,
    isValidIBAN,
    BUILTIN_PATTERNS
  };
});
