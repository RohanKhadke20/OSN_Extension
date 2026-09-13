/**
 * OSN Guard - Scam & Fraud Content Analyzer
 * Analyzes social posts, direct messages, and interactive feeds for fraudulent patterns,
 * crypto drainers, credential phishing lures, and deceptive spam.
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    const defaultInstance = factory();
    module.exports = defaultInstance;
    module.exports.create = factory;
  } else {
    const defaultInstance = factory();
    root.OSNScamAnalyzer = defaultInstance;
    root.OSNScamAnalyzer.create = factory;
  }
})(typeof self !== "undefined" ? self : this, function (userConfig) {
  "use strict";

  // Resolve threat config: prefer userConfig.scam.rules, else OSNThreatConfig global / require fallback, else inline defaults
  let _threatConfigModule = null;
  if (typeof OSNThreatConfig !== "undefined") {
    _threatConfigModule = OSNThreatConfig;
  } else if (typeof require === "function") {
    try {
      _threatConfigModule = require("./threat-config");
    } catch (_) {}
  }

  const _defaults = (_threatConfigModule && _threatConfigModule.DEFAULT_THREAT_CONFIG)
    ? _threatConfigModule.DEFAULT_THREAT_CONFIG.scam
    : null;

  const _uc = (userConfig && typeof userConfig === "object" && userConfig.scam)
    ? userConfig.scam
    : {};

  // Build SCAM_RULES: convert pattern strings back to RegExp objects
  function _buildRules(rawRules) {
    return rawRules.map(function (r) {
      const rule = {
        id: r.id,
        category: r.category,
        severity: r.severity,
        keywords: Array.isArray(r.keywords) ? r.keywords.slice() : [],
        reason: r.reason
      };
      if (Array.isArray(r.patterns)) {
        rule.patterns = r.patterns.map(function (p) {
          return (p instanceof RegExp) ? p : new RegExp(p, "i");
        });
      }
      return rule;
    });
  }

  const SCAM_RULES = _buildRules(
    Array.isArray(_uc.rules) ? _uc.rules
      : (_defaults && Array.isArray(_defaults.rules) ? _defaults.rules : [])
  );

  // Inline default rules used only if both config sources are absent (bare require with no global)
  // (Rules sourced above from OSNThreatConfig or userConfig — no duplication needed here)

  const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u200E\u200F\uFEFF\u2060\u00AD\u202A-\u202E\u2066-\u2069]/g;


  /**
   * Fast Aho-Corasick Multi-Pattern Automaton for sub-millisecond keyword matching
   */
  function buildAhoCorasick(rules) {
    const root = { next: new Map(), fail: null, output: [] };
    if (!Array.isArray(rules) || rules.length === 0) return root;

    // 1. Build Trie
    for (const rule of rules) {
      if (!rule || !Array.isArray(rule.keywords)) continue;
      for (const kw of rule.keywords) {
        if (!kw || typeof kw !== "string") continue;
        const lowerKw = kw.toLowerCase();
        let curr = root;
        for (let i = 0; i < lowerKw.length; i++) {
          const ch = lowerKw[i];
          if (!curr.next.has(ch)) {
            curr.next.set(ch, { next: new Map(), fail: null, output: [] });
          }
          curr = curr.next.get(ch);
        }
        curr.output.push({ rule, keyword: kw });
      }
    }

    // 2. Build Failure Links using BFS
    const queue = [];
    for (const [, child] of root.next) {
      child.fail = root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const curr = queue.shift();

      for (const [ch, child] of curr.next) {
        let f = curr.fail;
        while (f && !f.next.has(ch)) {
          f = f.fail;
        }
        child.fail = f ? f.next.get(ch) : root;
        if (child.fail.output.length > 0) {
          child.output = child.output.concat(child.fail.output);
        }
        queue.push(child);
      }
    }

    return root;
  }

  /**
   * Searches text using precompiled Aho-Corasick automaton
   * @param {string} text - Lowercase text to search
   * @param {object} root - Automaton root
   * @returns {Array<{ rule: object, keyword: string }>}
   */
  function searchAhoCorasick(text, root) {
    const results = [];
    if (!text || typeof text !== "string" || !root || !root.next) {
      return results;
    }
    let curr = root;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      while (curr && !curr.next.has(ch)) {
        curr = curr.fail;
      }
      curr = curr ? curr.next.get(ch) : root;

      if (curr.output.length > 0) {
        for (let j = 0; j < curr.output.length; j++) {
          results.push(curr.output[j]);
        }
      }
    }

    return results;
  }

  // Precompile Aho-Corasick automaton once at module initialization
  const KEYWORD_AUTOMATON = buildAhoCorasick(SCAM_RULES);

  /**
   * Analyzes text content for scam, fraud, or phishing indicators
   * Detects hidden zero-width character evasion and prioritizes critical severity matches
   * @param {string} text - The post or message content
   * @returns {{ flagged: boolean, id?: string, category?: string, reason?: string, severity?: "warning" | "critical", matchedKeyword?: string, containsZeroWidth?: boolean, zeroWidthObfuscation?: boolean, allMatches?: Array<object> }}
   */
  function detectScamContent(text) {
    if (!text || typeof text !== "string" || text.trim().length < 8) {
      return { flagged: false };
    }

    const hasZeroWidth = ZERO_WIDTH_REGEX.test(text);
    const sanitizedText = hasZeroWidth ? text.replace(ZERO_WIDTH_REGEX, "") : text;
    const lowerRaw = text.toLowerCase();
    const lowerSanitized = hasZeroWidth ? sanitizedText.toLowerCase() : lowerRaw;

    const matchedRuleMap = new Map();

    // 1. High-speed multi-pattern Aho-Corasick keyword search
    const rawMatches = searchAhoCorasick(lowerRaw, KEYWORD_AUTOMATON);
    for (let i = 0; i < rawMatches.length; i++) {
      const m = rawMatches[i];
      if (!matchedRuleMap.has(m.rule.id)) {
        matchedRuleMap.set(m.rule.id, {
          rule: m.rule,
          matchedTerm: m.keyword,
          matchedViaSanitization: false
        });
      }
    }

    if (hasZeroWidth) {
      const sanitizedMatches = searchAhoCorasick(lowerSanitized, KEYWORD_AUTOMATON);
      for (let i = 0; i < sanitizedMatches.length; i++) {
        const m = sanitizedMatches[i];
        const existing = matchedRuleMap.get(m.rule.id);
        if (!existing) {
          matchedRuleMap.set(m.rule.id, {
            rule: m.rule,
            matchedTerm: m.keyword,
            matchedViaSanitization: true
          });
        } else if (!existing.matchedViaSanitization && m.keyword.length > existing.matchedTerm.length) {
          matchedRuleMap.set(m.rule.id, {
            rule: m.rule,
            matchedTerm: m.keyword,
            matchedViaSanitization: true
          });
        }
      }
    }

    // 2. Pattern check for rules with regex patterns (or rules not yet matched by keywords)
    for (let i = 0; i < SCAM_RULES.length; i++) {
      const rule = SCAM_RULES[i];
      if (matchedRuleMap.has(rule.id) || !rule.patterns) continue;

      for (let j = 0; j < rule.patterns.length; j++) {
        const pattern = rule.patterns[j];
        if (pattern.test(lowerRaw)) {
          matchedRuleMap.set(rule.id, {
            rule,
            matchedTerm: pattern.source,
            matchedViaSanitization: false
          });
          break;
        } else if (hasZeroWidth && pattern.test(lowerSanitized)) {
          matchedRuleMap.set(rule.id, {
            rule,
            matchedTerm: pattern.source,
            matchedViaSanitization: true
          });
          break;
        }
      }
    }

    if (matchedRuleMap.size === 0) {
      return { flagged: false };
    }

    const matches = [];
    for (const [, item] of matchedRuleMap) {
      matches.push({
        flagged: true,
        id: item.rule.id,
        category: item.rule.category,
        reason: item.rule.reason,
        severity: item.rule.severity,
        matchedKeyword: item.matchedTerm,
        containsZeroWidth: hasZeroWidth,
        zeroWidthObfuscation: item.matchedViaSanitization
      });
    }

    // Always surface critical threats first
    const topThreat = matches.find(m => m.severity === "critical") || matches[0];
    return {
      ...topThreat,
      containsZeroWidth: hasZeroWidth,
      zeroWidthObfuscation: matches.some(m => m.zeroWidthObfuscation),
      allMatches: matches
    };
  }

  return {
    detectScamContent,
    SCAM_RULES,
    ZERO_WIDTH_REGEX,
    buildAhoCorasick,
    searchAhoCorasick
  };
});

