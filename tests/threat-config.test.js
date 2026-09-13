"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const ThreatConfig = require("../src/core/threat-config");
const { DEFAULT_THREAT_CONFIG, deepFreeze } = ThreatConfig;
const UrlAnalyzer = require("../src/core/url-analyzer");
const PiiAnalyzer = require("../src/core/pii-analyzer");
const ScamAnalyzer = require("../src/core/scam-analyzer");

describe("Threat Configuration Module (core/threat-config.js)", () => {
  it("exports a valid DEFAULT_THREAT_CONFIG with url, pii, and scam sections", () => {
    assert.ok(DEFAULT_THREAT_CONFIG);
    assert.ok(DEFAULT_THREAT_CONFIG.url);
    assert.ok(DEFAULT_THREAT_CONFIG.pii);
    assert.ok(DEFAULT_THREAT_CONFIG.scam);

    // URL config verification
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.safeDomains));
    assert.ok(DEFAULT_THREAT_CONFIG.url.safeDomains.includes("google.com"));
    assert.ok(DEFAULT_THREAT_CONFIG.url.safeDomains.includes("github.com"));
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.suspiciousDomains));
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.suspiciousTlds));
    assert.ok(DEFAULT_THREAT_CONFIG.url.suspiciousTlds.includes(".xyz"));
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.urlShorteners));
    assert.ok(DEFAULT_THREAT_CONFIG.url.urlShorteners.includes("bit.ly"));
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.phishingKeywords));
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.dangerousSchemes));
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.url.dangerousExtensions));
    assert.ok(DEFAULT_THREAT_CONFIG.url.thresholds);
    assert.equal(typeof DEFAULT_THREAT_CONFIG.url.thresholds.minPhishingKeywordMatches, "number");

    // PII config verification
    assert.ok(DEFAULT_THREAT_CONFIG.pii.thresholds);
    assert.equal(DEFAULT_THREAT_CONFIG.pii.thresholds.maxInputLength, 5000);
    assert.equal(DEFAULT_THREAT_CONFIG.pii.thresholds.lruCacheSize, 100);

    // Scam config verification
    assert.ok(Array.isArray(DEFAULT_THREAT_CONFIG.scam.rules));
    assert.ok(DEFAULT_THREAT_CONFIG.scam.rules.some(r => r.id === "crypto-scam"));
    assert.ok(DEFAULT_THREAT_CONFIG.scam.rules.some(r => r.id === "quishing-lure"));
  });

  it("ensures DEFAULT_THREAT_CONFIG is deeply frozen and immutable", () => {
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.url));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.url.safeDomains));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.url.thresholds));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.pii));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.pii.thresholds));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.scam));
    assert.ok(Object.isFrozen(DEFAULT_THREAT_CONFIG.scam.rules));

    assert.throws(() => {
      DEFAULT_THREAT_CONFIG.url.safeDomains.push("evil.com");
    }, TypeError);

    assert.throws(() => {
      DEFAULT_THREAT_CONFIG.url.thresholds.minPhishingKeywordMatches = 999;
    }, TypeError);
  });

  it("deepFreeze utility correctly freezes nested structures", () => {
    const mutableObj = {
      nested: {
        array: [1, 2, 3],
        val: "test"
      }
    };
    const frozen = deepFreeze(mutableObj);
    assert.ok(Object.isFrozen(frozen));
    assert.ok(Object.isFrozen(frozen.nested));
    assert.ok(Object.isFrozen(frozen.nested.array));
  });

  it("allows URL Analyzer to be instantiated with custom threat configuration", () => {
    const customConfig = {
      url: {
        safeDomains: ["custom-corp-portal.internal"],
        suspiciousDomains: ["bad-actor.example"],
        suspiciousTlds: [".fake"],
        urlShorteners: ["c.link"],
        phishingKeywords: ["secret-login"],
        dangerousSchemes: ["custom-scheme:"],
        dangerousExtensions: [".badext"],
        highRiskExtensions: [".badext"],
        openRedirectParams: ["goto_dest"],
        thresholds: {
          minPhishingKeywordMatches: 1,
          maxSubdomainDepth: 3,
          maxRedirectDepth: 1
        }
      }
    };

    const customUrlAnalyzer = UrlAnalyzer.create(customConfig);
    assert.ok(customUrlAnalyzer.isSafeDomain("custom-corp-portal.internal"));
    assert.equal(customUrlAnalyzer.isSafeDomain("google.com"), false); // Overridden

    const safetyResult = customUrlAnalyzer.analyzeUrlSafety("https://bad-actor.example/page");
    assert.equal(safetyResult.safe, false);
    assert.equal(safetyResult.severity, "critical");
  });

  it("allows Scam Analyzer to be instantiated with custom rules", () => {
    const customConfig = {
      scam: {
        rules: [
          {
            id: "corp-spoof",
            category: "Corporate Impersonation",
            severity: "critical",
            keywords: ["urgent ceo wire transfer"],
            reason: "Simulated BEC attack."
          }
        ]
      }
    };

    const customScamAnalyzer = ScamAnalyzer.create(customConfig);
    const result = customScamAnalyzer.detectScamContent("Please perform an urgent CEO wire transfer to our overseas vendor.");
    assert.equal(result.flagged, true);
    assert.equal(result.id, "corp-spoof");
    assert.equal(result.severity, "critical");

    // Standard crypto scam shouldn't match in this isolated instance
    const cryptoResult = customScamAnalyzer.detectScamContent("Send ETH to get double your bitcoin in our crypto giveaway!");
    assert.equal(cryptoResult.flagged, false);
  });

  it("allows PII Analyzer to be instantiated with custom thresholds", () => {
    const customConfig = {
      pii: {
        thresholds: {
          minTextLength: 20,
          lruCacheSize: 10
        }
      }
    };

    const customPiiAnalyzer = PiiAnalyzer.create(customConfig);
    // Short string less than 20 chars should be ignored
    const shortResult = customPiiAnalyzer.detectPii("test@example.com");
    assert.equal(shortResult.length, 0);

    // Longer string should be analyzed
    const longResult = customPiiAnalyzer.detectPii("Here is my primary email address test@example.com for communication.");
    assert.equal(longResult.length, 1);
    assert.equal(longResult[0].type, "email");
  });
});
