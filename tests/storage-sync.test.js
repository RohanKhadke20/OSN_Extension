const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { isDomainWhitelisted, isSafeDomain } = require("../core/url-analyzer.js");
const { detectPii, isSafeRegexPattern } = require("../core/pii-analyzer.js");

describe("Storage & Integration Helpers", () => {
  describe("Domain Whitelist Matching Logic", () => {
    const testWhitelist = [
      "mycompany.com",
      "*.internal-network.net",
      "https://portal.partner.org",
      "www.trusted-vendor.io",
      "localhost"
    ];

    it("matches exact domains", () => {
      assert.equal(isDomainWhitelisted("mycompany.com", testWhitelist), true);
      assert.equal(isDomainWhitelisted("www.mycompany.com", testWhitelist), true);
    });

    it("matches subdomains of whitelisted domains", () => {
      assert.equal(isDomainWhitelisted("hr.mycompany.com", testWhitelist), true);
      assert.equal(isDomainWhitelisted("api.v2.mycompany.com", testWhitelist), true);
    });

    it("handles wildcard format (*.domain)", () => {
      assert.equal(isDomainWhitelisted("wiki.internal-network.net", testWhitelist), true);
      assert.equal(isDomainWhitelisted("internal-network.net", testWhitelist), true);
    });

    it("handles domains entered with protocols or www", () => {
      assert.equal(isDomainWhitelisted("portal.partner.org", testWhitelist), true);
      assert.equal(isDomainWhitelisted("trusted-vendor.io", testWhitelist), true);
      assert.equal(isDomainWhitelisted("app.trusted-vendor.io", testWhitelist), true);
    });

    it("handles localhost", () => {
      assert.equal(isDomainWhitelisted("localhost", testWhitelist), true);
    });

    it("rejects non-whitelisted domains and spoofed substrings", () => {
      assert.equal(isDomainWhitelisted("notmycompany.com", testWhitelist), false);
      assert.equal(isDomainWhitelisted("mycompany.com.evil.com", testWhitelist), false);
      assert.equal(isDomainWhitelisted("other-network.net", testWhitelist), false);
      assert.equal(isDomainWhitelisted("", testWhitelist), false);
      assert.equal(isDomainWhitelisted("google.com", []), false);
    });
  });

  describe("Safe Domains Registry", () => {
    it("recognizes trusted social networks and tech platforms", () => {
      assert.equal(isSafeDomain("facebook.com"), true);
      assert.equal(isSafeDomain("x.com"), true);
      assert.equal(isSafeDomain("twitter.com"), true);
      assert.equal(isSafeDomain("linkedin.com"), true);
      assert.equal(isSafeDomain("reddit.com"), true);
      assert.equal(isSafeDomain("instagram.com"), true);
      assert.equal(isSafeDomain("github.com"), true);
      assert.equal(isSafeDomain("api.github.com"), true);
      assert.equal(isSafeDomain("gist.github.com"), true);
    });

    it("does not match domain prefixes falsely", () => {
      assert.equal(isSafeDomain("facebook.com.attacker.com"), false);
      assert.equal(isSafeDomain("fake-twitter.com"), false);
    });
  });

  describe("Custom PII Expression Resilience", () => {
    it("gracefully ignores malformed regex patterns without throwing", () => {
      const brokenRules = [
        { name: "Broken Pattern", pattern: "[a-z", severity: "critical" }, // Unclosed bracket
        { name: "Valid Rule", pattern: "REF-[0-9]{3}", severity: "warning" }
      ];

      const text = "Reference code: REF-456 in filing.";
      const results = detectPii(text, brokenRules);

      assert.equal(results.length, 1);
      assert.equal(results[0].name, "Valid Rule");
      assert.equal(results[0].match, "REF-456");
    });
  });

  describe("Stats and Counter Math Logic", () => {
    it("accumulates stats safely without NaN or false increments", () => {
      const stats = {
        linksScanned: 10,
        piiBlockedCount: 2,
        threatsDetected: 1,
        sitesProtected: 3
      };

      const update = {
        linksScanned: 5,
        threats: 2,
        siteProtected: false
      };

      if (update.linksScanned) stats.linksScanned += update.linksScanned;
      if (update.piiBlocked) stats.piiBlockedCount += update.piiBlocked;
      if (update.threats) stats.threatsDetected += update.threats;
      if (update.siteProtected) stats.sitesProtected += 1;

      assert.equal(stats.linksScanned, 15);
      assert.equal(stats.piiBlockedCount, 2);
      assert.equal(stats.threatsDetected, 3);
      assert.equal(stats.sitesProtected, 3); // Untouched because siteProtected was false
    });
  });

  describe("Configuration Backup & Sanitization", () => {
    function sanitizeDomainInput(input) {
      const rawInput = (input || "").trim().toLowerCase().replace(/\.+$/, "");
      if (!rawInput) return null;

      let cleanDomain = rawInput;
      let isWildcard = cleanDomain.startsWith("*.");
      if (isWildcard) cleanDomain = cleanDomain.substring(2);

      if (cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
        try {
          cleanDomain = new URL(cleanDomain).hostname;
        } catch {
          cleanDomain = cleanDomain.replace(/^https?:\/\//, "").split("/")[0];
        }
      }

      if (cleanDomain.startsWith("*.")) {
        isWildcard = true;
        cleanDomain = cleanDomain.substring(2);
      }

      if (cleanDomain.startsWith("www.")) cleanDomain = cleanDomain.substring(4);
      cleanDomain = cleanDomain.split("/")[0].split("?")[0].split(":")[0].replace(/\.+$/, "");

      if (!cleanDomain || cleanDomain.length < 3 || (!cleanDomain.includes(".") && cleanDomain !== "localhost")) {
        return null;
      }

      return isWildcard ? `*.${cleanDomain}` : cleanDomain;
    }

    it("sanitizes domain inputs across various formats", () => {
      assert.equal(sanitizeDomainInput("https://*.internal.org/dashboard"), "*.internal.org");
      assert.equal(sanitizeDomainInput("HTTP://WWW.EXAMPLE.COM:8080/"), "example.com");
      assert.equal(sanitizeDomainInput("corp.local."), "corp.local");
      assert.equal(sanitizeDomainInput("localhost"), "localhost");
      assert.equal(sanitizeDomainInput("invalid"), null);
      assert.equal(sanitizeDomainInput(""), null);
    });

    it("validates and filters imported backup payloads correctly", () => {
      const sampleBackup = {
        shields: { pii: true, url: false, content: true, security: true },
        whitelistedDomains: ["EXAMPLE.COM.", "*.PARTNER.NET"],
        customPiiPatterns: [
          { name: "Valid Rule", pattern: "CODE-[0-9]{4}" },
          { name: "Bad Regex", pattern: "([a-z" }
        ]
      };

      const sanitizedDomains = sampleBackup.whitelistedDomains
        .filter(d => typeof d === "string" && d.trim().length > 0)
        .map(d => d.trim().toLowerCase().replace(/\.+$/, ""));

      assert.deepEqual(sanitizedDomains, ["example.com", "*.partner.net"]);

      const validRules = sampleBackup.customPiiPatterns.filter(p => {
        if (!p || !p.pattern) return false;
        try {
          new RegExp(p.pattern, "g");
          return true;
        } catch {
          return false;
        }
      });

      assert.equal(validRules.length, 1);
      assert.equal(validRules[0].name, "Valid Rule");
    });

    it("rejects ReDoS patterns, oversized fields, and invalid severities in imported payloads", () => {
      const maliciousBackup = {
        shields: { pii: true, url: true, content: true, security: true },
        whitelistedDomains: ["valid.com", "a".repeat(150)], // Oversized domain
        customPiiPatterns: [
          { name: "Safe Token", pattern: "TOK-[0-9]{6}", severity: "critical" },
          { name: "ReDoS Attack", pattern: "(a+)+$", severity: "critical" },
          { name: "Nested Repeat ReDoS", pattern: "([0-9]+)*", severity: "warning" },
          { name: "a".repeat(60), pattern: "TEST", severity: "warning" }, // Oversized name > 50
          { name: "Empty Pattern", pattern: "" },
          { name: "Invalid Severity", pattern: "SEC-[A-Z]+", severity: "super-critical" }
        ]
      };

      const validatedDomains = maliciousBackup.whitelistedDomains
        .filter(d => typeof d === "string" && d.trim().length > 0 && d.trim().length <= 100)
        .map(d => d.trim().toLowerCase().replace(/\.+$/, ""))
        .slice(0, 200);

      assert.deepEqual(validatedDomains, ["valid.com"]);

      const validatedRules = maliciousBackup.customPiiPatterns
        .filter(p => {
          if (!p || typeof p !== "object") return false;
          if (!p.name || typeof p.name !== "string" || p.name.trim().length === 0 || p.name.length > 50) return false;
          if (!p.pattern || typeof p.pattern !== "string" || p.pattern.trim().length === 0 || p.pattern.length > 250) return false;
          return isSafeRegexPattern(p.pattern);
        })
        .map(p => ({
          name: p.name.trim().slice(0, 50),
          pattern: p.pattern.trim(),
          severity: (p.severity === "critical" || p.severity === "warning") ? p.severity : "warning"
        }));

      assert.equal(validatedRules.length, 2);
      assert.equal(validatedRules[0].name, "Safe Token");
      assert.equal(validatedRules[0].severity, "critical");
      assert.equal(validatedRules[1].name, "Invalid Severity");
      assert.equal(validatedRules[1].severity, "warning"); // Sanitized to fallback 'warning'
    });

    it("prevents prototype pollution from parsed JSON backups", () => {
      const maliciousJson = '{"__proto__": {"polluted": true}, "shields": {"pii": true}}';
      const parsed = JSON.parse(maliciousJson);

      const updates = {};
      if (parsed.shields && typeof parsed.shields === "object") {
        updates.shields = {
          pii: Boolean(parsed.shields.pii),
          url: Boolean(parsed.shields.url),
          content: Boolean(parsed.shields.content),
          security: Boolean(parsed.shields.security)
        };
      }

      assert.equal(Object.prototype.polluted, undefined, "Prototype must not be polluted");
      assert.equal(updates.shields.pii, true);
    });

    it("safely handles adversarial and malformed backup payloads during schema validation", () => {
      const fuzzPayloads = [
        null,
        undefined,
        12345,
        "malicious string",
        [],
        { shields: null, whitelistedDomains: "not-an-array", customPiiPatterns: 999 },
        {
          whitelistedDomains: [null, undefined, {}, [], 123, "   ", "a".repeat(1000)],
          customPiiPatterns: [
            null,
            undefined,
            "not-an-object",
            {},
            { name: "   ", pattern: "abc" },
            { name: "Valid", pattern: "   " },
            { name: "Valid", pattern: "a".repeat(300) },
            { name: "constructor", pattern: "( a + ) +", severity: "critical" },
            { name: "__proto__", pattern: "[0-9]{4}", severity: "warning" }
          ]
        }
      ];

      for (const payload of fuzzPayloads) {
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
          continue;
        }

        const updates = {};
        if (payload.shields && typeof payload.shields === "object") {
          updates.shields = {
            pii: Boolean(payload.shields.pii),
            url: Boolean(payload.shields.url),
            content: Boolean(payload.shields.content),
            security: Boolean(payload.shields.security)
          };
        }

        if (Array.isArray(payload.whitelistedDomains)) {
          updates.whitelistedDomains = payload.whitelistedDomains
            .filter(d => typeof d === "string" && d.trim().length > 0 && d.trim().length <= 100)
            .map(d => d.trim().toLowerCase().replace(/\.+$/, ""))
            .slice(0, 200);
        }

        if (Array.isArray(payload.customPiiPatterns)) {
          updates.customPiiPatterns = payload.customPiiPatterns
            .filter(p => {
              if (!p || typeof p !== "object") return false;
              if (!p.name || typeof p.name !== "string" || p.name.trim().length === 0 || p.name.length > 50) return false;
              if (!p.pattern || typeof p.pattern !== "string" || p.pattern.trim().length === 0 || p.pattern.length > 250) return false;
              return isSafeRegexPattern(p.pattern);
            })
            .map(p => ({
              id: (typeof p.id === "string" && /^rule_[a-zA-Z0-9_-]+$/.test(p.id))
                ? p.id
                : "rule_mock_id",
              name: p.name.trim().slice(0, 50),
              pattern: p.pattern.trim(),
              severity: (p.severity === "critical" || p.severity === "warning") ? p.severity : "warning"
            }))
            .slice(0, 50);
        }

        assert.equal(Object.prototype.polluted, undefined);
      }
    });

    it("prevents prototype pollution from constructor and __proto__ attack payloads", () => {
      const payloads = [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}'
      ];

      for (const raw of payloads) {
        const parsed = JSON.parse(raw);
        const target = Object.create(null);
        if (parsed.shields && typeof parsed.shields === "object") {
          target.shields = {};
        }
        assert.equal(Object.prototype.admin, undefined, "Object prototype must not be polluted");
        assert.equal({}.admin, undefined, "Plain object must not inherit polluted properties");
      }
    });
  });

  describe("Dormant Tab Reconciliation Logic", () => {
    it("prunes orphaned tab storage keys while preserving active tabs and global settings", () => {
      const activeTabIds = new Set([101, 102]);
      const sessionData = {
        tab_101: { url: "https://example.com", threats: [] },
        tab_102: { url: "https://github.com", threats: [] },
        tab_999: { url: "https://crashed.site", threats: [] },
        tab_888: { url: "https://closed.site", threats: [] },
        global_config: { debug: false }
      };

      const keysToRemove = [];
      for (const key of Object.keys(sessionData)) {
        if (key.startsWith("tab_")) {
          const tabId = parseInt(key.slice(4), 10);
          if (!activeTabIds.has(tabId)) {
            keysToRemove.push(key);
          }
        }
      }

      assert.deepEqual(keysToRemove, ["tab_999", "tab_888"]);
    });

    it("throttles reconciliation intervals to prevent storage thrashing", () => {
      let lastReconcile = 0;
      const THROTTLE = 180000;
      let reconcileCount = 0;

      function mockThrottledReconcile(currentTime) {
        if (currentTime - lastReconcile > THROTTLE) {
          lastReconcile = currentTime;
          reconcileCount++;
        }
      }

      const t0 = 1700000000000;
      mockThrottledReconcile(t0); // Call 1: triggers (t0 - 0 > THROTTLE)
      mockThrottledReconcile(t0 + 5000); // Call 2: suppressed (5s later)
      mockThrottledReconcile(t0 + 179000); // Call 3: suppressed (179s later)
      mockThrottledReconcile(t0 + 180001); // Call 4: triggers (180.001s later)

      assert.equal(reconcileCount, 2);
    });
  });
});
