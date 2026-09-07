const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { isDomainWhitelisted, isSafeDomain } = require("../core/url-analyzer.js");
const { detectPii } = require("../core/pii-analyzer.js");

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
  });
});
