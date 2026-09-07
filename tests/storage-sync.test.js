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
});
