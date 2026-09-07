const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrlSafety, isDomainWhitelisted } = require("../core/url-analyzer.js");

describe("URL Safety Analyzer", () => {
  it("recognizes safe domains and their subdomains", () => {
    const safeUrls = [
      "https://www.google.com/search?q=test",
      "https://sub.twitter.com/i/flow/signup",
      "https://x.com/explore",
      "https://github.com/torvalds/linux",
      "https://docs.github.com/en",
      "https://en.wikipedia.org/wiki/Main_Page",
      "https://m.facebook.com"
    ];

    for (const url of safeUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, true, `Expected ${url} to be safe`);
    }
  });

  it("identifies known malicious and phishing domains", () => {
    const maliciousUrls = [
      "http://login-verify-facebook.com/login.php",
      "https://security-alert-twitter.net/checkpoint",
      "http://pay-paypal-verify.com/account",
      "https://metamask-wallet-recovery.com/seed",
      "http://win-iphone-now.xyz"
    ];

    for (const url of maliciousUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected ${url} to be flagged as unsafe`);
      assert.equal(result.severity, "critical");
    }
  });

  it("detects IDN homograph / punycode spoofing", () => {
    const punycodeUrls = [
      "https://xn--pypal-4ve.com/signin",
      "https://sub.xn--apple-43a.com",
      "http://xn--microsoft-92a.xyz"
    ];

    for (const url of punycodeUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected ${url} to be flagged`);
      assert.equal(result.severity, "critical");
      assert.match(result.reason, /punycode/i);
    }
  });

  it("flags raw IP address hostnames including IPv4, IPv6, and dword formats", () => {
    const ipUrls = [
      "http://192.168.1.100/admin",
      "https://45.33.32.156/setup",
      "http://10.0.0.1",
      "http://[::1]/debug",
      "https://[2001:db8::1]/status",
      "http://2130706433/gateway"
    ];

    for (const url of ipUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected ${url} to be flagged for IP address`);
      assert.match(result.reason, /raw IP address/i);
    }
  });

  it("flags embedded credentials and userinfo in URL authority", () => {
    const spoofedUrls = [
      "https://google.com@phishing-target.com/login",
      "https://paypal.com:account-security@attacker-domain.org",
      "http://admin:pass@rogue-server.net"
    ];

    for (const url of spoofedUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected ${url} to be flagged for embedded credentials`);
      assert.equal(result.severity, "critical");
      assert.match(result.reason, /credentials/i);
    }
  });

  it("flags unencrypted HTTP protocol", () => {
    const httpUrl = "http://my-obscure-blog.org/article";
    const result = analyzeUrlSafety(httpUrl);
    assert.equal(result.safe, false);
    assert.equal(result.severity, "warning");
    assert.match(result.reason, /HTTP protocol/i);
  });

  it("flags suspicious TLDs including modern disposable domains", () => {
    const tldUrls = [
      "https://freeprizes.xyz",
      "https://crypto-claim.sbs",
      "https://fast-payout.cfd",
      "https://luxury-gift.beauty"
    ];

    for (const url of tldUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected ${url} to be flagged for suspicious TLD`);
      assert.match(result.reason, /suspicious low-cost TLD/i);
    }
  });

  it("flags combination of phishing keywords on unknown domains", () => {
    const phishUrl = "https://randomdomain123.com/account/verify/login";
    const result = analyzeUrlSafety(phishUrl);
    assert.equal(result.safe, false);
    assert.match(result.reason, /phishing keywords/i);
  });

  it("flags potential open redirect parameters pointing to external hosts", () => {
    const redirectUrl = "https://obscure-portal.org/login?redirect=https://evil-phish.com/harvest";
    const result = analyzeUrlSafety(redirectUrl);
    assert.equal(result.safe, false);
    assert.match(result.reason, /open redirect/i);
  });

  it("honors user whitelist properly", () => {
    const whitelist = ["custom-internal.xyz", "company-intranet.local", "*.partner-domain.cc"];

    // Normally .xyz is flagged, but whitelist should bypass
    const res1 = analyzeUrlSafety("https://custom-internal.xyz", whitelist);
    assert.equal(res1.safe, true);
    assert.match(res1.reason, /whitelist/i);

    // Subdomain on whitelisted domain
    const res2 = analyzeUrlSafety("https://portal.custom-internal.xyz/dashboard", whitelist);
    assert.equal(res2.safe, true);

    // Wildcard whitelist
    const res3 = analyzeUrlSafety("https://api.partner-domain.cc", whitelist);
    assert.equal(res3.safe, true);

    // Non-whitelisted should still be flagged
    const res4 = analyzeUrlSafety("https://other-domain.xyz", whitelist);
    assert.equal(res4.safe, false);
  });

  it("handles malformed or internal URLs gracefully", () => {
    assert.equal(analyzeUrlSafety("javascript:void(0)").safe, true);
    assert.equal(analyzeUrlSafety("#top").safe, true);
    assert.equal(analyzeUrlSafety("mailto:test@example.com").safe, true);
    assert.equal(analyzeUrlSafety("not-a-valid-url").safe, false);
    assert.equal(analyzeUrlSafety("").safe, false);
    assert.equal(analyzeUrlSafety(null).safe, false);
  });
});
