const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  analyzeUrlSafety,
  isDomainWhitelisted,
  isRawIpAddress,
  hasMixedScriptConfusables,
  isUrlShortener,
  getDangerousFileExtension,
  SHORTENER_DOMAINS,
  DANGEROUS_FILE_EXTENSIONS,
  HIGH_RISK_EXECUTABLE_EXTS
} = require("../core/url-analyzer.js");

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

  it("flags raw IP address hostnames including IPv4, IPv6, octal, hex, and dword formats", () => {
    const ipUrls = [
      "http://192.168.1.100/admin",
      "https://45.33.32.156/setup",
      "http://10.0.0.1",
      "http://[::1]/debug",
      "https://[2001:db8::1]/status",
      "http://2130706433/gateway",
      "http://0177.0.0.1/admin",
      "http://0x7f.0.0.1/console",
      "http://0x7f.0x0.0x0.0x1/test",
      "http://0x7f000001/status",
      "http://127.1/debug"
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

  it("supports developer ports and private intranet subnet wildcards in whitelist", () => {
    const devWhitelist = [
      "localhost:3000",
      "127.0.0.1:8080",
      "192.168.*",
      "10.*",
      "*.internal.corp:5173"
    ];

    // Exact host and port matches
    assert.equal(isDomainWhitelisted("localhost:3000", devWhitelist), true);
    assert.equal(isDomainWhitelisted("127.0.0.1:8080", devWhitelist), true);

    // Different port on same host does not match port-specific entry
    assert.equal(isDomainWhitelisted("localhost:9000", devWhitelist), false);
    assert.equal(isDomainWhitelisted("127.0.0.1:3000", devWhitelist), false);

    // Private subnet prefixes match any IP within that range
    assert.equal(isDomainWhitelisted("192.168.1.1", devWhitelist), true);
    assert.equal(isDomainWhitelisted("192.168.0.254:8000", devWhitelist), true);
    assert.equal(isDomainWhitelisted("10.0.0.15", devWhitelist), true);
    assert.equal(isDomainWhitelisted("10.255.4.1:443", devWhitelist), true);

    // Other private ranges not in whitelist do not match
    assert.equal(isDomainWhitelisted("172.16.0.1", devWhitelist), false);
    assert.equal(isDomainWhitelisted("8.8.8.8", devWhitelist), false);

    // Wildcard subdomain with port
    assert.equal(isDomainWhitelisted("dev.internal.corp:5173", devWhitelist), true);
    assert.equal(isDomainWhitelisted("dev.internal.corp:3000", devWhitelist), false);

    // End-to-end analyzeUrlSafety check with dev port
    const urlCheck1 = analyzeUrlSafety("http://localhost:3000/api/status", devWhitelist);
    assert.equal(urlCheck1.safe, true);
    assert.match(urlCheck1.reason, /whitelist/i);

    const subnetCheck = analyzeUrlSafety("http://192.168.1.55:8080/dashboard", devWhitelist);
    assert.equal(subnetCheck.safe, true);
    assert.match(subnetCheck.reason, /whitelist/i);
  });

  it("handles malformed or internal URLs gracefully", () => {
    assert.equal(analyzeUrlSafety("javascript:void(0)").safe, true);
    assert.equal(analyzeUrlSafety("#top").safe, true);
    assert.equal(analyzeUrlSafety("mailto:test@example.com").safe, true);
    assert.equal(analyzeUrlSafety("not-a-valid-url").safe, false);
    assert.equal(analyzeUrlSafety("").safe, false);
    assert.equal(analyzeUrlSafety(null).safe, false);
  });

  it("blocks dangerous schemes including data:, blob:, file:, and filesystem:", () => {
    const dangerousUrls = [
      "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      "data:application/javascript;base64,dmFyIGE9MTs=",
      "blob:https://evil-site.com/d94943f2-1b1d-405a-8b1b-7a2e2f9d3b4c",
      "file:///etc/passwd",
      "file:///C:/Windows/System32/calc.exe",
      "filesystem:http://example.com/temporary/payload.html"
    ];

    for (const url of dangerousUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected ${url} to be blocked as dangerous`);
      assert.equal(result.severity, "critical");
      assert.match(result.reason, /dangerous uri scheme/i);
    }
  });

  it("inspects open redirects on safe platforms and flags malicious destinations as critical", () => {
    // Trusted domain redirecting to known malicious domain -> critical
    const googlePhish = analyzeUrlSafety("https://www.google.com/url?q=https://win-iphone-now.xyz");
    assert.equal(googlePhish.safe, false);
    assert.equal(googlePhish.severity, "critical");
    assert.match(googlePhish.reason, /unsafe destination/i);

    // Facebook link shim redirecting to known crypto scam -> critical
    const fbPhish = analyzeUrlSafety("https://l.facebook.com/l.php?u=https://metamask-wallet-recovery.com");
    assert.equal(fbPhish.safe, false);
    assert.equal(fbPhish.severity, "critical");
    assert.match(fbPhish.reason, /unsafe destination/i);

    // YouTube redirect to punycode homograph -> critical
    const ytHomograph = analyzeUrlSafety("https://www.youtube.com/redirect?q=https://xn--pypal-4ve.com");
    assert.equal(ytHomograph.safe, false);
    assert.equal(ytHomograph.severity, "critical");

    // Safe platform redirecting to another safe platform -> safe
    const googleWiki = analyzeUrlSafety("https://www.google.com/url?q=https://en.wikipedia.org/wiki/Phishing");
    assert.equal(googleWiki.safe, true);

    // Internal redirect within same safe platform -> safe
    const googleInternal = analyzeUrlSafety("https://www.google.com/url?q=https://mail.google.com/inbox");
    assert.equal(googleInternal.safe, true);

    // Safe platform redirecting to unverified external domain -> warning
    const googleExternal = analyzeUrlSafety("https://www.google.com/url?q=https://some-normal-blog.com/post");
    assert.equal(googleExternal.safe, false);
    assert.equal(googleExternal.severity, "warning");
    assert.match(googleExternal.reason, /external unverified destination/i);

    // Google search query with search string should remain safe
    const googleSearch = analyzeUrlSafety("https://www.google.com/search?q=https+basics");
    assert.equal(googleSearch.safe, true);
  });

  it("handles FQDN with trailing dots gracefully", () => {
    const trailingDotSafe = analyzeUrlSafety("https://www.google.com./webhp");
    assert.equal(trailingDotSafe.safe, true);

    const whitelist = ["my-corp.com"];
    const trailingDotWhitelist = analyzeUrlSafety("https://portal.my-corp.com./login", whitelist);
    assert.equal(trailingDotWhitelist.safe, true);
  });

  it("detects mixed-script confusable homoglyph domain attacks", () => {
    // Cyrillic 'о' (\u043E) mixed with Latin 'g', 'g', 'l', 'e'
    const cyrillicSpoof = "https://g\u043E\u043Egle.com/login";
    const res1 = analyzeUrlSafety(cyrillicSpoof);
    assert.equal(res1.safe, false, "Expected Cyrillic spoofed domain to be flagged");
    assert.equal(res1.severity, "critical");
    assert.match(res1.reason, /punycode|homograph|confusable/i);

    // Greek 'α' (\u03B1) mixed with Latin 'p', 'y', 'p', 'a', 'l'
    const greekSpoof = "https://p\u03B1ypal.com/verify";
    const res2 = analyzeUrlSafety(greekSpoof);
    assert.equal(res2.safe, false, "Expected Greek spoofed domain to be flagged");
    assert.equal(res2.severity, "critical");
    assert.match(res2.reason, /punycode|homograph|confusable/i);

    // Benign query parameters containing non-Latin scripts on safe domains must remain safe
    const benignSearch = "https://www.google.com/search?q=\u043F\u0440\u0438\u0432\u0435\u0442";
    const res3 = analyzeUrlSafety(benignSearch);
    assert.equal(res3.safe, true, "Benign non-Latin search query on safe domain should be safe");

    const benignWiki = "https://en.wikipedia.org/wiki/\u041F\u0440\u0438\u0432\u0435\u0442";
    const res4 = analyzeUrlSafety(benignWiki);
    assert.equal(res4.safe, true, "Benign non-Latin path on safe domain should be safe");
  });

  it("identifies URL shorteners and flags destination obscurity", () => {
    const pureShortenerUrls = [
      "https://bit.ly/3xY123",
      "https://tinyurl.com/abc789",
      "https://t.ly/xyz99",
      "https://is.gd/photo42",
      "https://cutt.ly/blog-post"
    ];

    for (const url of pureShortenerUrls) {
      const result = analyzeUrlSafety(url);
      assert.equal(result.safe, false, `Expected shortener ${url} to be flagged`);
      assert.equal(result.severity, "warning");
      assert.match(result.reason, /URL shortener detected/i);
    }

    // Shortener combined with multiple phishing keywords escalates to critical
    const phishShortener = analyzeUrlSafety("https://tinyurl.com/account-verify");
    assert.equal(phishShortener.safe, false);
    assert.equal(phishShortener.severity, "critical");
    assert.match(phishShortener.reason, /phishing keywords/i);
    assert.match(phishShortener.reason, /URL shortener detected/i);

    // Whitelisted shortener domain should be permitted
    const whitelistedResult = analyzeUrlSafety("https://bit.ly/internal-docs", ["bit.ly"]);
    assert.equal(whitelistedResult.safe, true);

    // Shortener with unencrypted HTTP should escalate to critical (two heuristics: HTTP + shortener)
    const httpShortener = analyzeUrlSafety("http://bit.ly/3xY123");
    assert.equal(httpShortener.safe, false);
    assert.equal(httpShortener.severity, "critical");
  });

  it("verifies direct helper functions isRawIpAddress, hasMixedScriptConfusables, and isUrlShortener", () => {
    // isRawIpAddress
    assert.equal(isRawIpAddress("127.0.0.1"), true);
    assert.equal(isRawIpAddress("192.168.1.1"), true);
    assert.equal(isRawIpAddress("[::1]"), true);
    assert.equal(isRawIpAddress("::1"), true);
    assert.equal(isRawIpAddress("2001:db8::1"), true);
    assert.equal(isRawIpAddress("0177.0.0.1"), true);
    assert.equal(isRawIpAddress("0x7f.0.0.1"), true);
    assert.equal(isRawIpAddress("0x7f000001"), true);
    assert.equal(isRawIpAddress("2130706433"), true);
    assert.equal(isRawIpAddress("127.1"), true);
    assert.equal(isRawIpAddress("google.com"), false);
    assert.equal(isRawIpAddress("sub.example.org"), false);

    // hasMixedScriptConfusables
    assert.equal(hasMixedScriptConfusables("google.com"), false);
    assert.equal(hasMixedScriptConfusables("g\u043E\u043Egle.com"), true);
    assert.equal(hasMixedScriptConfusables("p\u03B1ypal.com"), true);
    assert.equal(hasMixedScriptConfusables("\u044F\u043D\u0434\u0435\u043A\u0441.\u0440\u0444"), false); // pure Cyrillic

    // isUrlShortener
    assert.equal(isUrlShortener("bit.ly"), true);
    assert.equal(isUrlShortener("www.bit.ly"), true);
    assert.equal(isUrlShortener("tinyurl.com"), true);
    assert.equal(isUrlShortener("sub.tinyurl.com"), true);
    assert.equal(isUrlShortener("google.com"), false);
    assert.equal(isUrlShortener("github.com"), false);
    assert.equal(SHORTENER_DOMAINS.has("bit.ly"), true);
  });

  it("detects dangerous executable and script download links on untrusted domains", () => {
    // Untrusted standalone executable (.exe, .msi, .iso, .apk) triggers warning
    const exeResult = analyzeUrlSafety("https://untrusted-software-host.org/download/client_setup.exe");
    assert.equal(exeResult.safe, false);
    assert.equal(exeResult.severity, "warning");
    assert.match(exeResult.reason, /dangerous executable or script file \(\.exe\)/i);

    const msiResult = analyzeUrlSafety("https://external-unknown-site.net/patches/update.msi");
    assert.equal(msiResult.safe, false);
    assert.equal(msiResult.severity, "warning");
    assert.match(msiResult.reason, /dangerous executable or script file \(\.msi\)/i);

    // High-risk script droppers (.scr, .vbs, .bat, .hta, .ps1) escalate to critical
    const scrResult = analyzeUrlSafety("https://unknown-host.org/screensaver.scr");
    assert.equal(scrResult.safe, false);
    assert.equal(scrResult.severity, "critical");
    assert.match(scrResult.reason, /dangerous executable or script file \(\.scr\)/i);

    const vbsResult = analyzeUrlSafety("https://unknown-host.org/run.vbs");
    assert.equal(vbsResult.safe, false);
    assert.equal(vbsResult.severity, "critical");

    const batResult = analyzeUrlSafety("https://unknown-host.org/tools/cleaner.bat");
    assert.equal(batResult.safe, false);
    assert.equal(batResult.severity, "critical");

    // Unencrypted HTTP + executable download has 2 heuristics -> critical
    const httpExeResult = analyzeUrlSafety("http://untrusted-software-host.org/download/client_setup.exe");
    assert.equal(httpExeResult.safe, false);
    assert.equal(httpExeResult.severity, "critical");

    // Query parameter download filename detection
    const queryDownload = analyzeUrlSafety("https://unknown-site.org/get-file?download=malicious-payload.hta");
    assert.equal(queryDownload.safe, false);
    assert.equal(queryDownload.severity, "critical");
    assert.match(queryDownload.reason, /dangerous executable or script file \(\.hta\)/i);

    // Safe domains with executables should be permitted without false positives
    const githubExe = analyzeUrlSafety("https://github.com/microsoft/terminal/releases/download/v1.0/Setup.msi");
    assert.equal(githubExe.safe, true);
    assert.match(githubExe.reason, /secure domain/i);

    // Whitelisted domains with executables should be permitted
    const whitelistedExe = analyzeUrlSafety("https://internal-repo.xyz/app.exe", ["internal-repo.xyz"]);
    assert.equal(whitelistedExe.safe, true);
    assert.match(whitelistedExe.reason, /whitelist/i);

    // Benign file types (.pdf, .jpg, .png, .html) on unknown domains should not trigger executable heuristic
    const pdfResult = analyzeUrlSafety("https://unknown-site.org/whitepaper.pdf");
    assert.equal(pdfResult.safe, true);

    const imgResult = analyzeUrlSafety("https://unknown-site.org/avatar.png");
    assert.equal(imgResult.safe, true);

    // getDangerousFileExtension helper checks
    assert.equal(getDangerousFileExtension(new URL("https://example.com/file.exe")), ".exe");
    assert.equal(getDangerousFileExtension(new URL("https://example.com/file.scr")), ".scr");
    assert.equal(getDangerousFileExtension(new URL("https://example.com/file.pdf")), null);
    assert.equal(getDangerousFileExtension(new URL("https://example.com/dl?item=payload.ps1")), ".ps1");
    assert.equal(DANGEROUS_FILE_EXTENSIONS.has(".exe"), true);
    assert.equal(HIGH_RISK_EXECUTABLE_EXTS.has(".scr"), true);
    assert.equal(HIGH_RISK_EXECUTABLE_EXTS.has(".exe"), false);
  });
});
