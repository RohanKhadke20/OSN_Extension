const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  detectPii,
  maskPii,
  luhnCheck,
  isValidSSN,
  isValidIBAN,
  getCompiledCustomRegex,
  clearCustomRegexCache,
  getCustomRegexCacheSize,
  isSafeRegexPattern
} = require("../core/pii-analyzer.js");

describe("PII Leak Detector", () => {
  describe("Luhn algorithm check", () => {
    it("validates authentic test card numbers", () => {
      // Standard Luhn test numbers
      assert.equal(luhnCheck("49927398716"), true);
      assert.equal(luhnCheck("4111111111111111"), true);
    });

    it("rejects invalid card numbers and all-zero sequences", () => {
      assert.equal(luhnCheck("49927398717"), false);
      assert.equal(luhnCheck("0000000000000000"), false);
      assert.equal(luhnCheck("1111111111111111"), false);
      assert.equal(luhnCheck("12345"), false);
    });
  });

  describe("SSN validation", () => {
    it("validates properly structured SSNs", () => {
      assert.equal(isValidSSN("123-45-6789"), true);
      assert.equal(isValidSSN("219-09-9999"), true);
    });

    it("rejects invalid area/group/serial SSNs", () => {
      assert.equal(isValidSSN("000-12-3456"), false);
      assert.equal(isValidSSN("666-12-3456"), false);
      assert.equal(isValidSSN("900-12-3456"), false);
      assert.equal(isValidSSN("123-00-3456"), false);
      assert.equal(isValidSSN("123-45-0000"), false);
    });
  });

  describe("IBAN validation", () => {
    it("validates authentic international IBANs", () => {
      // Standard valid IBANs from various nations
      assert.equal(isValidIBAN("DE89370400440532013000"), true);
      assert.equal(isValidIBAN("GB82 WEST 1234 5698 7654 32"), true);
      assert.equal(isValidIBAN("FR14 2004 1010 0505 0001 3M02 606"), true);
    });

    it("rejects invalid checksums, lengths, and formats", () => {
      assert.equal(isValidIBAN("DE89370400440532013001"), false); // Wrong check digits
      assert.equal(isValidIBAN("GB00 WEST 1234 5698 7654 32"), false);
      assert.equal(isValidIBAN("1234567890"), false);
      assert.equal(isValidIBAN(""), false);
      assert.equal(isValidIBAN(null), false);
    });
  });

  describe("PII detection in free text", () => {
    it("detects email addresses", () => {
      const text = "Please email me at john.doe@company.org for details.";
      const results = detectPii(text);
      assert.equal(results.length, 1);
      assert.equal(results[0].type, "email");
      assert.equal(results[0].match, "john.doe@company.org");
      assert.equal(results[0].severity, "warning");
    });

    it("detects credit cards with Luhn verification", () => {
      const text = "My card number is 4111 1111 1111 1111, please charge it.";
      const results = detectPii(text);
      assert.equal(results.length, 1);
      assert.equal(results[0].type, "creditCard");
      assert.equal(results[0].severity, "critical");
    });

    it("does not flag invalid credit card sequences", () => {
      const text = "Order ID: 1234 5678 9012 3456 (not a valid Luhn card)";
      const results = detectPii(text);
      const cardMatch = results.find(r => r.type === "creditCard");
      assert.equal(cardMatch, undefined);
    });

    it("detects international bank account numbers (IBANs)", () => {
      const text = "Wire payment directly to my IBAN: DE89 3704 0044 0532 0130 00 today.";
      const results = detectPii(text);
      const ibanMatch = results.find(r => r.type === "iban");
      assert.notEqual(ibanMatch, undefined);
      assert.equal(ibanMatch.severity, "critical");
      assert.match(ibanMatch.match, /DE89/);
    });

    it("detects US SSNs with dashes or spaces", () => {
      const dashedText = "SSN on application: 123-45-6789";
      const dashedRes = detectPii(dashedText);
      const dashedMatch = dashedRes.find(r => r.type === "ssn");
      assert.notEqual(dashedMatch, undefined);
      assert.equal(dashedMatch.severity, "critical");

      const spacedText = "My social is 123 45 6789";
      const spacedRes = detectPii(spacedText);
      const spacedMatch = spacedRes.find(r => r.type === "ssn");
      assert.notEqual(spacedMatch, undefined);
      assert.equal(spacedMatch.severity, "critical");
    });

    it("detects leaked API keys and tokens", () => {
      const openAiText = "Here is the key: " + "sk-" + "abcdef1234567890abcdef1234567890";
      const openAiRes = detectPii(openAiText);
      assert.equal(openAiRes.some(r => r.type === "apiKey"), true);

      const githubText = "GitHub token: " + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz";
      const githubRes = detectPii(githubText);
      assert.equal(githubRes.some(r => r.type === "apiKey"), true);

      const githubPatText = "GitHub PAT: " + "github_pat_" + "11ABCD1234567890abcdefghijklmnopqrstuvwxyz_01234567890abcdefghijklmnopqrstuv";
      const githubPatRes = detectPii(githubPatText);
      assert.equal(githubPatRes.some(r => r.type === "apiKey"), true);

      const stripeText = "Stripe secret key: " + "sk_" + "test_" + "51Abcd1234567890Abcd1234";
      const stripeRes = detectPii(stripeText);
      assert.equal(stripeRes.some(r => r.type === "apiKey"), true);

      const slackText = "Slack token: " + "xoxb" + "-" + "123456789012" + "-" + "1234567890123" + "-abcdefghijklmnopqrstuvwx";
      const slackRes = detectPii(slackText);
      assert.equal(slackRes.some(r => r.type === "apiKey"), true);

      const googleText = "Google API Key: " + "AIza" + "SyD1234567890abcdefghijklmnopqrstuv";
      const googleRes = detectPii(googleText);
      assert.equal(googleRes.some(r => r.type === "apiKey"), true);

      const awsText = "AWS Key: " + "AKIA" + "IOSFODNN7EXAMPLE";
      const awsRes = detectPii(awsText);
      assert.equal(awsRes.some(r => r.type === "apiKey"), true);
    });

    it("detects standard and international phone numbers", () => {
      const texts = [
        "Call me at +1 (555) 234-5678 soon",
        "Phone: 555-234-5678",
        "Contact: +44 20 7946 0958"
      ];

      for (const text of texts) {
        const results = detectPii(text);
        const phoneMatch = results.find(r => r.type === "phoneNumber");
        assert.notEqual(phoneMatch, undefined, `Expected phone match in "${text}"`);
      }
    });

    it("supports custom user-defined regex patterns", () => {
      const customRules = [
        { name: "Employee Code", pattern: "EMP-[0-9]{4}", severity: "critical" },
        { name: "Ticket ID", pattern: "TICK-[A-Z]{3}", severity: "warning" }
      ];

      const text = "Badge assigned to EMP-9021 with ticket TICK-SEC.";
      const results = detectPii(text, customRules);

      const empMatch = results.find(r => r.name === "Employee Code");
      assert.notEqual(empMatch, undefined);
      assert.equal(empMatch.match, "EMP-9021");
      assert.equal(empMatch.severity, "critical");

      const ticketMatch = results.find(r => r.name === "Ticket ID");
      assert.notEqual(ticketMatch, undefined);
      assert.equal(ticketMatch.match, "TICK-SEC");
      assert.equal(ticketMatch.severity, "warning");
    });

    it("returns empty array for safe ordinary text", () => {
      const text = "Hello everyone! Loving the weather today in San Francisco.";
      const results = detectPii(text);
      assert.equal(results.length, 0);
    });

    it("detects JWT tokens, database URIs, and card CVVs", () => {
      // JWT Bearer token
      const jwtStr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const jwtRes = detectPii("Auth Header: Bearer " + jwtStr);
      const jwtMatch = jwtRes.find(r => r.type === "jwt");
      assert.notEqual(jwtMatch, undefined);
      assert.equal(jwtMatch.severity, "critical");

      // Database URI with credentials
      const dbText = "Connecting with postgres://dbuser:SecretPass99@db.prod.internal:5432/appdb";
      const dbRes = detectPii(dbText);
      const dbMatch = dbRes.find(r => r.type === "dbUri");
      assert.notEqual(dbMatch, undefined);
      assert.equal(dbMatch.severity, "critical");

      // Mongo connection string
      const mongoText = "URI: mongodb+srv://admin:MockPass88@cluster0.abcde.mongodb.net/production";
      const mongoRes = detectPii(mongoText);
      const mongoMatch = mongoRes.find(r => r.type === "dbUri");
      assert.notEqual(mongoMatch, undefined);

      // Card Security Code (CVV / CVC)
      const cvvText = "Card valid thru 12/28, CVV: 789";
      const cvvRes = detectPii(cvvText);
      const cvvMatch = cvvRes.find(r => r.type === "cvv");
      assert.notEqual(cvvMatch, undefined);
      assert.equal(cvvMatch.severity, "critical");
    });

    it("detects expanded private key formats (PGP, DSA, ENCRYPTED)", () => {
      const pgpText = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2.0\n...";
      const pgpRes = detectPii(pgpText);
      assert.equal(pgpRes.some(r => r.type === "apiKey"), true);

      const dsaText = "-----BEGIN DSA PRIVATE KEY-----\nMIIBvAIBAAKCAQEA...";
      const dsaRes = detectPii(dsaText);
      assert.equal(dsaRes.some(r => r.type === "apiKey"), true);

      const encText = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0w...";
      const encRes = detectPii(encText);
      assert.equal(encRes.some(r => r.type === "apiKey"), true);
    });

    it("masks sensitive PII data accurately with maskPii", () => {
      const emailText = "Contact user@example.com for assistance.";
      const maskedEmail = maskPii(emailText);
      assert.equal(maskedEmail, "Contact u***r@example.com for assistance.");

      const cardText = "Card number 4532 0151 1283 0234 charged.";
      const maskedCard = maskPii(cardText);
      assert.equal(maskedCard, "Card number ****-****-****-0234 charged.");

      const ssnText = "SSN is 123-45-6789 on file.";
      const maskedSsn = maskPii(ssnText);
      assert.equal(maskedSsn, "SSN is ***-**-6789 on file.");

      const secretText = "API secret is " + "sk-" + "abcdef1234567890abcdef1234567890.";
      const maskedSecret = maskPii(secretText);
      assert.match(maskedSecret, /\[REDACTED_API_SECRET___TOKEN\]/);

      const safeText = "Totally benign message with nothing private.";
      assert.equal(maskPii(safeText), safeText);
    });
  });

  describe("Custom Regex Compilation Caching", () => {
    it("compiles and caches custom regex instances across calls", () => {
      clearCustomRegexCache();
      const initialSize = getCustomRegexCacheSize();
      assert.equal(initialSize, 0);

      const r1 = getCompiledCustomRegex("TEST-[0-9]+");
      const r2 = getCompiledCustomRegex("TEST-[0-9]+");

      assert.equal(r1, r2, "Expected identical RegExp object reference from cache");
      assert.equal(getCustomRegexCacheSize(), 1);
    });

    it("resets lastIndex to 0 on subsequent retrievals", () => {
      const regex = getCompiledCustomRegex("abc[0-9]");
      assert.notEqual(regex, null);
      regex.lastIndex = 4;

      const retrieved = getCompiledCustomRegex("abc[0-9]");
      assert.equal(retrieved.lastIndex, 0);
    });

    it("gracefully caches null for invalid syntax without throwing repeatedly", () => {
      const invalid = getCompiledCustomRegex("[0-9(");
      assert.equal(invalid, null);

      const cachedInvalid = getCompiledCustomRegex("[0-9(");
      assert.equal(cachedInvalid, null);
    });

    it("evicts oldest entries when cache limit is exceeded", () => {
      clearCustomRegexCache();
      for (let i = 0; i < 105; i++) {
        getCompiledCustomRegex(`PATTERN_${i}_[0-9]`);
      }
      assert.equal(getCustomRegexCacheSize(), 100);
    });

    it("detects custom patterns repeatedly with cache reuse across keystrokes", () => {
      clearCustomRegexCache();
      const custom = [{ name: "Order ID", pattern: "ORD-[0-9]{5}" }];

      const res1 = detectPii("Processing ORD-12345 now", custom);
      const res2 = detectPii("Processing ORD-12345 and ORD-99999", custom);

      assert.equal(res1.length, 1);
      assert.equal(res1[0].match, "ORD-12345");
      assert.equal(res2.length, 2);
      assert.equal(getCustomRegexCacheSize(), 1);
    });
  });

  describe("ReDoS & Regular Expression Safety Validation", () => {
    it("permits standard, benign custom regex patterns", () => {
      const validPatterns = [
        "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$",
        "ORD-[0-9]{5,8}",
        "(?:\\+1[-.\\s]?)?\\d{10}",
        "AKIA[0-9A-Z]{16}",
        "[A-Za-z0-9_-]{10,40}",
        "ghp_[a-zA-Z0-9]{36}"
      ];

      for (const pat of validPatterns) {
        assert.equal(isSafeRegexPattern(pat), true, `Expected valid: ${pat}`);
        const compiled = getCompiledCustomRegex(pat);
        assert.notEqual(compiled, null, `Expected compilable: ${pat}`);
      }
    });

    it("rejects catastrophic backtracking (ReDoS) nested quantifiers", () => {
      const redosPatterns = [
        "(a+)+",
        "(a*)*",
        "([0-9]+)*",
        "(foo|bar+)+",
        "(a+){2,}",
        "((x)+)+",
        "([a-zA-Z]+)*"
      ];

      for (const pat of redosPatterns) {
        assert.equal(isSafeRegexPattern(pat), false, `Expected ReDoS rejection for: ${pat}`);
        const compiled = getCompiledCustomRegex(pat);
        assert.equal(compiled, null, `Expected getCompiledCustomRegex to return null for ReDoS: ${pat}`);
      }
    });

    it("rejects obfuscated, whitespace-padded, and variably quantified ReDoS variations", () => {
      const adversarialPatterns = [
        "( a + ) +",
        "( a + ) { 2 , }",
        "( a { 1 , } ) +",
        "( a { 2 , 5 } ) { 2 , }",
        "( a + ? ) +",
        "( [0-9]+ ) *",
        "( ( a ) + ) +",
        "( a | b + ) +",
        "( [a-z]+ ) { 2 , }",
        "((a+)+)+",
        "(?:(?:[a-z]+)+)+"
      ];

      for (const pat of adversarialPatterns) {
        assert.equal(isSafeRegexPattern(pat), false, `Expected ReDoS rejection for adversarial: ${pat}`);
        const compiled = getCompiledCustomRegex(pat);
        assert.equal(compiled, null, `Expected null compiled regex for: ${pat}`);
      }
    });

    it("permits safe patterns with non-nested quantifiers or fixed repetitions", () => {
      const safePatterns = [
        "\\b(?:\\d{4}-){3}\\d{4}\\b",
        "[A-Z]{2,4}-[0-9]{4,6}",
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
        "(https?|ftp)://[a-zA-Z0-9.-]+"
      ];

      for (const pat of safePatterns) {
        assert.equal(isSafeRegexPattern(pat), true, `Expected safe pattern to pass: ${pat}`);
      }
    });

    it("rejects invalid syntax, empty strings, and oversized patterns", () => {
      assert.equal(isSafeRegexPattern(""), false);
      assert.equal(isSafeRegexPattern(null), false);
      assert.equal(isSafeRegexPattern(undefined), false);
      assert.equal(isSafeRegexPattern("[0-9("), false); // Syntax error
      assert.equal(isSafeRegexPattern("*invalid"), false); // Leading quantifier syntax error
      assert.equal(isSafeRegexPattern("a".repeat(251)), false); // Exceeds length bound
    });
  });
});
