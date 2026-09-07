const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { detectPii, luhnCheck, isValidSSN, isValidIBAN } = require("../core/pii-analyzer.js");

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
  });
});
