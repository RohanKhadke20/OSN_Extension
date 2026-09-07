const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { detectPii, luhnCheck, isValidSSN } = require("../core/pii-analyzer.js");

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

    it("detects US SSNs", () => {
      const text = "SSN on application: 123-45-6789";
      const results = detectPii(text);
      const ssnMatch = results.find(r => r.type === "ssn");
      assert.notEqual(ssnMatch, undefined);
      assert.equal(ssnMatch.severity, "critical");
    });

    it("detects leaked API keys and tokens", () => {
      const openAiText = "Here is the key: sk-abcdef1234567890abcdef1234567890";
      const openAiRes = detectPii(openAiText);
      assert.equal(openAiRes.some(r => r.type === "apiKey"), true);

      const githubText = "GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz";
      const githubRes = detectPii(githubText);
      assert.equal(githubRes.some(r => r.type === "apiKey"), true);

      const awsText = "AWS Key: AKIAIOSFODNN7EXAMPLE";
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
