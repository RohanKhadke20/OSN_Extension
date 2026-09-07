const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { detectScamContent } = require("../core/scam-analyzer.js");

describe("Scam & Fraud Content Detector", () => {
  it("detects cryptocurrency giveaway and doubling scams", () => {
    const texts = [
      "🔥 Double your bitcoin instantly! Send ETH to our wallet address for 2x return.",
      "Join our exclusive crypto giveaway and claim your airdrop now!",
      "Free crypto bonus available for the next 100 users."
    ];

    for (const text of texts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
    }
  });

  it("detects wallet drainer and seed phrase theft lures", () => {
    const texts = [
      "Your wallet has an error. Enter seed phrase here to synchronize and restore access.",
      "Connect wallet to claim 50,000 token bonus immediately!",
      "Metamask verification required before tomorrow or funds are locked."
    ];

    for (const text of texts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "seed-phrase-theft");
    }
  });

  it("detects credential phishing and urgent suspension threats", () => {
    const texts = [
      "Urgent: Unusual activity detected on your profile. Verify account now.",
      "Account suspension warning: Reset credentials now or account will be terminated.",
      "Last chance to update your security settings before closure."
    ];

    for (const text of texts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "credential-phish");
    }
  });

  it("detects tech support imposter scams", () => {
    const text = "System infected! Call Microsoft support toll-free at 1-800-555-0199 immediately.";
    const res = detectScamContent(text);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "critical");
    assert.equal(res.id, "tech-support-fraud");
  });

  it("detects spam recruitment and suspicious telegram/whatsapp channels", () => {
    const text = "Earn $500/day work from home scam-free! Contact our WhatsApp or join our telegram channel.";
    const res = detectScamContent(text);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "warning");
  });

  it("detects QR code phishing (quishing) lures", () => {
    const texts = [
      "Security Notice: Scan QR code to verify your credentials immediately.",
      "Scan this QR code to log in securely to your mobile account.",
      "Scan the QR code to receive payment into your account."
    ];

    for (const text of texts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for quishing: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "quishing-lure");
    }
  });

  it("detects NFT drainer and stealth drop scams", () => {
    const text = "Surprise community reward! Free mint is live right now! Mint your free NFT before allocation ends.";
    const res = detectScamContent(text);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "critical");
    assert.equal(res.id, "nft-drainer");
  });

  it("detects AI token and fake yield multiplier scams", () => {
    const text = "Exclusive opportunity: Claim free AI tokens with our AI arbitrage bot guaranteed 50% weekly return!";
    const res = detectScamContent(text);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "warning");
    assert.equal(res.id, "ai-token-fraud");
  });

  it("prioritizes critical threats over warnings in compound scam posts", () => {
    // Contains a warning keyword ("telegram channel join") AND a critical keyword ("enter seed phrase")
    const compoundText = "Telegram channel join here! Important: enter seed phrase to verify and claim your compensation.";
    const res = detectScamContent(compoundText);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "critical", "Expected critical threat to take precedence over warning");
    assert.equal(res.id, "seed-phrase-theft");
  });

  it("ignores benign regular social posts", () => {
    const benignTexts = [
      "Just had a wonderful brunch with friends! Hope everyone has a productive Monday.",
      "Reading an interesting article about distributed databases and consensus algorithms.",
      "Does anyone have recommendations for a good noise-cancelling headset?"
    ];

    for (const text of benignTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, false);
    }
  });
});
