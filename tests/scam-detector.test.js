const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { detectScamContent, buildAhoCorasick, searchAhoCorasick } = require("../core/scam-analyzer.js");

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
    assert.equal(Array.isArray(res.allMatches), true);
    assert.equal(res.allMatches.length >= 2, true);
  });

  it("detects urgent package and delivery phishing lures", () => {
    const deliveryTexts = [
      "Alert: Package delivery failed due to incorrect zip code. Update delivery address now.",
      "Your parcel pending delivery requires a reschedule delivery fee of $1.50 to clear.",
      "Customs fee unpaid on foreign parcel. Shipment held at depot."
    ];

    for (const text of deliveryTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "package-phish");
    }
  });

  it("detects online task and fake review advance payment scams", () => {
    const taskTexts = [
      "Easy remote work: Earn commission for rating merchant products daily from home.",
      "Complete daily tasks to earn $200-$500 per day! Paid per video review with instant withdrawal.",
      "App review job daily pay guaranteed. Recharge wallet to unlock commission tier 2."
    ];

    for (const text of taskTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "warning");
      assert.equal(res.id, "task-investment-scam");
    }
  });

  it("detects romance grooming and pig-butchering investment redirection", () => {
    const romanceTexts = [
      "You seem so kind! Let's move to WhatsApp my dear, I rarely check this app.",
      "My uncle teaches me crypto trading on a special platform with 100% win rate.",
      "We can invest together on this platform, my financial advisor helps me trade daily.",
      "Let's chat on Telegram honey, I can teach you how to trade gold contracts."
    ];

    for (const text of romanceTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "romance-pig-butchering");
      assert.match(res.category, /Pig-Butchering/i);
    }
  });

  it("detects fake invoice and auto-renewal refund scams", () => {
    const invoiceTexts = [
      "Your Geek Squad renewal has been processed. Charged your account $399.99. Call to cancel subscription immediately.",
      "McAfee subscription renewed for 3 years. Auto-debit of $499 will appear on bank statement. Invoice attached call 1-800-555-0199.",
      "Norton auto-renewal confirmed. Call to dispute this charge or refund department hotline within 24 hours."
    ];

    for (const text of invoiceTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "invoice-refund-fraud");
      assert.match(res.category, /Fake Invoice/i);
    }
  });

  it("detects family emergency and impersonation scams", () => {
    const emergencyTexts = [
      "Hi mom, I dropped my phone in water and lost my phone this is my new number.",
      "Dad, I'm in trouble please don't tell mom, I need urgent bail money right now.",
      "Stranded at the airport need cash to get home, can't call right now please wire.",
      "I was in an accident need emergency money for hospital bill urgent send funds."
    ];

    for (const text of emergencyTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "emergency-impersonation");
      assert.match(res.category, /Family Emergency/i);
    }
  });

  it("detects Web3 crypto drainer approvals and malicious signature lures", () => {
    const drainerTexts = [
      "Claim Season 2 Airdrop! Sign Permit2 batch message to verify your eligibility.",
      "Security Migration Notice: Please execute setApprovalForAll on our new vault contract to protect your NFTs.",
      "IncreaseAllowance to unlimited token allowance on this router to participate in the flash loan pool.",
      "Urgent verification: Sign eth_sign payload to authenticate wallet ownership.",
      "Connect and sign this message to verify wallet and receive 5,000 USDC instantly.",
      "Sign gasless transaction to claim your retroactive community rewards."
    ];

    for (const text of drainerTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected flagged for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "crypto-approval-drainer");
      assert.match(res.category, /Web3 Approval Drainer/i);
    }
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

  // --- Expanded Heuristics: Fake Recovery Phrases & Modern Quishing Tests ---

  it("detects fake recovery phrase with zero-width spaces (ZWSP \\u200B)", () => {
    const text = "Enter your s\u200Be\u200Ce\u200Bd phrase to restore your wallet balance immediately.";
    const res = detectScamContent(text);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "critical");
    assert.equal(res.id, "seed-phrase-theft");
    assert.equal(res.containsZeroWidth, true);
    assert.equal(res.zeroWidthObfuscation, true);
  });

  it("detects secret recovery phrase with zero-width non-joiners (ZWNJ \\u200C) and joiners (ZWJ \\u200D)", () => {
    const text = "Security Alert: Provide your secret r\u200Ceco\u200Dvery p\u200Bhrase to verify ownership.";
    const res = detectScamContent(text);
    assert.equal(res.flagged, true);
    assert.equal(res.severity, "critical");
    assert.equal(res.id, "seed-phrase-theft");
    assert.equal(res.containsZeroWidth, true);
    assert.equal(res.zeroWidthObfuscation, true);
  });

  it("detects 12-word and 24-word recovery phrase lures with directional markers (LRM/RLM)", () => {
    const texts = [
      "Backup required: Type your 12-word\u200E recovery\u200F phrase into our migration portal.",
      "Enter your 24-word\u200B seed\u200C phrase to upgrade wallet security."
    ];

    for (const text of texts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "seed-phrase-theft");
      assert.equal(res.containsZeroWidth, true);
    }
  });

  it("detects fake accidental or leaked recovery phrase honeypot drops", () => {
    const drops = [
      "I'm quitting Web3, here is my 12-word recovery phrase with 5.4 ETH inside, whoever claims it first gets it.",
      "Found an accidental recovery phrase from an old paper wallet: claim it before someone else does.",
      "Leaked recovery phrase from whale wallet: import immediately to claim balance."
    ];

    for (const text of drops) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "seed-phrase-theft");
    }
  });

  it("detects wallet import/restore lures with zero-width BOM (\\uFEFF) obfuscation", () => {
    const texts = [
      "Please import\uFEFF recovery\uFEFF phrase into the synchronized validator tool.",
      "Restore wallet with seed\uFEFF phrase to unlock your tokens."
    ];

    for (const text of texts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "seed-phrase-theft");
      assert.equal(res.containsZeroWidth, true);
      assert.equal(res.zeroWidthObfuscation, true);
    }
  });

  it("detects modern Quishing 2FA and authenticator configuration lures", () => {
    const quishingTexts = [
      "Scan QR code to configure 2FA on your account before the mandatory security deadline.",
      "Action Required: Scan QR code for two-factor authentication setup.",
      "Scan QR code to register authenticator app to prevent account lockout."
    ];

    for (const text of quishingTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected quishing 2FA detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "quishing-lure");
    }
  });

  it("detects modern Quishing phone camera and mobile device instructions", () => {
    const cameraTexts = [
      "Point camera at QR code to authenticate your workstation session.",
      "Please scan QR code with your phone camera to continue login.",
      "Scan QR code with mobile device to verify your identity."
    ];

    for (const text of cameraTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected quishing camera detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "quishing-lure");
    }
  });

  it("detects modern Quishing mailbox and password expiration lures", () => {
    const mailTexts = [
      "Your mailbox has 6 quarantined messages. Scan QR code to release pending emails immediately.",
      "Password expiring today. Scan QR code to retain password and maintain cloud access.",
      "Scan QR code to review quarantined message and avoid message purge."
    ];

    for (const text of mailTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected quishing mailbox detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "quishing-lure");
    }
  });

  it("detects modern Quishing HR, payroll, and benefits open enrollment lures", () => {
    const hrTexts = [
      "Internal HR Announcement: Scan QR code to view your payslip and confirm bonus payout.",
      "Annual Benefits Update: Scan QR code to complete open enrollment before Friday.",
      "Employee Payroll: Scan QR code to access W-2 wage statement."
    ];

    for (const text of hrTexts) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected quishing HR detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "quishing-lure");
    }
  });

  it("detects modern Quishing instructions with zero-width character evasion", () => {
    const obfuscatedQuishing = [
      "S\u200Bcan Q\u200BR c\u200Bode to approve refund of $450 back to your card.",
      "P\u200Coint camera at Q\u200DR c\u200Bode to authenticate."
    ];

    for (const text of obfuscatedQuishing) {
      const res = detectScamContent(text);
      assert.equal(res.flagged, true, `Expected obfuscated quishing detection for: ${text}`);
      assert.equal(res.severity, "critical");
      assert.equal(res.id, "quishing-lure");
      assert.equal(res.containsZeroWidth, true);
      assert.equal(res.zeroWidthObfuscation, true);
    }
  });

  describe("Aho-Corasick Multi-Pattern Trie Automaton", () => {
    const customRules = [
      { id: "rule-a", keywords: ["he", "she", "his", "hers"] },
      { id: "rule-b", keywords: ["crypto", "cryptocurrency", "airdrop"] },
      { id: "rule-c", keywords: ["send eth", "send btc"] }
    ];

    const automaton = buildAhoCorasick(customRules);

    it("matches multiple keywords simultaneously in linear time", () => {
      const text = "she said that his crypto airdrop was legit";
      const matches = searchAhoCorasick(text.toLowerCase(), automaton);

      const foundWords = matches.map(m => m.keyword);
      assert.ok(foundWords.includes("she"));
      assert.ok(foundWords.includes("he")); // 'he' is a substring of 'she'
      assert.ok(foundWords.includes("his"));
      assert.ok(foundWords.includes("crypto"));
      assert.ok(foundWords.includes("airdrop"));
    });

    it("handles overlapping prefixes with failure links correctly", () => {
      const text = "check this cryptocurrency token";
      const matches = searchAhoCorasick(text.toLowerCase(), automaton);

      const foundWords = matches.map(m => m.keyword);
      assert.ok(foundWords.includes("crypto"));
      assert.ok(foundWords.includes("cryptocurrency"));
    });

    it("returns empty array when no keywords match", () => {
      const text = "an ordinary harmless post about cooking";
      const matches = searchAhoCorasick(text.toLowerCase(), automaton);
      assert.equal(matches.length, 0);
    });
  });
});

