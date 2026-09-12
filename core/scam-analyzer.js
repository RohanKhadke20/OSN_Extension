/**
 * OSN Guard - Scam & Fraud Content Analyzer
 * Analyzes social posts, direct messages, and interactive feeds for fraudulent patterns,
 * crypto drainers, credential phishing lures, and deceptive spam.
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.OSNScamAnalyzer = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const SCAM_RULES = [
    {
      id: "crypto-scam",
      category: "Crypto Fraud / Fake Giveaway",
      severity: "critical",
      keywords: [
        "free crypto",
        "crypto giveaway",
        "bitcoin doubled",
        "double your bitcoin",
        "send eth",
        "send btc to",
        "airdrop claim",
        "claim your airdrop",
        "guaranteed returns up to",
        "eth bonus",
        "presale allocation guaranteed"
      ],
      reason: "Suspected cryptocurrency scam or fake doubling giveaway."
    },
    {
      id: "seed-phrase-theft",
      category: "Seed Phrase / Wallet Drainer",
      severity: "critical",
      keywords: [
        "enter seed phrase",
        "enter secret recovery phrase",
        "secret recovery phrase",
        "recovery phrase",
        "seed phrase",
        "12-word recovery phrase",
        "24-word recovery phrase",
        "12 word recovery phrase",
        "24 word recovery phrase",
        "12-word seed phrase",
        "24-word seed phrase",
        "12 word seed phrase",
        "24 word seed phrase",
        "backup recovery phrase",
        "backup seed phrase",
        "import recovery phrase",
        "import your recovery phrase",
        "import your seed phrase",
        "enter your seed phrase",
        "input recovery phrase",
        "input seed phrase",
        "input your recovery phrase",
        "input your seed phrase",
        "provide recovery phrase",
        "provide your recovery phrase",
        "share your recovery phrase",
        "share your seed phrase",
        "verify recovery phrase",
        "verify your recovery phrase",
        "restore wallet with recovery phrase",
        "restore wallet with seed phrase",
        "restore wallet with seed",
        "mnemonic recovery phrase",
        "mnemonic seed phrase",
        "enter mnemonic phrase",
        "enter your mnemonic",
        "type your 12 words",
        "type your 24 words",
        "enter your 12 words",
        "enter your 24 words",
        "fake recovery phrase",
        "leaked recovery phrase",
        "accidental recovery phrase",
        "wallet recovery phrase",
        "here is my recovery phrase",
        "here is my 12-word phrase",
        "here is my 12 word phrase",
        "here is my 12-word seed",
        "here is my 12 word seed",
        "connect wallet to claim",
        "wallet verification required",
        "metamask verification",
        "trust wallet restore",
        "sync wallet to resolve",
        "validate your private key"
      ],
      patterns: [
        /\b(?:enter|input|import|verify|restore|submit|provide|share|backup)\s+(?:your\s+)?(?:secret\s+)?(?:12|24)[\s-]*words?\b/i,
        /\b(?:12|24)[\s-]*(?:word|mnemonic)[\s-]*(?:recovery|seed)[\s-]*phrase\b/i,
        /\b(?:fake|leaked|accidental|abandoned|unclaimed)\s+(?:wallet\s+)?(?:seed|recovery|mnemonic)\s+phrase\b/i,
        /\bhere\s+is\s+my\s+(?:12|24)[\s-]*(?:word\s+)?(?:seed|recovery)\b/i
      ],
      reason: "Attempted cryptocurrency wallet drainer, fake recovery phrase lure, or private key theft."
    },
    {
      id: "credential-phish",
      category: "Credential Phishing / Account Takeover",
      severity: "critical",
      keywords: [
        "verify account",
        "unusual activity detected",
        "reset credentials now",
        "suspicious access login",
        "account suspension warning",
        "log in within 24 hours",
        "last chance to update",
        "action required to prevent suspension",
        "click to unlock your account",
        "confirm identity to avoid termination"
      ],
      reason: "Urgent credential phishing or account takeover lure."
    },
    {
      id: "tech-support-fraud",
      category: "Tech Support Scam",
      severity: "critical",
      keywords: [
        "call microsoft support",
        "contact apple support at",
        "call toll-free to remove virus",
        "windows defender alert call",
        "security center hotline",
        "call our certified technician"
      ],
      reason: "Tech support impersonation scam designed to compromise system."
    },
    {
      id: "spam-recruitment",
      category: "Employment & Financial Spam",
      severity: "warning",
      keywords: [
        "whatsapp contact",
        "contact our whatsapp",
        "earn daily",
        "work from home scam",
        "click here to earn",
        "telegram channel join",
        "join our telegram channel",
        "earn $500/day",
        "easy money from home",
        "passive income guaranteed"
      ],
      reason: "High correlation with social engineering scams and spam networks."
    },
    {
      id: "advance-fee-fraud",
      category: "Advance-Fee / Prize Scam",
      severity: "warning",
      keywords: [
        "amazon gift card giveaway",
        "won a free gift card",
        "claim $1000 prize",
        "wire transfer immediately",
        "pay via western union",
        "moneygram fee to claim"
      ],
      reason: "Potential advance-fee fraud or fake prize generation scheme."
    },
    {
      id: "quishing-lure",
      category: "QR Code Phishing (Quishing)",
      severity: "critical",
      keywords: [
        "scan qr code to verify",
        "scan this qr code to log in",
        "scan qr to login",
        "scan the qr code to receive payment",
        "scan qr code to update payment",
        "scan to unlock your account",
        // Modern Quishing Instructions - 2FA / MFA / Authenticator
        "scan qr code to configure 2fa",
        "scan qr code to set up 2fa",
        "scan qr code to enable 2fa",
        "scan qr code for two-factor authentication",
        "scan qr code for 2fa",
        "scan qr to update 2fa",
        "scan qr code to register authenticator",
        "scan qr code for authenticator app",
        "scan qr for authenticator",
        "scan qr to authenticate session",
        // Modern Quishing Instructions - Phone Camera / Mobile Devices
        "scan qr code with your phone camera",
        "scan qr code with mobile camera",
        "point camera at qr code",
        "point your camera at the qr code",
        "point phone camera at qr code",
        "scan qr code with your smartphone",
        "scan qr code with mobile device",
        "scan qr with your mobile device",
        "scan qr with phone to continue",
        "scan this qr with your phone",
        // Modern Quishing Instructions - Mailbox / Security / Password Expiration
        "scan qr code to retain password",
        "scan qr code to prevent password expiration",
        "scan qr code to release pending emails",
        "scan qr code to review quarantined message",
        "scan qr code to review quarantined messages",
        "scan qr code to unblock incoming emails",
        "scan qr code to renew email access",
        "scan qr to unlock mailbox",
        "scan qr to keep current password",
        // Modern Quishing Instructions - HR / Payroll / Employee Benefits
        "scan qr code to view your payslip",
        "scan qr code to view payslip",
        "scan qr code to access w-2",
        "scan qr code to review annual compensation",
        "scan qr code to complete open enrollment",
        "scan qr code to claim employee benefits",
        "scan qr to review salary increase",
        // Modern Quishing Instructions - Payment / Refund / Toll
        "scan qr code to approve refund",
        "scan qr code to confirm transaction",
        "scan qr code to complete payment",
        "scan qr code to pay unpaid toll",
        "scan qr code to avoid parking citation",
        // Modern Quishing Instructions - Web3 / Crypto
        "scan qr code to connect wallet",
        "scan qr code to claim airdrop",
        "scan qr code to migrate tokens",
        "scan qr to sign transaction"
      ],
      patterns: [
        /\bscan\s+(?:the\s+|this\s+)?qr[\s-]*(?:code)?\s+(?:with\s+(?:your\s+)?(?:phone|mobile|smartphone)(?:\s+camera)?|to\s+(?:configure|enable|set\s+up|update)\s+2fa)\b/i,
        /\b(?:point|aim)\s+(?:your\s+)?(?:phone\s+|mobile\s+)?camera\s+at\s+(?:the\s+|this\s+)?qr[\s-]*(?:code)?\b/i,
        /\bscan\s+(?:the\s+|this\s+)?qr[\s-]*(?:code)?\s+to\s+(?:release\s+pending\s+emails|retain\s+password|prevent\s+password\s+expiration|view\s+(?:your\s+)?payslip|access\s+w-?2|approve\s+refund)\b/i
      ],
      reason: "Potential QR code phishing (Quishing) designed to bypass browser link inspection."
    },
    {
      id: "nft-drainer",
      category: "NFT Drainer / Stealth Drop",
      severity: "critical",
      keywords: [
        "stealth drop is live",
        "free mint is live",
        "mint your free nft",
        "claim free nft whitelist",
        "claim limited allocation"
      ],
      reason: "Suspected fake NFT mint lure or malicious contract approval drainer."
    },
    {
      id: "ai-token-fraud",
      category: "AI Token / Fake Yield Scam",
      severity: "warning",
      keywords: [
        "claim free ai tokens",
        "chatgpt tokens giveaway",
        "invest in ai compute",
        "ai arbitrage bot guaranteed",
        "daily passive crypto yield",
        "guaranteed 50% weekly return"
      ],
      reason: "Deceptive AI investment scheme or unregulated yield multiplier."
    },
    {
      id: "package-phish",
      category: "Package Delivery Phishing",
      severity: "critical",
      keywords: [
        "package delivery failed",
        "parcel pending delivery",
        "reschedule delivery fee",
        "update delivery address",
        "customs fee unpaid",
        "shipment held at depot",
        "usps delivery issue",
        "redelivery scheduled fee"
      ],
      reason: "Urgent package or parcel delivery fee lure mimicking courier services."
    },
    {
      id: "task-investment-scam",
      category: "Online Task / Fake Review Scam",
      severity: "warning",
      keywords: [
        "earn commission for rating",
        "complete daily tasks to earn",
        "paid per video review",
        "daily task commission",
        "app review job daily pay",
        "recharge wallet to unlock commission"
      ],
      reason: "Suspected task-based advance payment scam or deceptive review syndicate."
    },
    {
      id: "romance-pig-butchering",
      category: "Romance Grooming / Pig-Butchering Scam",
      severity: "critical",
      keywords: [
        "move to whatsapp my dear",
        "chat on whatsapp instead",
        "my uncle teaches me crypto",
        "uncle works in finance",
        "guaranteed crypto trading platform",
        "invest together on this platform",
        "my financial advisor helps me trade",
        "teach you how to trade gold",
        "exclusive liquidity pool",
        "let's talk on telegram handsome",
        "let's chat on telegram honey",
        "my private whatsapp number"
      ],
      reason: "Suspected romance grooming or 'pig-butchering' crypto investment redirection."
    },
    {
      id: "invoice-refund-fraud",
      category: "Fake Invoice / Refund Scam",
      severity: "critical",
      keywords: [
        "geek squad renewal",
        "mcafee subscription renewed",
        "norton auto-renewal",
        "charged your account $399",
        "charged your account $499",
        "auto-debit of $",
        "call to cancel subscription",
        "call to dispute this charge",
        "invoice attached call",
        "call toll-free to refund",
        "refund department hotline",
        "cancel within 24 hours to get refund"
      ],
      reason: "Suspected fake invoice or auto-renewal refund fraud designed to elicit remote desktop access or banking credentials."
    },
    {
      id: "emergency-impersonation",
      category: "Family Emergency / Grandparent Scam",
      severity: "critical",
      keywords: [
        "lost my phone this is my new number",
        "dropped my phone in water",
        "in trouble please don't tell mom",
        "in trouble please don't tell dad",
        "urgent bail money",
        "need money urgently please send",
        "stranded at the airport need cash",
        "in an accident need emergency money",
        "hospital bill urgent send funds",
        "can't call right now please wire"
      ],
      reason: "Suspected family emergency or impersonation scam targeting urgent money transfers."
    },
    {
      id: "crypto-approval-drainer",
      category: "Web3 Approval Drainer / Malicious Signature",
      severity: "critical",
      keywords: [
        "permit2 batch",
        "sign permit2",
        "permit2 signature",
        "setapprovalforall",
        "increaseallowance",
        "sign eth_sign",
        "sign this message to verify wallet",
        "sign message to claim airdrop",
        "approve unlimited",
        "unlimited token allowance",
        "sign gasless transaction to claim",
        "sign off-chain voucher to receive",
        "delegatecash verification signature"
      ],
      reason: "Dangerous Web3 signature or unlimited contract approval request commonly used by wallet drainers to steal tokens and NFTs without transaction gas."
    }
  ];

  const ZERO_WIDTH_REGEX = /[\u200B-\u200D\u200E\u200F\uFEFF\u2060\u00AD\u202A-\u202E\u2066-\u2069]/g;

  /**
   * Fast Aho-Corasick Multi-Pattern Automaton for sub-millisecond keyword matching
   */
  function buildAhoCorasick(rules) {
    const root = { next: new Map(), fail: null, output: [] };

    // 1. Build Trie
    for (const rule of rules) {
      if (!rule.keywords) continue;
      for (const kw of rule.keywords) {
        const lowerKw = kw.toLowerCase();
        let curr = root;
        for (let i = 0; i < lowerKw.length; i++) {
          const ch = lowerKw[i];
          if (!curr.next.has(ch)) {
            curr.next.set(ch, { next: new Map(), fail: null, output: [] });
          }
          curr = curr.next.get(ch);
        }
        curr.output.push({ rule, keyword: kw });
      }
    }

    // 2. Build Failure Links using BFS
    const queue = [];
    for (const [ch, child] of root.next) {
      child.fail = root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const curr = queue.shift();

      for (const [ch, child] of curr.next) {
        let f = curr.fail;
        while (f && !f.next.has(ch)) {
          f = f.fail;
        }
        child.fail = f ? f.next.get(ch) : root;
        if (child.fail.output.length > 0) {
          child.output = child.output.concat(child.fail.output);
        }
        queue.push(child);
      }
    }

    return root;
  }

  /**
   * Searches text using precompiled Aho-Corasick automaton
   * @param {string} text - Lowercase text to search
   * @param {object} root - Automaton root
   * @returns {Array<{ rule: object, keyword: string }>}
   */
  function searchAhoCorasick(text, root) {
    const results = [];
    let curr = root;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      while (curr && !curr.next.has(ch)) {
        curr = curr.fail;
      }
      curr = curr ? curr.next.get(ch) : root;

      if (curr.output.length > 0) {
        for (let j = 0; j < curr.output.length; j++) {
          results.push(curr.output[j]);
        }
      }
    }

    return results;
  }

  // Precompile Aho-Corasick automaton once at module initialization
  const KEYWORD_AUTOMATON = buildAhoCorasick(SCAM_RULES);

  /**
   * Analyzes text content for scam, fraud, or phishing indicators
   * Detects hidden zero-width character evasion and prioritizes critical severity matches
   * @param {string} text - The post or message content
   * @returns {{ flagged: boolean, id?: string, category?: string, reason?: string, severity?: "warning" | "critical", matchedKeyword?: string, containsZeroWidth?: boolean, zeroWidthObfuscation?: boolean, allMatches?: Array<object> }}
   */
  function detectScamContent(text) {
    if (!text || typeof text !== "string" || text.trim().length < 8) {
      return { flagged: false };
    }

    const hasZeroWidth = ZERO_WIDTH_REGEX.test(text);
    const sanitizedText = hasZeroWidth ? text.replace(ZERO_WIDTH_REGEX, "") : text;
    const lowerRaw = text.toLowerCase();
    const lowerSanitized = hasZeroWidth ? sanitizedText.toLowerCase() : lowerRaw;

    const matchedRuleMap = new Map();

    // 1. High-speed multi-pattern Aho-Corasick keyword search
    const rawMatches = searchAhoCorasick(lowerRaw, KEYWORD_AUTOMATON);
    for (let i = 0; i < rawMatches.length; i++) {
      const m = rawMatches[i];
      if (!matchedRuleMap.has(m.rule.id)) {
        matchedRuleMap.set(m.rule.id, {
          rule: m.rule,
          matchedTerm: m.keyword,
          matchedViaSanitization: false
        });
      }
    }

    if (hasZeroWidth) {
      const sanitizedMatches = searchAhoCorasick(lowerSanitized, KEYWORD_AUTOMATON);
      for (let i = 0; i < sanitizedMatches.length; i++) {
        const m = sanitizedMatches[i];
        const existing = matchedRuleMap.get(m.rule.id);
        if (!existing) {
          matchedRuleMap.set(m.rule.id, {
            rule: m.rule,
            matchedTerm: m.keyword,
            matchedViaSanitization: true
          });
        } else if (!existing.matchedViaSanitization && m.keyword.length > existing.matchedTerm.length) {
          matchedRuleMap.set(m.rule.id, {
            rule: m.rule,
            matchedTerm: m.keyword,
            matchedViaSanitization: true
          });
        }
      }
    }

    // 2. Pattern check for rules with regex patterns (or rules not yet matched by keywords)
    for (let i = 0; i < SCAM_RULES.length; i++) {
      const rule = SCAM_RULES[i];
      if (matchedRuleMap.has(rule.id) || !rule.patterns) continue;

      for (let j = 0; j < rule.patterns.length; j++) {
        const pattern = rule.patterns[j];
        if (pattern.test(lowerRaw)) {
          matchedRuleMap.set(rule.id, {
            rule,
            matchedTerm: pattern.source,
            matchedViaSanitization: false
          });
          break;
        } else if (hasZeroWidth && pattern.test(lowerSanitized)) {
          matchedRuleMap.set(rule.id, {
            rule,
            matchedTerm: pattern.source,
            matchedViaSanitization: true
          });
          break;
        }
      }
    }

    if (matchedRuleMap.size === 0) {
      return { flagged: false };
    }

    const matches = [];
    for (const [, item] of matchedRuleMap) {
      matches.push({
        flagged: true,
        id: item.rule.id,
        category: item.rule.category,
        reason: item.rule.reason,
        severity: item.rule.severity,
        matchedKeyword: item.matchedTerm,
        containsZeroWidth: hasZeroWidth,
        zeroWidthObfuscation: item.matchedViaSanitization
      });
    }

    // Always surface critical threats first
    const topThreat = matches.find(m => m.severity === "critical") || matches[0];
    return {
      ...topThreat,
      containsZeroWidth: hasZeroWidth,
      zeroWidthObfuscation: matches.some(m => m.zeroWidthObfuscation),
      allMatches: matches
    };
  }

  return {
    detectScamContent,
    SCAM_RULES,
    ZERO_WIDTH_REGEX,
    buildAhoCorasick,
    searchAhoCorasick
  };
});

