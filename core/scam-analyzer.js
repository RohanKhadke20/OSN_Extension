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
        "connect wallet to claim",
        "wallet verification required",
        "metamask verification",
        "trust wallet restore",
        "sync wallet to resolve",
        "validate your private key"
      ],
      reason: "Attempted cryptocurrency wallet drainer or private key theft."
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
    }
  ];

  /**
   * Analyzes text content for scam, fraud, or phishing indicators
   * @param {string} text - The post or message content
   * @returns {{ flagged: boolean, category?: string, reason?: string, severity?: "warning" | "critical", matchedKeyword?: string }}
   */
  function detectScamContent(text) {
    if (!text || typeof text !== "string" || text.trim().length < 8) {
      return { flagged: false };
    }

    const lower = text.toLowerCase();

    for (const rule of SCAM_RULES) {
      for (const keyword of rule.keywords) {
        if (lower.includes(keyword)) {
          return {
            flagged: true,
            id: rule.id,
            category: rule.category,
            reason: rule.reason,
            severity: rule.severity,
            matchedKeyword: keyword
          };
        }
      }
    }

    return { flagged: false };
  }

  return {
    detectScamContent,
    SCAM_RULES
  };
});
