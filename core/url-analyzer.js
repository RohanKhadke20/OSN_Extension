/**
 * OSN Guard - URL Safety Analyzer Engine
 * Evaluates URLs against safe domain registries, phishing blacklists,
 * punycode/IDN homograph exploits, IP address targets, and risk heuristics.
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.OSNUrlAnalyzer = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Comprehensive list of well-known trusted domains and major OSNs
  const SAFE_DOMAINS = new Set([
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "reddit.com",
    "instagram.com",
    "threads.net",
    "youtube.com",
    "tiktok.com",
    "pinterest.com",
    "tumblr.com",
    "snapchat.com",
    "discord.com",
    "telegram.org",
    "whatsapp.com",
    "medium.com",
    "quora.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "stackexchange.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "wikimedia.org",
    "w3.org",
    "mozilla.org",
    "cloudflare.com",
    "npmjs.com",
    "yahoo.com",
    "duckduckgo.com",
    "bing.com",
    "spotify.com",
    "netflix.com",
    "twitch.tv",
    "vimeo.com"
  ]);

  // Known malicious, phishing, or scam test domains
  const SUSPICIOUS_DOMAINS = [
    "login-verify-facebook.com",
    "security-alert-twitter.net",
    "linkedin-verify.info",
    "reddit-coins-free.org",
    "pay-paypal-verify.com",
    "free-crypto-giveaway.cc",
    "win-iphone-now.xyz",
    "update-banking-security.co",
    "metamask-wallet-recovery.com",
    "binance-airdrop-claim.com",
    "steam-community-nitro.ru",
    "discord-free-nitro.xyz"
  ];

  // Suspicious low-cost / high-abuse TLDs often used for disposable phishing
  const SUSPICIOUS_TLDS = new Set([
    ".xyz", ".cc", ".info", ".click", ".top", ".buzz",
    ".work", ".gq", ".tk", ".cf", ".ml", ".ga",
    ".rest", ".country", ".stream", ".cam", ".monster",
    ".sbs", ".cfd", ".quest", ".beauty", ".hair", ".skin"
  ]);

  // High-risk keywords commonly combined in phishing URLs
  const PHISHING_KEYWORDS = [
    "login", "verify", "secure", "signin", "account",
    "update", "banking", "free-coins", "giveaway", "claim",
    "airdrop", "wallet-connect", "password-reset", "recover", "billing"
  ];

  // IP address regex patterns (IPv4, IPv6, and dword/hex representations)
  const IPV4_PATTERN = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const IPV6_PATTERN = /^\[[0-9a-fA-F:]+\]$/;
  const DWORD_IP_PATTERN = /^(?:0x[0-9a-fA-F]+|\d{8,11})$/;

  /**
   * Checks if a given hostname is a raw IP address (IPv4, IPv6, or integer notation)
   * @param {string} host - Hostname string
   * @returns {boolean}
   */
  function isRawIpAddress(host) {
    if (!host) return false;
    return IPV4_PATTERN.test(host) || IPV6_PATTERN.test(host) || DWORD_IP_PATTERN.test(host);
  }

  /**
   * Checks if a domain is included in the whitelist
   * @param {string} hostname - Target hostname
   * @param {Array<string>} whitelistedDomains - List of whitelisted domain names
   * @returns {boolean}
   */
  function isDomainWhitelisted(hostname, whitelistedDomains = []) {
    if (!hostname || !Array.isArray(whitelistedDomains) || whitelistedDomains.length === 0) {
      return false;
    }

    const cleanHost = hostname.toLowerCase().trim();

    return whitelistedDomains.some(entry => {
      if (!entry) return false;
      let cleanEntry = entry.toLowerCase().trim();
      
      // Strip scheme if present
      if (cleanEntry.startsWith("http://") || cleanEntry.startsWith("https://")) {
        try {
          cleanEntry = new URL(cleanEntry).hostname;
        } catch {
          cleanEntry = cleanEntry.replace(/^https?:\/\//, "");
        }
      }

      // Remove wildcard prefix (*.example.com -> example.com)
      if (cleanEntry.startsWith("*.")) {
        cleanEntry = cleanEntry.slice(2);
      }

      // Strip leading www. if needed
      if (cleanEntry.startsWith("www.")) {
        cleanEntry = cleanEntry.slice(4);
      }

      const hostWithoutWww = cleanHost.startsWith("www.") ? cleanHost.slice(4) : cleanHost;

      return (
        hostWithoutWww === cleanEntry ||
        hostWithoutWww.endsWith("." + cleanEntry)
      );
    });
  }

  /**
   * Checks if a domain belongs to a safe / well-known provider
   * @param {string} domain - Hostname to check
   * @returns {boolean}
   */
  function isSafeDomain(domain) {
    const cleanDomain = domain.toLowerCase();
    const hostWithoutWww = cleanDomain.startsWith("www.") ? cleanDomain.slice(4) : cleanDomain;

    if (SAFE_DOMAINS.has(hostWithoutWww)) {
      return true;
    }

    for (const safe of SAFE_DOMAINS) {
      if (hostWithoutWww.endsWith("." + safe)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Analyzes the safety of a given URL
   * @param {string} urlString - The URL string to inspect
   * @param {Array<string>} whitelistedDomains - Optional user-configured whitelist
   * @returns {{ safe: boolean, reason: string, severity?: "warning" | "critical", details?: Array<string> }}
   */
  function analyzeUrlSafety(urlString, whitelistedDomains = []) {
    if (!urlString || typeof urlString !== "string") {
      return { safe: false, reason: "Missing or invalid URL parameter", severity: "warning" };
    }

    // Ignore benign non-http schemes without flagging as threats
    const trimmed = urlString.trim().toLowerCase();
    if (trimmed.startsWith("javascript:") || trimmed.startsWith("#") || trimmed.startsWith("mailto:") || trimmed.startsWith("tel:")) {
      return { safe: true, reason: "Ignored internal or interactive scheme" };
    }

    // Early detection of Punycode (IDN) attempts to catch both valid and malformed homograph exploits
    if (trimmed.includes("://xn--") || trimmed.includes(".xn--") || trimmed.startsWith("xn--")) {
      return {
        safe: false,
        reason: "Punycode (IDN) domain detected: potential spoofing or homograph phishing",
        severity: "critical"
      };
    }

    let urlObj;
    try {
      urlObj = new URL(urlString);
    } catch {
      return { safe: false, reason: "Invalid or malformed URL", severity: "warning" };
    }

    const domain = urlObj.hostname.toLowerCase();

    // Check 1: User Whitelist
    if (isDomainWhitelisted(domain, whitelistedDomains)) {
      return { safe: true, reason: "Domain is in user whitelist" };
    }

    // Check 2: Well-known Safe Domains
    if (isSafeDomain(domain)) {
      return { safe: true, reason: "Well-known secure domain" };
    }

    // Check 3: Known Malicious or Phishing Domains
    const isSuspicious = SUSPICIOUS_DOMAINS.some(suspicious => {
      return domain === suspicious || domain.endsWith("." + suspicious) || domain.includes(suspicious);
    });

    if (isSuspicious) {
      return {
        safe: false,
        reason: "Matched known phishing/malicious database pattern",
        severity: "critical"
      };
    }

    // Check 4: IDN Homograph / Punycode Attacks
    if (domain.startsWith("xn--") || domain.includes(".xn--")) {
      return {
        safe: false,
        reason: "Punycode (IDN) domain detected: potential spoofing or homograph phishing",
        severity: "critical"
      };
    }

    // Heuristic Evaluation
    const heuristics = [];

    // Heuristic A: Embedded credentials / userinfo in URL authority (e.g. https://google.com@attacker.com)
    if (urlObj.username || urlObj.password) {
      heuristics.push("Contains embedded credentials or userinfo in URL authority (potential phishing/spoofing)");
    }

    // Heuristic B: Unencrypted HTTP Protocol
    if (urlObj.protocol === "http:") {
      heuristics.push("Uses unencrypted HTTP protocol");
    }

    // Heuristic C: Raw IP address as hostname (IPv4, IPv6, or integer notation)
    if (isRawIpAddress(domain)) {
      heuristics.push("Hostname is a raw IP address");
    }

    // Heuristic D: Suspicious Top-Level Domain (TLD)
    for (const tld of SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) {
        heuristics.push(`Uses a suspicious low-cost TLD (${tld})`);
        break;
      }
    }

    // Heuristic E: Phishing keyword combinations in subdomain / path
    const urlLower = urlString.toLowerCase();
    const matchedKeywords = PHISHING_KEYWORDS.filter(kw => urlLower.includes(kw));
    if (matchedKeywords.length >= 2) {
      heuristics.push(`Contains multiple phishing keywords: ${matchedKeywords.join(", ")}`);
    }

    // Heuristic F: Excessive subdomain nesting (e.g. login.secure.bank.evil.com)
    const hostParts = domain.split(".");
    if (hostParts.length >= 5 && !isRawIpAddress(domain)) {
      heuristics.push("Excessive subdomain nesting often used to disguise brand names");
    }

    // Heuristic G: Suspicious open redirect parameter pointing to external hosts
    const redirectParams = ["redirect", "redirect_url", "redirect_to", "return_to", "url", "dest", "destination", "next", "link", "target", "goto"];
    for (const [key, val] of urlObj.searchParams.entries()) {
      if (redirectParams.includes(key.toLowerCase())) {
        const lowerVal = val.toLowerCase().trim();
        if (lowerVal.startsWith("http://") || lowerVal.startsWith("https://") || lowerVal.startsWith("//")) {
          try {
            const targetUrl = new URL(lowerVal.startsWith("//") ? "https:" + lowerVal : lowerVal);
            if (targetUrl.hostname && targetUrl.hostname !== domain && !targetUrl.hostname.endsWith("." + domain)) {
              heuristics.push(`Contains external open redirect parameter (${key}) pointing to ${targetUrl.hostname}`);
              break;
            }
          } catch {
            // Malformed URL in parameter
          }
        }
      }
    }

    if (heuristics.length > 0) {
      const isCritical = heuristics.length >= 2 || heuristics.some(h => h.includes("raw IP address") || h.includes("embedded credentials"));
      return {
        safe: false,
        reason: heuristics.join("; "),
        severity: isCritical ? "critical" : "warning",
        details: heuristics
      };
    }

    return { safe: true, reason: "Heuristics pass" };
  }

  return {
    analyzeUrlSafety,
    isDomainWhitelisted,
    isSafeDomain,
    SAFE_DOMAINS,
    SUSPICIOUS_DOMAINS,
    SUSPICIOUS_TLDS,
    PHISHING_KEYWORDS
  };
});
