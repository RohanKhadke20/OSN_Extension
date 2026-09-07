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

  // Known URL shortening services frequently abused to conceal phishing/scam destinations
  const SHORTENER_DOMAINS = new Set([
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "v.gd",
    "buff.ly",
    "ow.ly",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
    "bc.vc",
    "t.ly",
    "soo.gd",
    "clck.ru",
    "rotf.lol",
    "s.id",
    "shorte.st"
  ]);

  // IP address regex patterns (IPv4, IPv6, octal/hex dotted, and dword representations)
  const IPV4_PATTERN = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const IPV6_PATTERN = /^(?:\[[0-9a-fA-F:]+\]|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})$/;
  const DWORD_IP_PATTERN = /^(?:0x[0-9a-fA-F]+|\d{8,11})$/;
  const DOTTED_OCTAL_HEX_IP_PATTERN = /^(?:0x[0-9a-fA-F]{1,4}|0[0-7]{1,6}|\d{1,4})(?:\.(?:0x[0-9a-fA-F]{1,4}|0[0-7]{1,6}|\d{1,4})){1,3}$/;

  // Unicode character blocks for detecting mixed-script confusable homoglyphs
  const CYRILLIC_PATTERN = /[\u0400-\u04FF]/;
  const GREEK_PATTERN = /[\u0370-\u03FF]/;
  const LATIN_PATTERN = /[a-zA-Z]/;

  // Dangerous URI schemes that can carry obfuscated scripts, file system exploits, or payload data
  const DANGEROUS_SCHEMES = new Set(["data:", "blob:", "file:", "filesystem:"]);

  // Open redirect query parameter names commonly used across platforms
  const REDIRECT_PARAM_NAMES = new Set([
    "redirect", "redirect_url", "redirect_to", "return_to", "return",
    "url", "dest", "destination", "next", "link", "target", "goto",
    "out", "forward", "redir", "r", "u"
  ]);

  /**
   * Checks if a given hostname is a raw IP address (IPv4, IPv6, octal/hex, or integer notation)
   * @param {string} host - Hostname string
   * @returns {boolean}
   */
  function isRawIpAddress(host) {
    if (!host) return false;
    return IPV4_PATTERN.test(host) ||
      IPV6_PATTERN.test(host) ||
      DWORD_IP_PATTERN.test(host) ||
      DOTTED_OCTAL_HEX_IP_PATTERN.test(host);
  }

  /**
   * Detects mixed-script confusable homoglyphs (e.g. Cyrillic/Greek letters mixed with Latin)
   * @param {string} str - String to inspect
   * @returns {boolean}
   */
  function hasMixedScriptConfusables(str) {
    if (!str || typeof str !== "string") return false;
    const hasLatin = LATIN_PATTERN.test(str);
    const hasCyrillic = CYRILLIC_PATTERN.test(str);
    const hasGreek = GREEK_PATTERN.test(str);
    return (hasLatin && hasCyrillic) || (hasLatin && hasGreek);
  }

  /**
   * Checks if a domain is a known URL shortener service
   * @param {string} domain - Hostname to check
   * @returns {boolean}
   */
  function isUrlShortener(domain) {
    if (!domain) return false;
    const clean = domain.toLowerCase().replace(/\.+$/, "");
    const hostWithoutWww = clean.startsWith("www.") ? clean.slice(4) : clean;
    if (SHORTENER_DOMAINS.has(hostWithoutWww)) return true;
    for (const shortener of SHORTENER_DOMAINS) {
      if (hostWithoutWww.endsWith("." + shortener)) return true;
    }
    return false;
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

    const cleanHost = hostname.toLowerCase().trim().replace(/\.+$/, "");

    return whitelistedDomains.some(entry => {
      if (!entry) return false;
      let cleanEntry = entry.toLowerCase().trim().replace(/\.+$/, "");
      
      // Strip scheme if present
      if (cleanEntry.startsWith("http://") || cleanEntry.startsWith("https://")) {
        try {
          cleanEntry = new URL(cleanEntry).hostname.replace(/\.+$/, "");
        } catch {
          cleanEntry = cleanEntry.replace(/^https?:\/\//, "").replace(/\.+$/, "");
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
    if (!domain) return false;
    const cleanDomain = domain.toLowerCase().replace(/\.+$/, "");
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
   * Extracts a potential external redirect target URL from query parameters
   * @param {URL} urlObj - Parsed URL object
   * @returns {string|null} - Decoded target URL string if found, or null
   */
  function extractRedirectTarget(urlObj) {
    if (!urlObj || !urlObj.searchParams) return null;
    const pathname = (urlObj.pathname || "").toLowerCase();

    for (const [key, val] of urlObj.searchParams.entries()) {
      if (!val) continue;
      const lowerKey = key.toLowerCase();
      const lowerVal = val.toLowerCase().trim();

      // Known redirect parameter, or 'q' on redirect endpoints (e.g. google /url?q= or youtube /redirect?q=)
      const isRedirectKey = REDIRECT_PARAM_NAMES.has(lowerKey) ||
        (lowerKey === "q" && (pathname.includes("/url") || pathname.includes("/redirect") || pathname.includes("/redir")));

      if (isRedirectKey) {
        if (lowerVal.startsWith("http://") || lowerVal.startsWith("https://") || lowerVal.startsWith("//")) {
          return val.trim();
        }
      }
    }
    return null;
  }

  /**
   * Extracts candidate hostname from a URL string before parsing
   * @param {string} str - Raw URL string
   * @returns {string} - Extracted host or empty string
   */
  function extractCandidateHost(str) {
    if (!str || typeof str !== "string") return "";
    try {
      const match = str.trim().toLowerCase().match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/?#]+)/i);
      if (!match || !match[1]) return "";
      const hostPort = match[1].includes("@") ? match[1].split("@").pop() : match[1];
      return hostPort.split(":")[0].replace(/\.+$/, "");
    } catch {
      return "";
    }
  }

  /**
   * Analyzes the safety of a given URL
   * @param {string} urlString - The URL string to inspect
   * @param {Array<string>} whitelistedDomains - Optional user-configured whitelist
   * @param {number} _depth - Internal recursion depth guard for redirect analysis
   * @returns {{ safe: boolean, reason: string, severity?: "warning" | "critical", details?: Array<string> }}
   */
  function analyzeUrlSafety(urlString, whitelistedDomains = [], _depth = 0) {
    if (!urlString || typeof urlString !== "string") {
      return { safe: false, reason: "Missing or invalid URL parameter", severity: "warning" };
    }

    // Ignore benign non-http schemes without flagging as threats
    const trimmed = urlString.trim().toLowerCase();
    if (trimmed.startsWith("javascript:") || trimmed.startsWith("#") || trimmed.startsWith("mailto:") || trimmed.startsWith("tel:")) {
      return { safe: true, reason: "Ignored internal or interactive scheme" };
    }

    // Early detection of Punycode (IDN) or mixed-script confusable homograph attempts
    const candidateHost = extractCandidateHost(trimmed);
    if (
      trimmed.includes("://xn--") ||
      trimmed.includes(".xn--") ||
      trimmed.startsWith("xn--") ||
      (candidateHost && hasMixedScriptConfusables(candidateHost))
    ) {
      return {
        safe: false,
        reason: "Punycode (IDN) or mixed-script confusable domain detected: potential spoofing or homograph phishing",
        severity: "critical"
      };
    }

    let urlObj;
    try {
      urlObj = new URL(urlString);
    } catch {
      return { safe: false, reason: "Invalid or malformed URL", severity: "warning" };
    }

    // Check dangerous schemes (data:, blob:, file:, filesystem:)
    if (DANGEROUS_SCHEMES.has(urlObj.protocol)) {
      return {
        safe: false,
        reason: `Dangerous URI scheme detected (${urlObj.protocol}): potential exploit or obfuscated payload`,
        severity: "critical"
      };
    }

    const domain = urlObj.hostname.toLowerCase().replace(/\.+$/, "");

    // Check 1: User Whitelist
    if (isDomainWhitelisted(domain, whitelistedDomains)) {
      return { safe: true, reason: "Domain is in user whitelist" };
    }

    // Check Open Redirect on Any Domain (including well-known safe platforms)
    const redirectTarget = extractRedirectTarget(urlObj);
    if (redirectTarget) {
      let targetUrl;
      try {
        targetUrl = new URL(redirectTarget.startsWith("//") ? "https:" + redirectTarget : redirectTarget);
      } catch {
        // Malformed redirect destination
      }

      if (targetUrl && targetUrl.hostname) {
        const targetDomain = targetUrl.hostname.toLowerCase().replace(/\.+$/, "");
        const isInternalRedirect = targetDomain === domain || targetDomain.endsWith("." + domain);

        if (!isInternalRedirect) {
          // Recursively inspect destination safety if within recursion limit
          if (_depth < 2) {
            const destResult = analyzeUrlSafety(targetUrl.href, whitelistedDomains, _depth + 1);
            if (!destResult.safe) {
              return {
                safe: false,
                reason: `Open redirect leads to unsafe destination (${targetDomain}): ${destResult.reason}`,
                severity: "critical",
                details: [`Redirect target: ${targetUrl.href}`, ...(destResult.details || [])]
              };
            }
          }

          // If hosted on a safe domain but redirecting to an unverified external destination
          if (isSafeDomain(domain)) {
            const targetIsSafe = isSafeDomain(targetDomain) || isDomainWhitelisted(targetDomain, whitelistedDomains);
            if (!targetIsSafe) {
              return {
                safe: false,
                reason: `Open redirect on trusted domain pointing to external unverified destination (${targetDomain})`,
                severity: "warning",
                details: [`Redirect target: ${targetUrl.href}`]
              };
            }
          }
        }
      }
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

    // Check 4: IDN Homograph / Punycode Attacks and Mixed-Script Confusables
    if (
      domain.startsWith("xn--") ||
      domain.includes(".xn--") ||
      hasMixedScriptConfusables(domain) ||
      (candidateHost && hasMixedScriptConfusables(candidateHost))
    ) {
      return {
        safe: false,
        reason: "Punycode (IDN) or mixed-script confusable domain detected: potential spoofing or homograph phishing",
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
    if (redirectTarget) {
      heuristics.push("Contains external open redirect parameter pointing to external host");
    }

    // Heuristic H: URL Shortener / Destination Obscurity
    if (isUrlShortener(domain)) {
      heuristics.push("URL shortener detected: destination target is obscured");
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
    isRawIpAddress,
    hasMixedScriptConfusables,
    isUrlShortener,
    SAFE_DOMAINS,
    SUSPICIOUS_DOMAINS,
    SUSPICIOUS_TLDS,
    PHISHING_KEYWORDS,
    SHORTENER_DOMAINS
  };
});
