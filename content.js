// Content script for OSN Guard - runs on social pages and interactive inputs
(() => {
  "use strict";

  let shields = { pii: true, url: true, content: true, security: true };
  let localWhitelisted = [];
  let customPii = [];
  let isScannerInitialized = false;

  const SCANNED_ATTR = "data-osn-scanned";
  let pageThreats = [];
  let scanStats = { linksScanned: 0, threats: 0, siteProtected: false };
  let isInitialReportDone = false;

  // Active PII Alert Banners map: element -> { banner, lastPiiNames, lastSeverity }
  const activeAlertBanners = new Map();

  // Shared singleton floating tooltip container (attached directly to body to prevent overflow clipping)
  let sharedTooltip = null;

  function getSharedTooltip() {
    if (!sharedTooltip) {
      sharedTooltip = document.createElement("div");
      sharedTooltip.className = "osn-guard-floating-tooltip";
      sharedTooltip.style.display = "none";
      document.body.appendChild(sharedTooltip);
    }
    return sharedTooltip;
  }

  function showSharedTooltip(badgeElement, threat) {
    const tooltip = getSharedTooltip();
    tooltip.innerHTML = ""; // Safe as we construct DOM children

    const header = document.createElement("div");
    header.className = `osn-guard-tooltip-header ${threat.severity}`;
    const strong = document.createElement("strong");
    strong.textContent = `OSN Guard: ${threat.type}`;
    header.appendChild(strong);

    const body = document.createElement("div");
    body.className = "osn-guard-tooltip-body";
    body.textContent = threat.message;

    tooltip.appendChild(header);
    tooltip.appendChild(body);

    const rect = badgeElement.getBoundingClientRect();
    tooltip.style.display = "block";
    tooltip.style.opacity = "0";

    const tooltipRect = tooltip.getBoundingClientRect();
    let top = rect.top - tooltipRect.height - 8;
    let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);

    // Reposition below if above viewport
    if (top < 8) {
      top = rect.bottom + 8;
    }
    // Prevent horizontal overflow
    if (left < 8) left = 8;
    if (left + tooltipRect.width > window.innerWidth - 8) {
      left = window.innerWidth - tooltipRect.width - 8;
    }

    tooltip.style.top = `${Math.round(top)}px`;
    tooltip.style.left = `${Math.round(left)}px`;
    tooltip.style.opacity = "1";
  }

  function hideSharedTooltip() {
    if (sharedTooltip) {
      sharedTooltip.style.display = "none";
      sharedTooltip.style.opacity = "0";
    }
  }

  // Load configuration from extension storage
  function loadSettings(callback) {
    chrome.storage.local.get(["shields", "whitelistedDomains", "customPiiPatterns"], (data) => {
      if (data.shields) shields = data.shields;
      if (data.whitelistedDomains) localWhitelisted = data.whitelistedDomains;
      if (data.customPiiPatterns) customPii = data.customPiiPatterns;
      if (callback) callback();
    });
  }

  // Check if current hostname is whitelisted
  function isCurrentSiteWhitelisted() {
    if (typeof OSNUrlAnalyzer !== "undefined" && OSNUrlAnalyzer.isDomainWhitelisted) {
      return OSNUrlAnalyzer.isDomainWhitelisted(window.location.hostname, localWhitelisted);
    }
    return false;
  }

  // Watch for real-time setting changes
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local") {
      loadSettings(() => {
        if (isCurrentSiteWhitelisted()) {
          clearAllBadgesAndAlerts();
          pageThreats = [];
          reportCurrentThreats([], { linksScanned: 0, threats: 0, siteProtected: false });
          return;
        }

        if (!shields.pii) clearAllPiiAlerts();
        if (!shields.url) clearAllUrlBadges();
        if (!shields.content) clearAllContentBadges();
        if (!shields.security) clearAllFormBadges();

        scanPage();
      });
    }
  });

  // Listen for background commands (e.g. manual rescan request)
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "triggerRescan") {
      rescanPage();
      sendResponse({ status: "success", threatCount: pageThreats.length });
      return true;
    }
  });

  function rescanPage() {
    clearAllBadgesAndAlerts();
    document.querySelectorAll(`[${SCANNED_ATTR}]`).forEach(el => el.removeAttribute(SCANNED_ATTR));
    document.querySelectorAll("[data-osn-badged]").forEach(el => el.removeAttribute("data-osn-badged"));
    pageThreats = [];
    isInitialReportDone = false;
    scanPage();
  }

  function clearAllPiiAlerts() {
    document.querySelectorAll(".osn-guard-input-warning, .osn-guard-input-critical").forEach(el => {
      el.classList.remove("osn-guard-input-warning", "osn-guard-input-critical");
    });
    activeAlertBanners.forEach(({ banner }) => banner.remove());
    activeAlertBanners.clear();
  }

  function clearAllUrlBadges() {
    document.querySelectorAll(".osn-guard-tooltip-wrapper[data-threat-type='url']").forEach(el => el.remove());
  }

  function clearAllContentBadges() {
    document.querySelectorAll(".osn-guard-tooltip-wrapper[data-threat-type='content']").forEach(el => el.remove());
  }

  function clearAllFormBadges() {
    document.querySelectorAll(".osn-guard-tooltip-wrapper[data-threat-type='security']").forEach(el => el.remove());
  }

  function clearAllBadgesAndAlerts() {
    clearAllPiiAlerts();
    clearAllUrlBadges();
    clearAllContentBadges();
    clearAllFormBadges();
    hideSharedTooltip();
  }

  // Initialize Scanner
  function initScanner() {
    if (isScannerInitialized) return;
    isScannerInitialized = true;

    if (isCurrentSiteWhitelisted()) {
      scanStats.siteProtected = false;
      return;
    }

    scanStats.siteProtected = true;

    // Run initial scan
    setTimeout(scanPage, 1000);

    // Dynamic content observer for infinite scrolling feeds
    let scanTimeout = null;
    const observer = new MutationObserver((mutations) => {
      // Ignore mutations caused exclusively by OSN Guard elements
      const isExternalMutation = mutations.some(m => {
        return Array.from(m.addedNodes).some(node => {
          if (node.nodeType !== Node.ELEMENT_NODE) return false;
          const cls = typeof node.className === "string"
            ? node.className
            : (node.className && typeof node.className.baseVal === "string" ? node.className.baseVal : "");
          return !cls || !cls.includes("osn-guard");
        });
      });

      if (!isExternalMutation) return;

      clearTimeout(scanTimeout);
      scanTimeout = setTimeout(scanPage, 800);
    });

    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }

    // Event listeners for interactive inputs
    document.addEventListener("input", handleInputEvent, true);
    document.addEventListener("paste", handleInputEvent, true);

    // Keep PII alert banners aligned on scroll and window resize
    window.addEventListener("scroll", updateAllBannerPositions, { passive: true });
    window.addEventListener("resize", updateAllBannerPositions, { passive: true });
  }

  // Main Page Scanning Logic
  function scanPage() {
    if (isCurrentSiteWhitelisted()) return;
    if (!shields.url && !shields.content && !shields.security) return;

    let localThreats = [];
    let linksScannedCount = 0;
    let newThreatsCount = 0;

    // 1. LINK REPUTATION SCAN
    if (shields.url) {
      const links = document.querySelectorAll(`a:not([${SCANNED_ATTR}])`);
      links.forEach(link => {
        link.setAttribute(SCANNED_ATTR, "true");

        const href = link.href;
        if (!href || href.startsWith("javascript:") || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
          return;
        }

        linksScannedCount++;

        // Fast synchronous check if analyzer is loaded
        let result = null;
        if (typeof OSNUrlAnalyzer !== "undefined") {
          result = OSNUrlAnalyzer.analyzeUrlSafety(href, localWhitelisted);
          handleUrlResult(link, href, result);
        } else {
          // Fallback to background worker
          chrome.runtime.sendMessage({ action: "checkUrlSafety", url: href }, (response) => {
            if (chrome.runtime.lastError || !response) return;
            handleUrlResult(link, href, response);
          });
        }
      });
    }

    function handleUrlResult(link, href, response) {
      if (response && !response.safe) {
        newThreatsCount++;
        const threat = {
          id: "url-" + Math.random().toString(36).substring(2, 11),
          type: "Phishing / Malicious Link",
          severity: response.severity || "warning",
          message: response.reason,
          target: href
        };
        localThreats.push(threat);
        addUrlWarningBadge(link, threat);
        reportCurrentThreats([threat], { linksScanned: 0, threats: 1 });
      }
    }

    // 2. SCAM & SPAM CONTENT DETECTION
    if (shields.content) {
      const containers = getSocialTextContainers();
      containers.forEach(container => {
        container.setAttribute(SCANNED_ATTR, "true");
        const text = container.textContent || "";
        if (!text.trim()) return;

        let scamScan = { flagged: false };
        if (typeof OSNScamAnalyzer !== "undefined") {
          scamScan = OSNScamAnalyzer.detectScamContent(text);
        }

        if (scamScan.flagged) {
          newThreatsCount++;
          const threat = {
            id: "content-" + Math.random().toString(36).substring(2, 11),
            type: scamScan.category || "Suspicious Content",
            severity: scamScan.severity || "warning",
            message: scamScan.reason,
            target: text.trim().substring(0, 70) + (text.trim().length > 70 ? "..." : "")
          };
          localThreats.push(threat);
          addContentWarningBadge(container, threat);
        }
      });
    }

    // 3. INSECURE FORM SUBMISSION CHECKS
    if (shields.security) {
      const forms = document.querySelectorAll(`form:not([${SCANNED_ATTR}])`);
      forms.forEach(form => {
        form.setAttribute(SCANNED_ATTR, "true");
        const action = form.getAttribute("action") || "";

        if (action.startsWith("http://") && window.location.protocol === "https:") {
          newThreatsCount++;
          const threat = {
            id: "security-form-" + Math.random().toString(36).substring(2, 11),
            type: "Insecure Form Action",
            severity: "critical",
            message: "Form transmits data unencrypted over HTTP on a secure site.",
            target: form.id ? `#${form.id}` : (form.className ? `.${form.className.split(" ")[0]}` : "Form")
          };
          localThreats.push(threat);
          addFormWarningBadge(form, threat);
        }
      });
    }

    // Initial or incremental report
    if (linksScannedCount > 0 || newThreatsCount > 0 || !isInitialReportDone) {
      isInitialReportDone = true;
      reportCurrentThreats(localThreats, {
        linksScanned: linksScannedCount,
        threats: newThreatsCount,
        siteProtected: scanStats.siteProtected
      });
      // Reset siteProtected flag to prevent counting site multiple times on scroll mutations
      scanStats.siteProtected = false;
    }
  }

  // Report threats to background worker
  function reportCurrentThreats(newThreats, statsUpdate) {
    if (isCurrentSiteWhitelisted()) return;

    newThreats.forEach(nt => {
      if (!pageThreats.some(pt => pt.message === nt.message && pt.target === nt.target)) {
        pageThreats.push(nt);
      }
    });

    chrome.runtime.sendMessage({
      action: "reportThreats",
      threats: pageThreats,
      statsUpdate: statsUpdate
    });
  }

  // Platform-Specific Selectors for Social Containers
  function getSocialTextContainers() {
    const hostname = window.location.hostname;
    let selector = "p, .feed-text";

    if (hostname.includes("twitter.com") || hostname.includes("x.com")) {
      selector = '[data-testid="tweetText"], [data-testid="messageEntry"]';
    } else if (hostname.includes("facebook.com")) {
      selector = 'div[dir="auto"], [data-ad-preview="message"], .userContent';
    } else if (hostname.includes("linkedin.com")) {
      selector = '.feed-shared-update-v2__description-text, .feed-shared-text, .msg-s-event-listitem__body';
    } else if (hostname.includes("reddit.com")) {
      selector = 'div[data-click-id="text-content"], .RichTextJSON-root, [data-testid="post-container"] p';
    } else if (hostname.includes("threads.net")) {
      selector = 'div[dir="auto"], span[dir="auto"]';
    } else if (hostname.includes("bsky.app")) {
      selector = 'div[data-testid^="postContent"], div[dir="auto"]';
    } else if (hostname.includes("instagram.com")) {
      selector = 'h1, span._aacl, div._a9zs, ul._a9z6';
    } else if (hostname.includes("youtube.com")) {
      selector = '#content-text, ytd-comment-renderer #content-text';
    }

    const elements = document.querySelectorAll(selector);
    const unScanned = [];
    elements.forEach(el => {
      if (!el.hasAttribute(SCANNED_ATTR) && !el.closest(".osn-guard-tooltip-wrapper")) {
        unScanned.push(el);
      }
    });
    return unScanned;
  }

  // Badge Insertion
  function addUrlWarningBadge(linkElement, threat) {
    if (!linkElement || !linkElement.parentNode) return;
    if (linkElement.hasAttribute("data-osn-badged")) return;
    if (linkElement.nextElementSibling && linkElement.nextElementSibling.classList.contains("osn-guard-tooltip-wrapper")) return;

    linkElement.setAttribute("data-osn-badged", "true");
    const badgeWrapper = createBadge(threat, "url");
    linkElement.parentNode.insertBefore(badgeWrapper, linkElement.nextSibling);
  }

  function addContentWarningBadge(containerElement, threat) {
    if (!containerElement || containerElement.hasAttribute("data-osn-badged") || containerElement.querySelector(".osn-guard-warning-badge")) return;
    containerElement.setAttribute("data-osn-badged", "true");
    const badgeWrapper = createBadge(threat, "content");
    containerElement.appendChild(badgeWrapper);
  }

  function addFormWarningBadge(formElement, threat) {
    if (!formElement || formElement.hasAttribute("data-osn-badged") || formElement.querySelector(".osn-guard-warning-badge")) return;
    formElement.setAttribute("data-osn-badged", "true");
    const badgeWrapper = createBadge(threat, "security");
    if (formElement.firstChild) {
      formElement.insertBefore(badgeWrapper, formElement.firstChild);
    } else {
      formElement.appendChild(badgeWrapper);
    }
  }

  // Badge Element Construction with Hover Tooltip Trigger
  function createBadge(threat, threatType) {
    const badgeWrapper = document.createElement("span");
    badgeWrapper.className = "osn-guard-tooltip-wrapper";
    badgeWrapper.setAttribute("data-threat-type", threatType);

    const badge = document.createElement("span");
    badge.className = `osn-guard-warning-badge osn-guard-badge-${threat.severity}`;
    badge.textContent = "!";
    badge.setAttribute("role", "alert");
    badge.setAttribute("aria-label", `OSN Guard alert: ${threat.type}`);

    badge.addEventListener("mouseenter", () => showSharedTooltip(badge, threat));
    badge.addEventListener("mouseleave", hideSharedTooltip);

    badgeWrapper.appendChild(badge);
    return badgeWrapper;
  }

  // Input Field PII Leak Scanning
  function handleInputEvent(e) {
    if (!shields.pii || isCurrentSiteWhitelisted()) return;

    const target = e.target;
    if (!target) return;

    const isInputField = target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.getAttribute("contenteditable") === "true";
    if (!isInputField) return;

    clearTimeout(target._osnPiiTimeout);
    target._osnPiiTimeout = setTimeout(() => {
      const text = (target.tagName === "INPUT" || target.tagName === "TEXTAREA") ? target.value : target.innerText;
      inspectPii(target, text);
    }, 350);
  }

  function inspectPii(element, text) {
    if (!text || text.trim().length < 5) {
      removePiiWarning(element);
      return;
    }

    let detectedPii = [];
    if (typeof OSNPiiAnalyzer !== "undefined") {
      detectedPii = OSNPiiAnalyzer.detectPii(text, customPii);
    }

    if (detectedPii.length > 0) {
      const highestSeverity = detectedPii[0].severity;
      const uniqueNames = [...new Set(detectedPii.map(p => p.name))].join(", ");
      showPiiWarning(element, uniqueNames, highestSeverity);
    } else {
      removePiiWarning(element);
    }
  }

  function showPiiWarning(element, piiNames, severity) {
    element.classList.remove("osn-guard-input-warning", "osn-guard-input-critical");
    element.classList.add(`osn-guard-input-${severity}`);

    let record = activeAlertBanners.get(element);

    if (!record) {
      const banner = document.createElement("div");
      banner.className = "osn-guard-input-alert-banner";

      const icon = document.createElement("span");
      icon.className = `osn-guard-alert-icon ${severity}`;
      icon.textContent = "!";

      const textContainer = document.createElement("span");
      textContainer.className = "osn-guard-alert-text";

      const closeBtn = document.createElement("span");
      closeBtn.className = "close-btn";
      closeBtn.textContent = "×";
      closeBtn.title = "Dismiss alert";
      closeBtn.onclick = (e) => {
        e.stopPropagation();
        banner.remove();
        activeAlertBanners.delete(element);
      };

      banner.appendChild(icon);
      banner.appendChild(textContainer);
      banner.appendChild(closeBtn);

      document.body.appendChild(banner);
      record = { banner, icon, textContainer, lastPiiNames: "", lastSeverity: "" };
      activeAlertBanners.set(element, record);

      // Throttled stat reporting
      const now = Date.now();
      if (!element._lastPiiReportTime || now - element._lastPiiReportTime > 15000) {
        element._lastPiiReportTime = now;
        chrome.runtime.sendMessage({ action: "incrementPiiBlocked" });
      }
    }

    // Update banner message safely without innerHTML
    if (record.lastPiiNames !== piiNames || record.lastSeverity !== severity) {
      record.lastPiiNames = piiNames;
      record.lastSeverity = severity;

      record.icon.className = `osn-guard-alert-icon ${severity}`;

      record.textContainer.replaceChildren();
      const boldPrefix = document.createElement("strong");
      boldPrefix.textContent = "PII Alert: ";
      const msgPrefix = document.createTextNode("Sharing ");
      const boldName = document.createElement("strong");
      boldName.textContent = piiNames;
      const msgSuffix = document.createTextNode(" is unsafe on social sites.");

      record.textContainer.appendChild(boldPrefix);
      record.textContainer.appendChild(msgPrefix);
      record.textContainer.appendChild(boldName);
      record.textContainer.appendChild(msgSuffix);
    }

    positionBanner(element, record.banner);
  }

  function positionBanner(element, banner) {
    if (!element || !banner || !document.body.contains(element)) return;

    const rect = element.getBoundingClientRect();

    // If input element is invisible or hidden (e.g. modal dismissed), hide the banner
    if (rect.width === 0 && rect.height === 0) {
      banner.style.display = "none";
      return;
    }
    banner.style.display = "flex";

    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    let top = rect.top + scrollY - 36;
    if (top < scrollY) {
      top = rect.bottom + scrollY + 6;
    }

    banner.style.top = `${Math.round(top)}px`;
    banner.style.left = `${Math.round(Math.max(10, rect.left + scrollX))}px`;
  }

  function updateAllBannerPositions() {
    activeAlertBanners.forEach(({ banner }, element) => {
      positionBanner(element, banner);
    });
  }

  function removePiiWarning(element) {
    element.classList.remove("osn-guard-input-warning", "osn-guard-input-critical");
    const record = activeAlertBanners.get(element);
    if (record) {
      record.banner.remove();
      activeAlertBanners.delete(element);
    }
  }

  // Kickstart loader
  loadSettings(() => {
    if (Object.values(shields).some(v => v === true)) {
      initScanner();
    }
  });
})();
