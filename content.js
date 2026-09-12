// Content script for OSN Guard - runs on social pages and interactive inputs
(() => {
  "use strict";

  let shields = { pii: true, url: true, content: true, security: true };
  let localWhitelisted = [];
  let customPii = [];
  let isScannerInitialized = false;

  const SCANNED_ATTR = "data-osn-scanned";
  const BATCH_TIME_BUDGET_MS = 10;
  const MAX_CONTAINERS_PER_BATCH = 30;
  const MAX_LINKS_PER_BATCH = 50;
  const MAX_PAGE_LINKS_LIMIT = 500;
  const MAX_PAGE_CONTAINERS_LIMIT = 200;

  let totalLinksScannedOnPage = 0;
  let totalContainersScannedOnPage = 0;
  let domObserver = null;
  let scanTimeout = null;

  let batchScheduleId = null;
  let isBatchRunning = false;

  let pageThreats = [];
  let scanStats = { linksScanned: 0, threats: 0, siteProtected: false };
  let isInitialReportDone = false;

  function cancelScheduledBatches() {
    if (batchScheduleId !== null) {
      if (typeof cancelIdleCallback === "function") {
        cancelIdleCallback(batchScheduleId);
      } else {
        clearTimeout(batchScheduleId);
      }
      batchScheduleId = null;
    }
  }

  function teardownScanner() {
    cancelScheduledBatches();
    if (domObserver) {
      try { domObserver.disconnect(); } catch { /* ignore */ }
      domObserver = null;
    }
    if (scanTimeout) {
      clearTimeout(scanTimeout);
      scanTimeout = null;
    }
    if (bannerRafId !== null) {
      cancelAnimationFrame(bannerRafId);
      bannerRafId = null;
    }
    try {
      document.removeEventListener("input", handleInputEvent, true);
      document.removeEventListener("paste", handleInputEvent, true);
      window.removeEventListener("scroll", scheduleBannerUpdate);
      window.removeEventListener("resize", scheduleBannerUpdate);
      window.removeEventListener("pagehide", cancelScheduledBatches);
      window.removeEventListener("beforeunload", cancelScheduledBatches);
    } catch { /* ignore */ }
    isScannerInitialized = false;
  }

  function safeSendMessage(message, callback) {
    try {
      if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.id) {
        teardownScanner();
        return;
      }
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          const msg = chrome.runtime.lastError.message || "";
          if (msg.includes("Extension context invalidated") || msg.includes("Could not establish connection")) {
            teardownScanner();
            return;
          }
        }
        if (typeof callback === "function") {
          callback(response);
        }
      });
    } catch (err) {
      if (err && err.message && err.message.includes("Extension context invalidated")) {
        teardownScanner();
      }
    }
  }

  function scheduleNextBatch() {
    if (batchScheduleId !== null || isBatchRunning) return;

    if (typeof requestIdleCallback === "function") {
      batchScheduleId = requestIdleCallback(() => {
        batchScheduleId = null;
        scanPage();
      }, { timeout: 150 });
    } else {
      batchScheduleId = setTimeout(() => {
        batchScheduleId = null;
        scanPage();
      }, 20);
    }
  }

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
    tooltip.replaceChildren();

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
    try {
      if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
        teardownScanner();
        return;
      }
      chrome.storage.local.get(["shields", "whitelistedDomains", "customPiiPatterns"], (data) => {
        if (chrome.runtime.lastError) {
          return;
        }
        if (data && data.shields) shields = data.shields;
        if (data && data.whitelistedDomains) localWhitelisted = data.whitelistedDomains;
        if (data && data.customPiiPatterns) customPii = data.customPiiPatterns;
        if (callback) callback();
      });
    } catch {
      teardownScanner();
    }
  }

  // Check if current hostname is whitelisted
  function isCurrentSiteWhitelisted() {
    if (typeof OSNUrlAnalyzer !== "undefined" && OSNUrlAnalyzer.isDomainWhitelisted) {
      return OSNUrlAnalyzer.isDomainWhitelisted(window.location.hostname, localWhitelisted);
    }
    return false;
  }

  // Watch for real-time setting changes
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
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
}

  // Listen for background commands (e.g. manual rescan request or context-menu scan results)
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "triggerRescan") {
      rescanPage();
      sendResponse({ status: "success", threatCount: pageThreats.length });
      return true;
    } else if (message.action === "displayScanResult") {
      handleScanResultToast(message);
      sendResponse({ status: "success" });
      return true;
    }
  });

  function handleScanResultToast(message) {
    if (message.targetType === "link") {
      const result = message.result || {};
      const urlText = (message.targetValue || "").length > 45
        ? message.targetValue.slice(0, 42) + "..."
        : (message.targetValue || "Target URL");

      if (result.safe) {
        showToastNotification({
          title: "Link Verified Safe",
          message: `${urlText} passed all safety checks.`,
          severity: "safe"
        });
      } else {
        const isCritical = result.severity === "critical";
        showToastNotification({
          title: isCritical ? "Dangerous Link Blocked" : "Suspicious Link Warning",
          message: `${result.reason || "Safety threat detected"} (${urlText})`,
          severity: result.severity || "warning"
        });
      }
    } else if (message.targetType === "selection") {
      const scam = message.scamResult || {};
      const pii = Array.isArray(message.piiResult) ? message.piiResult : [];

      if (scam.flagged && pii.length > 0) {
        const piiTypes = [...new Set(pii.map(p => p.name))].join(", ");
        showToastNotification({
          title: "Scam & Sensitive PII Detected",
          message: `${scam.category || "Scam lure"} detected with unmasked ${piiTypes}.`,
          severity: "critical"
        });
      } else if (scam.flagged) {
        showToastNotification({
          title: scam.category || "Scam Detected",
          message: scam.reason || "Content matches known fraud patterns.",
          severity: scam.severity || "warning"
        });
      } else if (pii.length > 0) {
        const piiTypes = [...new Set(pii.map(p => p.name))].join(", ");
        showToastNotification({
          title: "Sensitive PII Detected",
          message: `Identified ${pii.length} item(s): ${piiTypes}. Avoid sharing publicly.`,
          severity: pii[0].severity || "warning"
        });
      } else {
        showToastNotification({
          title: "Content Inspection Passed",
          message: "No fraud lures or sensitive personal information identified in selected text.",
          severity: "safe"
        });
      }
    }
  }

  function showToastNotification({ title, message, severity = "info", duration = 6000 }) {
    let container = document.getElementById("osn-guard-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "osn-guard-toast-container";
      container.className = "osn-guard-toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `osn-guard-toast osn-guard-toast-${severity}`;

    const icon = document.createElement("span");
    icon.className = `osn-guard-toast-icon ${severity}`;
    icon.textContent = severity === "critical" ? "✕" : (severity === "warning" ? "!" : "✓");

    const content = document.createElement("div");
    content.className = "osn-guard-toast-content";

    const titleEl = document.createElement("div");
    titleEl.className = "osn-guard-toast-title";
    titleEl.textContent = title;

    const messageEl = document.createElement("div");
    messageEl.className = "osn-guard-toast-message";
    messageEl.textContent = message;

    content.appendChild(titleEl);
    content.appendChild(messageEl);

    const closeBtn = document.createElement("button");
    closeBtn.className = "osn-guard-toast-close";
    closeBtn.textContent = "×";
    closeBtn.setAttribute("aria-label", "Close notification");
    closeBtn.onclick = () => {
      toast.classList.add("osn-guard-toast-fadeout");
      setTimeout(() => toast.remove(), 200);
    };

    toast.appendChild(icon);
    toast.appendChild(content);
    toast.appendChild(closeBtn);

    container.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => {
        if (toast.isConnected) {
          toast.classList.add("osn-guard-toast-fadeout");
          setTimeout(() => toast.remove(), 200);
        }
      }, duration);
    }
  }

  function rescanPage() {
    cancelScheduledBatches();
    clearAllBadgesAndAlerts();
    document.querySelectorAll(`[${SCANNED_ATTR}]`).forEach(el => el.removeAttribute(SCANNED_ATTR));
    document.querySelectorAll("[data-osn-badged]").forEach(el => el.removeAttribute("data-osn-badged"));
    pageThreats = [];
    totalLinksScannedOnPage = 0;
    totalContainersScannedOnPage = 0;
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
    cancelScheduledBatches();
    clearAllPiiAlerts();
    clearAllUrlBadges();
    clearAllContentBadges();
    clearAllFormBadges();
    hideSharedTooltip();
    const toastContainer = document.getElementById("osn-guard-toast-container");
    if (toastContainer) toastContainer.remove();
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
    domObserver = new MutationObserver((mutations) => {
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

      if (scanTimeout) clearTimeout(scanTimeout);
      cancelScheduledBatches();
      scanTimeout = setTimeout(scanPage, 800);
    });

    if (document.body) {
      domObserver.observe(document.body, { childList: true, subtree: true });
    }

    // Event listeners for interactive inputs
    document.addEventListener("input", handleInputEvent, true);
    document.addEventListener("paste", handleInputEvent, true);

    // Keep PII alert banners aligned on scroll and window resize (debounced via requestAnimationFrame)
    window.addEventListener("scroll", scheduleBannerUpdate, { passive: true });
    window.addEventListener("resize", scheduleBannerUpdate, { passive: true });

    // Clean up timers on tab unload / navigation
    window.addEventListener("pagehide", cancelScheduledBatches, { passive: true });
    window.addEventListener("beforeunload", cancelScheduledBatches, { passive: true });

    // Global Escape key listener to dismiss open tooltips
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        hideSharedTooltip();
        document.querySelectorAll('.osn-guard-warning-badge[aria-expanded="true"]').forEach(b => {
          b.setAttribute("aria-expanded", "false");
        });
      }
    });
  }

  // Main Page Scanning Logic (Frame-budgeted to prevent tasks exceeding 16ms)
  function scanPage() {
    if (isCurrentSiteWhitelisted()) return;
    if (!shields.url && !shields.content && !shields.security) return;

    isBatchRunning = true;
    let hasMoreWork = false;
    let localThreats = [];
    let linksScannedCount = 0;
    let newThreatsCount = 0;
    const batchStartTime = performance.now();
    const pendingBadges = [];

    try {
      // 1. LINK REPUTATION SCAN (Batched & Bounded)
      if (shields.url && totalLinksScannedOnPage < MAX_PAGE_LINKS_LIMIT) {
        const remainingCapacity = MAX_PAGE_LINKS_LIMIT - totalLinksScannedOnPage;
        const links = document.querySelectorAll(`a:not([${SCANNED_ATTR}])`);
        const batchSize = Math.min(links.length, MAX_LINKS_PER_BATCH, remainingCapacity);
        if (links.length > batchSize && totalLinksScannedOnPage + batchSize < MAX_PAGE_LINKS_LIMIT) {
          hasMoreWork = true;
        }

        for (let i = 0; i < batchSize; i++) {
          if (performance.now() - batchStartTime > BATCH_TIME_BUDGET_MS) {
            hasMoreWork = true;
            break;
          }

          const link = links[i];
          link.setAttribute(SCANNED_ATTR, "true");
          totalLinksScannedOnPage++;

          const href = link.href;
          if (!href || href.startsWith("javascript:") || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
            continue;
          }

          linksScannedCount++;

          // Fast synchronous check if analyzer is loaded
          if (typeof OSNUrlAnalyzer !== "undefined") {
            const result = OSNUrlAnalyzer.analyzeUrlSafety(href, localWhitelisted);
            if (result && !result.safe) {
              newThreatsCount++;
              const threat = {
                id: "url-" + Math.random().toString(36).substring(2, 11),
                type: "Phishing / Malicious Link",
                severity: result.severity || "warning",
                message: result.reason,
                target: href
              };
              localThreats.push(threat);
              pendingBadges.push({ type: "url", element: link, threat });
            }
          } else {
            // Fallback to background worker via safeSendMessage
            safeSendMessage({ action: "checkUrlSafety", url: href }, (response) => {
              if (!response || response.safe) return;
              const threat = {
                id: "url-" + Math.random().toString(36).substring(2, 11),
                type: "Phishing / Malicious Link",
                severity: response.severity || "warning",
                message: response.reason,
                target: href
              };
              addUrlWarningBadge(link, threat);
              reportCurrentThreats([threat], { linksScanned: 0, threats: 1 });
            });
          }
        }
      }

      // 2. SCAM & SPAM CONTENT DETECTION (Batched within remaining frame budget)
      if (shields.content && totalContainersScannedOnPage < MAX_PAGE_CONTAINERS_LIMIT && (performance.now() - batchStartTime < BATCH_TIME_BUDGET_MS)) {
        const remainingContainerCapacity = MAX_PAGE_CONTAINERS_LIMIT - totalContainersScannedOnPage;
        const containers = getSocialTextContainers();
        const batchSize = Math.min(containers.length, MAX_CONTAINERS_PER_BATCH, remainingContainerCapacity);
        if (containers.length > batchSize && totalContainersScannedOnPage + batchSize < MAX_PAGE_CONTAINERS_LIMIT) {
          hasMoreWork = true;
        }

        for (let i = 0; i < batchSize; i++) {
          if (performance.now() - batchStartTime > BATCH_TIME_BUDGET_MS) {
            hasMoreWork = true;
            break;
          }

          const container = containers[i];
          container.setAttribute(SCANNED_ATTR, "true");
          totalContainersScannedOnPage++;
          const text = container.textContent || "";
          if (!text.trim()) continue;

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
            pendingBadges.push({ type: "content", element: container, threat });
          }
        }
      } else if (shields.content && totalContainersScannedOnPage < MAX_PAGE_CONTAINERS_LIMIT) {
        hasMoreWork = true;
      }

      // 3. INSECURE FORM SUBMISSION CHECKS (Batched within remaining frame budget)
      if (shields.security && (performance.now() - batchStartTime < BATCH_TIME_BUDGET_MS)) {
        const forms = document.querySelectorAll(`form:not([${SCANNED_ATTR}])`);
        forms.forEach(form => {
          form.setAttribute(SCANNED_ATTR, "true");
          const actionAttr = (form.getAttribute("action") || "").trim();
          const targetName = form.id ? `#${form.id}` : (form.className ? `.${form.className.split(" ")[0]}` : "Form");

          // Check A: Mixed content submission (HTTP action on HTTPS origin)
          if (actionAttr.startsWith("http://") && window.location.protocol === "https:") {
            newThreatsCount++;
            const threat = {
              id: "security-form-" + Math.random().toString(36).substring(2, 11),
              type: "Insecure Form Action",
              severity: "critical",
              message: "Form transmits data unencrypted over HTTP on a secure site (mixed content).",
              target: targetName
            };
            localThreats.push(threat);
            pendingBadges.push({ type: "security", element: form, threat });
            return;
          }

          // Check B: Dangerous URI schemes in form action (javascript:, data:)
          const lowerAction = actionAttr.toLowerCase();
          if (lowerAction.startsWith("javascript:") || lowerAction.startsWith("data:")) {
            newThreatsCount++;
            const threat = {
              id: "security-form-" + Math.random().toString(36).substring(2, 11),
              type: "Malicious Form Action",
              severity: "critical",
              message: `Dangerous execution scheme in form action (${lowerAction.split(":")[0]}:).`,
              target: targetName
            };
            localThreats.push(threat);
            pendingBadges.push({ type: "security", element: form, threat });
            return;
          }

          // Check C: Form destination URL safety analysis (phishing domains, raw IPs, IDN homographs, shorteners)
          if (actionAttr.startsWith("http://") || actionAttr.startsWith("https://") || actionAttr.startsWith("//")) {
            const fullActionUrl = actionAttr.startsWith("//") ? window.location.protocol + actionAttr : actionAttr;
            if (typeof OSNUrlAnalyzer !== "undefined" && OSNUrlAnalyzer.analyzeUrlSafety) {
              const actionSafety = OSNUrlAnalyzer.analyzeUrlSafety(fullActionUrl, localWhitelisted);
              if (!actionSafety.safe) {
                newThreatsCount++;
                const threat = {
                  id: "security-form-" + Math.random().toString(36).substring(2, 11),
                  type: "Phishing Form Action",
                  severity: actionSafety.severity || "critical",
                  message: `Form submits to untrusted destination: ${actionSafety.reason}`,
                  target: targetName
                };
                localThreats.push(threat);
                pendingBadges.push({ type: "security", element: form, threat });
                return;
              }
            }
          }

          // Check D: Cross-origin password or payment credential harvesting
          const hasCredentialField = Boolean(
            form.querySelector("input[type='password']") ||
            form.querySelector("input[autocomplete='current-password']") ||
            form.querySelector("input[autocomplete='cc-number']")
          );

          if (hasCredentialField && (actionAttr.startsWith("http://") || actionAttr.startsWith("https://") || actionAttr.startsWith("//"))) {
            try {
              const fullAction = actionAttr.startsWith("//") ? window.location.protocol + actionAttr : actionAttr;
              const actionHost = new URL(fullAction).hostname.toLowerCase().replace(/\.+$/, "");
              const currentHost = window.location.hostname.toLowerCase().replace(/\.+$/, "");
              const isSameDomain = actionHost === currentHost || actionHost.endsWith("." + currentHost) || currentHost.endsWith("." + actionHost);

              if (!isSameDomain && typeof OSNUrlAnalyzer !== "undefined") {
                const isActionWhitelisted = OSNUrlAnalyzer.isDomainWhitelisted(actionHost, localWhitelisted);
                const isActionSafe = OSNUrlAnalyzer.isSafeDomain(actionHost);

                if (!isActionWhitelisted && !isActionSafe) {
                  newThreatsCount++;
                  const threat = {
                    id: "security-form-" + Math.random().toString(36).substring(2, 11),
                    type: "Credential Harvester Form",
                    severity: "critical",
                    message: `Credential form submits passwords/payment data to external unverified domain (${actionHost}).`,
                    target: targetName
                  };
                  localThreats.push(threat);
                  pendingBadges.push({ type: "security", element: form, threat });
                }
              }
            } catch {
              // ignore malformed action URLs
            }
          }
        });
      }

      // Phase B: Batch Apply DOM Modifications (Avoids interleaving layout reads/writes)
      for (let i = 0; i < pendingBadges.length; i++) {
        const item = pendingBadges[i];
        if (item.type === "url") {
          addUrlWarningBadge(item.element, item.threat);
        } else if (item.type === "content") {
          addContentWarningBadge(item.element, item.threat);
        } else if (item.type === "security") {
          addFormWarningBadge(item.element, item.threat);
        }
      }

      // Initial or incremental report in single consolidated IPC call
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
    } finally {
      isBatchRunning = false;
    }

    // If remaining unscanned nodes exist, queue the next batch in idle time
    if (hasMoreWork) {
      scheduleNextBatch();
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

    safeSendMessage({
      action: "reportThreats",
      threats: pageThreats,
      statsUpdate: statsUpdate
    });
  }

  // Platform-Specific Selectors for Social Containers
  function getSocialTextContainers() {
    const hostname = window.location.hostname;
    let selector = ".feed-text, p";

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

    const unscannedSelector = selector
      .split(",")
      .map(part => `${part.trim()}:not([${SCANNED_ATTR}])`)
      .join(", ");

    let elements;
    try {
      elements = document.querySelectorAll(unscannedSelector);
    } catch {
      elements = document.querySelectorAll(selector);
    }

    const unScanned = [];
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i];
      const cls = typeof el.className === "string" ? el.className : "";
      if (!el.hasAttribute(SCANNED_ATTR) && !cls.includes("osn-guard")) {
        unScanned.push(el);
      }
    }
    return unScanned;
  }

  // Badge Insertion (O(1) guard check without forced layout or subtree query)
  function addUrlWarningBadge(linkElement, threat) {
    if (!linkElement || !linkElement.parentNode || linkElement.hasAttribute("data-osn-badged")) return;

    linkElement.setAttribute("data-osn-badged", "true");
    const badgeWrapper = createBadge(threat, "url");
    linkElement.parentNode.insertBefore(badgeWrapper, linkElement.nextSibling);
  }

  function addContentWarningBadge(containerElement, threat) {
    if (!containerElement || containerElement.hasAttribute("data-osn-badged")) return;
    containerElement.setAttribute("data-osn-badged", "true");
    const badgeWrapper = createBadge(threat, "content");
    containerElement.appendChild(badgeWrapper);
  }

  function addFormWarningBadge(formElement, threat) {
    if (!formElement || formElement.hasAttribute("data-osn-badged")) return;
    formElement.setAttribute("data-osn-badged", "true");
    const badgeWrapper = createBadge(threat, "security");
    if (formElement.firstChild) {
      formElement.insertBefore(badgeWrapper, formElement.firstChild);
    } else {
      formElement.appendChild(badgeWrapper);
    }
  }

  // Badge Element Construction with Accessible Keyboard & Hover Tooltip Triggers
  function createBadge(threat, threatType) {
    const badgeWrapper = document.createElement("span");
    badgeWrapper.className = "osn-guard-tooltip-wrapper";
    badgeWrapper.setAttribute("data-threat-type", threatType);

    const badge = document.createElement("span");
    badge.className = `osn-guard-warning-badge osn-guard-badge-${threat.severity}`;
    badge.textContent = "!";
    badge.setAttribute("role", "button");
    badge.setAttribute("tabindex", "0");
    badge.setAttribute("aria-haspopup", "dialog");
    badge.setAttribute("aria-expanded", "false");
    badge.setAttribute("aria-label", `OSN Guard alert: ${threat.type}. Press Enter or Space to view details.`);

    let isTooltipOpen = false;

    function openTooltip() {
      showSharedTooltip(badge, threat);
      badge.setAttribute("aria-expanded", "true");
      isTooltipOpen = true;
    }

    function closeTooltip() {
      hideSharedTooltip();
      badge.setAttribute("aria-expanded", "false");
      isTooltipOpen = false;
    }

    badge.addEventListener("mouseenter", openTooltip);
    badge.addEventListener("mouseleave", () => {
      if (document.activeElement !== badge) {
        closeTooltip();
      }
    });

    badge.addEventListener("focus", openTooltip);
    badge.addEventListener("blur", closeTooltip);

    badge.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (isTooltipOpen) {
          closeTooltip();
        } else {
          openTooltip();
        }
      } else if (e.key === "Escape") {
        if (isTooltipOpen) {
          e.preventDefault();
          e.stopPropagation();
          closeTooltip();
        }
      }
    });

    badgeWrapper.appendChild(badge);
    return badgeWrapper;
  }

  // Input Field PII Leak Scanning
  function handleInputEvent(e) {
    if (!shields.pii || isCurrentSiteWhitelisted()) return;

    const target = e.target;
    if (!target) return;

    // Ignore password inputs, hidden tokens, and file uploads
    if (target.type === "password" || target.type === "hidden" || target.type === "file") return;

    const isInputField = target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.getAttribute("contenteditable") === "true";
    if (!isInputField) return;

    // Fast check for paste events (50ms) vs debounce for typing (300ms)
    const delay = e.type === "paste" ? 50 : 300;

    clearTimeout(target._osnPiiTimeout);
    target._osnPiiTimeout = setTimeout(() => {
      // Use textContent for contenteditable to avoid forced synchronous layout reflows
      const text = (target.tagName === "INPUT" || target.tagName === "TEXTAREA")
        ? target.value
        : (target.textContent || "");
      inspectPii(target, text);
    }, delay);
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
        safeSendMessage({ action: "incrementPiiBlocked" });
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
    if (!element || !banner) return;
    if (!document.body.contains(element)) {
      banner.remove();
      activeAlertBanners.delete(element);
      return;
    }

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

  let bannerRafId = null;

  function scheduleBannerUpdate() {
    if (activeAlertBanners.size === 0 || bannerRafId !== null) return;
    bannerRafId = requestAnimationFrame(() => {
      bannerRafId = null;
      updateAllBannerPositions();
    });
  }

  function updateAllBannerPositions() {
    if (activeAlertBanners.size === 0) return;

    // Phase 1: Batch all geometric reads
    const updates = [];
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    activeAlertBanners.forEach(({ banner }, element) => {
      if (!document.body.contains(element)) {
        banner.remove();
        activeAlertBanners.delete(element);
        return;
      }
      const rect = element.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        updates.push({ banner, display: "none" });
        return;
      }
      let top = rect.top + scrollY - 36;
      if (top < scrollY) {
        top = rect.bottom + scrollY + 6;
      }
      const left = Math.round(Math.max(10, rect.left + scrollX));
      updates.push({ banner, display: "flex", top: Math.round(top), left });
    });

    // Phase 2: Batch all style mutations
    for (let i = 0; i < updates.length; i++) {
      const u = updates[i];
      u.banner.style.display = u.display;
      if (u.display !== "none") {
        u.banner.style.top = `${u.top}px`;
        u.banner.style.left = `${u.left}px`;
      }
    }
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
