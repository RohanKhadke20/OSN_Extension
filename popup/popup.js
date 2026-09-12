// JS control logic for OSN Guard Popup Dashboard

/**
 * Evaluates whether the user is eligible to see the ethical review prompt.
 * Local-only, frequency-capped, zero telemetry.
 *
 * Rules:
 * 1. Usage: >= 5 threats detected OR >= 50 links scanned
 * 2. Retention: Installed for at least 3 days (3 * 24 * 60 * 60 * 1000 ms)
 * 3. Never dismissed or completed: !reviewState.dismissed && !reviewState.completed
 * 4. Frequency cap: If deferred, cooldown of 14 days (14 * 24 * 60 * 60 * 1000 ms)
 *
 * @param {Object} data - Storage data containing stats, installedAt, reviewState
 * @param {number} [currentTime] - Current timestamp (defaults to Date.now())
 * @returns {{ eligible: boolean, reason?: string }}
 */
function isReviewPromptEligible(data, currentTime = Date.now()) {
  if (!data || typeof data !== "object") {
    return { eligible: false, reason: "No storage data available" };
  }

  const stats = data.stats || {};
  const threats = typeof stats.threatsDetected === "number" ? stats.threatsDetected : 0;
  const links = typeof stats.linksScanned === "number" ? stats.linksScanned : 0;

  // 1. Usage threshold
  if (threats < 5 && links < 50) {
    return { eligible: false, reason: "Usage threshold not met (need 5 threats or 50 links)" };
  }

  // 2. Minimum install retention (3 days)
  const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
  const installedAt = typeof data.installedAt === "number" ? data.installedAt : 0;
  if (installedAt <= 0 || (currentTime - installedAt) < THREE_DAYS_MS) {
    return { eligible: false, reason: "Minimum install age of 3 days not met" };
  }

  // 3. Not dismissed or already completed
  const reviewState = data.reviewState || {};
  if (reviewState.dismissed === true) {
    return { eligible: false, reason: "User previously dismissed review prompt" };
  }
  if (reviewState.completed === true) {
    return { eligible: false, reason: "User previously completed review" };
  }

  // 4. Frequency capping (14 days cooldown)
  const FOURTEEN_DAYS_MS = 14 * 24 * 60 * 60 * 1000;
  const lastPromptedAt = typeof reviewState.lastPromptedAt === "number" ? reviewState.lastPromptedAt : 0;
  if (lastPromptedAt > 0 && (currentTime - lastPromptedAt) < FOURTEEN_DAYS_MS) {
    return { eligible: false, reason: "Frequency cooldown active (prompted within last 14 days)" };
  }

  return { eligible: true };
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    "use strict";

  const settingsBtn = document.getElementById("settings-btn");
  const optionsLink = document.getElementById("view-options-link");
  const rescanBtn = document.getElementById("rescan-btn");
  const threatsContainer = document.getElementById("threats-container");

  // Stats elements
  const statScanned = document.getElementById("stat-scanned");
  const statPii = document.getElementById("stat-pii");
  const statThreats = document.getElementById("stat-threats");

  // Toggles
  const piiToggle = document.getElementById("shield-pii");
  const urlToggle = document.getElementById("shield-url");
  const contentToggle = document.getElementById("shield-content");
  const securityToggle = document.getElementById("shield-security");

  // Score elements
  const scoreValue = document.getElementById("score-value");
  const progressRing = document.querySelector(".progress-ring__circle");
  const statusText = document.getElementById("status-text");
  const statusDesc = document.getElementById("status-desc");

  let scoreAnimationInterval = null;
  let currentActiveTab = null;
  let whitelistedDomains = [];

  // Open settings
  const openOptions = () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL("options/options.html"));
    }
  };

  settingsBtn.addEventListener("click", openOptions);
  optionsLink.addEventListener("click", (e) => {
    e.preventDefault();
    openOptions();
  });

  // Review prompt elements
  const reviewPromptEl = document.getElementById("review-prompt");
  const reviewTextEl = document.getElementById("review-prompt-text");
  const reviewRateBtn = document.getElementById("review-rate-btn");
  const reviewLaterBtn = document.getElementById("review-later-btn");
  const reviewCloseBtn = document.getElementById("review-close-btn");

  // Local-only, ethical review prompt handler
  const checkReviewPromptEligibility = (data) => {
    if (!reviewPromptEl) return;

    // Seed installedAt if missing so the retention clock begins tracking locally
    if (!data || typeof data.installedAt !== "number" || data.installedAt <= 0) {
      const now = Date.now();
      chrome.storage.local.set({ installedAt: now });
      data = data || {};
      data.installedAt = now;
    }

    const { eligible } = isReviewPromptEligible(data);
    if (!eligible) {
      reviewPromptEl.classList.add("hidden");
      return;
    }

    const stats = data.stats || {};
    const threats = stats.threatsDetected || 0;
    const links = stats.linksScanned || 0;

    if (reviewTextEl) {
      if (threats > 0) {
        reviewTextEl.textContent = `OSN Guard has checked ${links} links and blocked ${threats} threats with zero external telemetry. If it has helped keep you safe, please consider leaving a review!`;
      } else {
        reviewTextEl.textContent = `OSN Guard has safely checked ${links} links with 100% local privacy. If you enjoy safe browsing, please consider leaving a quick review!`;
      }
    }

    reviewPromptEl.classList.remove("hidden");

    const hide = () => {
      reviewPromptEl.classList.add("hidden");
    };

    if (reviewRateBtn) {
      reviewRateBtn.onclick = () => {
        const reviewState = data.reviewState || {};
        const updated = {
          ...reviewState,
          dismissed: false,
          completed: true,
          lastPromptedAt: Date.now()
        };
        chrome.storage.local.set({ reviewState: updated }, () => {
          hide();
          const isFirefox = typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.includes("Firefox");
          const extensionId = (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id)
            ? chrome.runtime.id
            : "osn-guard";
          const reviewUrl = isFirefox
            ? "https://addons.mozilla.org/firefox/addon/osn-guard/"
            : `https://chromewebstore.google.com/detail/${extensionId}/reviews`;

          if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
            chrome.tabs.create({ url: reviewUrl });
          } else {
            window.open(reviewUrl, "_blank");
          }
        });
      };
    }

    if (reviewLaterBtn) {
      reviewLaterBtn.onclick = () => {
        const reviewState = data.reviewState || {};
        const updated = {
          ...reviewState,
          dismissed: false,
          completed: false,
          lastPromptedAt: Date.now()
        };
        chrome.storage.local.set({ reviewState: updated }, () => {
          hide();
        });
      };
    }

    if (reviewCloseBtn) {
      reviewCloseBtn.onclick = () => {
        const reviewState = data.reviewState || {};
        const updated = {
          ...reviewState,
          dismissed: true,
          completed: false,
          lastPromptedAt: Date.now()
        };
        chrome.storage.local.set({ reviewState: updated }, () => {
          hide();
        });
      };
    }
  };

  let managedShields = {};

  const fetchManagedPolicy = (callback) => {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ action: "getManagedPolicy" }, (response) => {
        if (!chrome.runtime.lastError && response && response.managed && response.managed.enforcedShields) {
          managedShields = response.managed.enforcedShields;
        }
        if (callback) callback();
      });
    } else if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.managed) {
      chrome.storage.managed.get("enforcedShields", (managedData) => {
        if (!chrome.runtime.lastError && managedData && managedData.enforcedShields) {
          managedShields = managedData.enforcedShields;
        }
        if (callback) callback();
      });
    } else {
      if (callback) callback();
    }
  };

  const applyManagedShields = () => {
    if (!managedShields || typeof managedShields !== "object") return;
    const toggles = {
      pii: piiToggle,
      url: urlToggle,
      content: contentToggle,
      security: securityToggle
    };
    for (const [key, isEnforced] of Object.entries(managedShields)) {
      if (toggles[key] && isEnforced === true) {
        toggles[key].checked = true;
        toggles[key].disabled = true;
        toggles[key].setAttribute("title", "Enforced by organization policy");
        const parentLabel = toggles[key].closest(".switch") || toggles[key].parentElement;
        if (parentLabel) {
          parentLabel.setAttribute("title", "Enforced by organization policy");
        }
      }
    }
  };

  // Load configuration and statistics
  const loadStatsAndSettings = (callback) => {
    fetchManagedPolicy(() => {
      chrome.storage.local.get(["shields", "stats", "whitelistedDomains", "installedAt", "reviewState"], (data) => {
        if (data.shields) {
          piiToggle.checked = !!data.shields.pii;
          urlToggle.checked = !!data.shields.url;
          contentToggle.checked = !!data.shields.content;
          securityToggle.checked = !!data.shields.security;
        }

        applyManagedShields();

        if (data.whitelistedDomains) {
          whitelistedDomains = data.whitelistedDomains;
        }

        if (data.stats) {
          statScanned.textContent = data.stats.linksScanned || 0;
          statPii.textContent = data.stats.piiBlockedCount || 0;
          statThreats.textContent = data.stats.threatsDetected || 0;
        }

        checkReviewPromptEligibility(data);

        if (callback) callback();
      });
    });
  };

  // Save checkbox updates
  const saveShields = () => {
    const shields = {
      pii: managedShields.pii === true ? true : piiToggle.checked,
      url: managedShields.url === true ? true : urlToggle.checked,
      content: managedShields.content === true ? true : contentToggle.checked,
      security: managedShields.security === true ? true : securityToggle.checked
    };

    chrome.storage.local.set({ shields }, () => {
      updateSafetyStatus();
    });
  };

  [piiToggle, urlToggle, contentToggle, securityToggle].forEach(toggle => {
    toggle.addEventListener("change", saveShields);
  });

  // Check if a URL belongs to a whitelisted domain
  const isUrlWhitelisted = (urlString) => {
    if (!urlString || typeof OSNUrlAnalyzer === "undefined") return false;
    try {
      const url = new URL(urlString);
      return OSNUrlAnalyzer.isDomainWhitelisted(url.hostname, whitelistedDomains);
    } catch {
      return false;
    }
  };

  // Check if current tab is a browser internal URL where extensions cannot run
  const isInternalUrl = (urlString) => {
    if (!urlString) return false;
    const lower = urlString.toLowerCase();
    return (
      lower.startsWith("chrome://") ||
      lower.startsWith("chrome-extension://") ||
      lower.startsWith("edge://") ||
      lower.startsWith("about:") ||
      lower.startsWith("view-source:")
    );
  };

  // Retrieve current active tab and scan result list
  const updateSafetyStatus = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) return;
      currentActiveTab = tabs[0];

      if (isInternalUrl(currentActiveTab.url)) {
        renderInternalState();
        animateScoreValue(100);
        setRingOffset(100);
        statusText.textContent = "System Page";
        statusText.style.color = "var(--text-secondary)";
        statusDesc.textContent = "Browser policy prevents script scanning on internal tabs.";
        progressRing.style.stroke = "var(--text-muted)";
        return;
      }

      if (isUrlWhitelisted(currentActiveTab.url)) {
        renderWhitelistedState();
        calculateScore([], true);
        return;
      }

      chrome.runtime.sendMessage(
        { action: "getThreatsForTab", tabId: currentActiveTab.id },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            renderEmptyState();
            calculateScore([]);
            return;
          }

          const rawThreats = Array.isArray(response.threats) ? response.threats : [];

          // Filter threats based on currently active shields
          const activeThreats = rawThreats.filter(threat => {
            if (threat.id && threat.id.startsWith("url-") && !urlToggle.checked) return false;
            if (threat.id && threat.id.startsWith("content-") && !contentToggle.checked) return false;
            if (threat.id && threat.id.startsWith("security-") && !securityToggle.checked) return false;
            return true;
          });

          if (activeThreats.length > 0) {
            renderThreats(activeThreats);
            calculateScore(activeThreats);
          } else {
            renderEmptyState();
            calculateScore([]);
          }
        }
      );
    });
  };

  // Render threats list safely without innerHTML
  const renderThreats = (threats) => {
    threatsContainer.replaceChildren();

    threats.forEach(threat => {
      const entry = document.createElement("div");
      entry.className = `threat-entry ${threat.severity || "warning"}`;

      const indicator = document.createElement("div");
      indicator.className = "threat-indicator";
      indicator.textContent = threat.severity === "critical" ? "🚨" : "⚠️";

      const info = document.createElement("div");
      info.className = "threat-info";

      const title = document.createElement("h5");
      title.textContent = threat.type || "Security Alert";

      const message = document.createElement("p");
      message.textContent = threat.message || "";

      const target = document.createElement("span");
      target.className = "target";
      target.textContent = threat.target || "";

      info.append(title, message, target);
      entry.append(indicator, info);
      threatsContainer.appendChild(entry);
    });
  };

  const renderEmptyState = () => {
    threatsContainer.replaceChildren();

    const empty = document.createElement("div");
    empty.className = "empty-state";

    const check = document.createElement("div");
    check.className = "success-check";
    check.textContent = "✓";

    const p = document.createElement("p");
    p.textContent = "No active threats detected on this tab.";

    empty.append(check, p);
    threatsContainer.appendChild(empty);
  };

  const renderWhitelistedState = () => {
    threatsContainer.replaceChildren();

    const empty = document.createElement("div");
    empty.className = "empty-state";

    const check = document.createElement("div");
    check.className = "success-check";
    check.textContent = "🌐";

    const p = document.createElement("p");
    p.textContent = "Domain is whitelisted. Shields bypassed.";

    empty.append(check, p);
    threatsContainer.appendChild(empty);
  };

  const renderInternalState = () => {
    threatsContainer.replaceChildren();

    const empty = document.createElement("div");
    empty.className = "empty-state";

    const check = document.createElement("div");
    check.className = "success-check";
    check.textContent = "ℹ️";

    const p = document.createElement("p");
    p.textContent = "Browser system page. Scanner is inactive here.";

    empty.append(check, p);
    threatsContainer.appendChild(empty);
  };

  // Score algorithm
  const calculateScore = (threats, isWhitelisted = false) => {
    let score = 100;

    if (isWhitelisted) {
      animateScoreValue(100);
      setRingOffset(100);
      statusText.textContent = "Domain Whitelisted";
      statusText.style.color = "var(--color-safe)";
      statusDesc.textContent = "All link and content scans bypassed per settings.";
      progressRing.style.stroke = "var(--color-safe)";
      return;
    }

    const criticalThreats = threats.filter(t => t.severity === "critical").length;
    const warningThreats = threats.filter(t => t.severity === "warning").length;

    score -= (criticalThreats * 25);
    score -= (warningThreats * 10);

    let activeShieldsCount = 0;
    const toggles = [piiToggle, urlToggle, contentToggle, securityToggle];
    toggles.forEach(t => {
      if (!t.checked) {
        score -= 5;
      } else {
        activeShieldsCount++;
      }
    });

    score = Math.max(0, Math.min(100, score));

    animateScoreValue(score);
    setRingOffset(score);
    updateStatusMessage(score, criticalThreats, warningThreats, activeShieldsCount);
  };

  const setRingOffset = (score) => {
    const circumference = 314.16;
    const offset = circumference - (score / 100) * circumference;
    progressRing.style.strokeDashoffset = offset;
  };

  const animateScoreValue = (targetScore) => {
    if (scoreAnimationInterval) {
      clearInterval(scoreAnimationInterval);
      scoreAnimationInterval = null;
    }

    let currentScore = parseInt(scoreValue.textContent, 10) || 0;
    if (currentScore === targetScore) {
      scoreValue.textContent = targetScore;
      return;
    }

    const step = targetScore > currentScore ? 1 : -1;
    scoreAnimationInterval = setInterval(() => {
      currentScore += step;
      scoreValue.textContent = currentScore;

      if (currentScore === targetScore) {
        clearInterval(scoreAnimationInterval);
        scoreAnimationInterval = null;
      }
    }, 15);
  };

  const updateStatusMessage = (score, critical, warnings, shieldsCount) => {
    if (shieldsCount === 0) {
      statusText.textContent = "Protection Offline";
      statusText.style.color = "var(--text-secondary)";
      statusDesc.textContent = "Enable shields to begin scanning this site.";
      progressRing.style.stroke = "var(--text-muted)";
      return;
    }

    if (score >= 90) {
      statusText.textContent = "Connection Secure";
      statusText.style.color = "var(--color-safe)";
      statusDesc.textContent = "All shields active. Browse with confidence.";
      progressRing.style.stroke = "var(--color-safe)";
    } else if (score >= 60) {
      statusText.textContent = "Caveats Found";
      statusText.style.color = "var(--color-warning)";
      statusDesc.textContent = `Warning: ${warnings} suspicious element(s) flagged.`;
      progressRing.style.stroke = "var(--color-warning)";
    } else {
      statusText.textContent = "High Risk Detected";
      statusText.style.color = "var(--color-critical)";
      statusDesc.textContent = `Alert: ${critical} critical security risk(s) active.`;
      progressRing.style.stroke = "var(--color-critical)";
    }
  };

  // Wire up in-page rescan without disruptive page reload
  rescanBtn.addEventListener("click", () => {
    if (!currentActiveTab || !currentActiveTab.id) return;

    rescanBtn.disabled = true;
    rescanBtn.textContent = "Scanning...";

    chrome.runtime.sendMessage({ action: "rescanTab", tabId: currentActiveTab.id }, () => {
      setTimeout(() => {
        updateSafetyStatus();
        loadStatsAndSettings(() => {
          rescanBtn.disabled = false;
          rescanBtn.textContent = "Rescan Page";
        });
      }, 700);
    });
  });

  // Initial load
  loadStatsAndSettings(() => {
    updateSafetyStatus();
  });
});
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    isReviewPromptEligible
  };
}

