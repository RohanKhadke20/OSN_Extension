// JS control logic for OSN Guard Popup Dashboard
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

  // Load configuration and statistics
  const loadStatsAndSettings = (callback) => {
    chrome.storage.local.get(["shields", "stats", "whitelistedDomains"], (data) => {
      if (data.shields) {
        piiToggle.checked = !!data.shields.pii;
        urlToggle.checked = !!data.shields.url;
        contentToggle.checked = !!data.shields.content;
        securityToggle.checked = !!data.shields.security;
      }

      if (data.whitelistedDomains) {
        whitelistedDomains = data.whitelistedDomains;
      }

      if (data.stats) {
        statScanned.textContent = data.stats.linksScanned || 0;
        statPii.textContent = data.stats.piiBlockedCount || 0;
        statThreats.textContent = data.stats.threatsDetected || 0;
      }

      if (callback) callback();
    });
  };

  // Save checkbox updates
  const saveShields = () => {
    const shields = {
      pii: piiToggle.checked,
      url: urlToggle.checked,
      content: contentToggle.checked,
      security: securityToggle.checked
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

  // Retrieve current active tab and scan result list
  const updateSafetyStatus = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) return;
      currentActiveTab = tabs[0];

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
