// JS Logic for OSN Guard Options Configuration
document.addEventListener("DOMContentLoaded", () => {
  "use strict";

  // Elements
  const closeBtn = document.getElementById("close-options-btn");
  const saveSuccessAlert = document.getElementById("save-success");

  // Custom PII Elements
  const newPiiName = document.getElementById("new-pii-name");
  const newPiiPattern = document.getElementById("new-pii-pattern");
  const newPiiSeverity = document.getElementById("new-pii-severity");
  const addPiiBtn = document.getElementById("add-pii-btn");
  const piiRulesContainer = document.getElementById("pii-rules-container");

  // Whitelist Elements
  const newWhitelistDomain = document.getElementById("new-whitelist-domain");
  const addWhitelistBtn = document.getElementById("add-whitelist-btn");
  const whitelistContainer = document.getElementById("whitelist-container");

  // Stats Elements
  const optStatLinks = document.getElementById("opt-stat-links");
  const optStatPii = document.getElementById("opt-stat-pii");
  const optStatThreats = document.getElementById("opt-stat-threats");
  const optStatSites = document.getElementById("opt-stat-sites");

  // Danger actions
  const resetStatsBtn = document.getElementById("reset-stats-btn");
  const factoryResetBtn = document.getElementById("factory-reset-btn");

  let localPiiRules = [];
  let localWhitelist = [];

  // Helper to show success notice
  const triggerSuccessAlert = (message = "Settings updated successfully.") => {
    saveSuccessAlert.textContent = `✓ ${message}`;
    saveSuccessAlert.style.display = "block";
    setTimeout(() => {
      saveSuccessAlert.style.display = "none";
    }, 3000);
  };

  // Close Settings
  closeBtn.addEventListener("click", () => {
    try {
      window.close();
    } catch {
      // Ignored if browser blocks window.close()
    }
    closeBtn.textContent = "Saved";
    setTimeout(() => {
      closeBtn.textContent = "Done";
    }, 1500);
  });

  // Load and Render Option lists
  const loadConfig = () => {
    chrome.storage.local.get(["customPiiPatterns", "whitelistedDomains", "stats"], (data) => {
      localPiiRules = Array.isArray(data.customPiiPatterns) ? data.customPiiPatterns : [];
      localWhitelist = Array.isArray(data.whitelistedDomains) ? data.whitelistedDomains : [];

      // Ensure every rule has an ID
      localPiiRules.forEach((rule, idx) => {
        if (!rule.id) {
          rule.id = "rule_" + Date.now() + "_" + idx;
        }
      });

      renderPiiRules();
      renderWhitelist();
      renderStats(data.stats);
    });
  };

  const renderStats = (stats = {}) => {
    optStatLinks.textContent = stats.linksScanned || 0;
    optStatPii.textContent = stats.piiBlockedCount || 0;
    optStatThreats.textContent = stats.threatsDetected || 0;
    optStatSites.textContent = stats.sitesProtected || 0;
  };

  // Render PII Rules safely without innerHTML
  const renderPiiRules = () => {
    piiRulesContainer.replaceChildren();

    if (localPiiRules.length === 0) {
      const emptyNotice = document.createElement("div");
      emptyNotice.style.cssText = "text-align:center; padding:12px; color:var(--text-muted); font-size:12px;";
      emptyNotice.textContent = "No custom PII filters configured.";
      piiRulesContainer.appendChild(emptyNotice);
      return;
    }

    localPiiRules.forEach(rule => {
      const row = document.createElement("div");
      row.className = "item-row";

      const details = document.createElement("div");

      const strongName = document.createElement("strong");
      strongName.textContent = rule.name;

      const badge = document.createElement("span");
      badge.className = `badge-tag ${rule.severity || "warning"}`;
      badge.textContent = rule.severity || "warning";

      const br = document.createElement("br");

      const patternDesc = document.createElement("span");
      patternDesc.style.fontSize = "11px";
      patternDesc.textContent = "Pattern: ";

      const code = document.createElement("code");
      code.textContent = rule.pattern;
      patternDesc.appendChild(code);

      details.append(strongName, badge, br, patternDesc);

      const delBtn = document.createElement("button");
      delBtn.className = "icon-btn delete-pii-btn";
      delBtn.setAttribute("aria-label", `Delete ${rule.name}`);
      delBtn.style.cssText = "width:26px; height:26px; font-size:12px; color:var(--color-critical)";
      delBtn.textContent = "✕";
      delBtn.onclick = () => deletePiiRule(rule.id);

      row.append(details, delBtn);
      piiRulesContainer.appendChild(row);
    });
  };

  // Delete PII rule by ID
  const deletePiiRule = (ruleId) => {
    localPiiRules = localPiiRules.filter(r => r.id !== ruleId);
    chrome.storage.local.set({ customPiiPatterns: localPiiRules }, () => {
      renderPiiRules();
      triggerSuccessAlert("PII rule deleted.");
    });
  };

  // Add Custom PII Pattern
  addPiiBtn.addEventListener("click", () => {
    const name = newPiiName.value.trim();
    const pattern = newPiiPattern.value.trim();
    const severity = newPiiSeverity.value;

    if (!name || !pattern) {
      alert("Please provide both a Rule Name and a Regex Pattern.");
      return;
    }

    // Verify valid Regular Expression syntax
    try {
      new RegExp(pattern);
    } catch {
      alert("Invalid Regular Expression syntax. Please verify your pattern.");
      return;
    }

    const newRule = {
      id: "rule_" + Date.now() + "_" + Math.random().toString(36).substring(2, 7),
      name,
      pattern,
      severity
    };

    localPiiRules.push(newRule);
    chrome.storage.local.set({ customPiiPatterns: localPiiRules }, () => {
      newPiiName.value = "";
      newPiiPattern.value = "";
      renderPiiRules();
      triggerSuccessAlert(`Added PII rule "${name}".`);
    });
  });

  // Render Whitelist safely without innerHTML
  const renderWhitelist = () => {
    whitelistContainer.replaceChildren();

    if (localWhitelist.length === 0) {
      const emptyNotice = document.createElement("div");
      emptyNotice.style.cssText = "text-align:center; padding:12px; color:var(--text-muted); font-size:12px;";
      emptyNotice.textContent = "No domains currently whitelisted.";
      whitelistContainer.appendChild(emptyNotice);
      return;
    }

    localWhitelist.forEach(domain => {
      const row = document.createElement("div");
      row.className = "item-row";

      const details = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = domain;
      details.appendChild(strong);

      const delBtn = document.createElement("button");
      delBtn.className = "icon-btn delete-whitelist-btn";
      delBtn.setAttribute("aria-label", `Remove ${domain} from whitelist`);
      delBtn.style.cssText = "width:26px; height:26px; font-size:12px; color:var(--color-critical)";
      delBtn.textContent = "✕";
      delBtn.onclick = () => deleteWhitelistDomain(domain);

      row.append(details, delBtn);
      whitelistContainer.appendChild(row);
    });
  };

  const deleteWhitelistDomain = (domain) => {
    localWhitelist = localWhitelist.filter(d => d !== domain);
    chrome.storage.local.set({ whitelistedDomains: localWhitelist }, () => {
      renderWhitelist();
      triggerSuccessAlert(`Removed "${domain}" from whitelist.`);
    });
  };

  // Add Domain to Whitelist
  addWhitelistBtn.addEventListener("click", () => {
    let rawInput = newWhitelistDomain.value.trim().toLowerCase();
    if (!rawInput) return;

    let cleanDomain = rawInput;

    // Handle wildcard domains like *.example.com
    const isWildcard = cleanDomain.startsWith("*.");
    if (isWildcard) {
      cleanDomain = cleanDomain.substring(2);
    }

    // Strip protocols if provided
    if (cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
      try {
        const parsed = new URL(cleanDomain);
        cleanDomain = parsed.hostname;
      } catch {
        cleanDomain = cleanDomain.replace(/^https?:\/\//, "").split("/")[0];
      }
    }

    if (cleanDomain.startsWith("www.")) {
      cleanDomain = cleanDomain.substring(4);
    }

    // Basic domain validation
    if (!cleanDomain || cleanDomain.length < 3 || (!cleanDomain.includes(".") && cleanDomain !== "localhost")) {
      alert("Please enter a valid domain format (e.g. example.com or *.internal.net).");
      return;
    }

    const domainToStore = isWildcard ? `*.${cleanDomain}` : cleanDomain;

    if (!localWhitelist.includes(domainToStore)) {
      localWhitelist.push(domainToStore);
      chrome.storage.local.set({ whitelistedDomains: localWhitelist }, () => {
        newWhitelistDomain.value = "";
        renderWhitelist();
        triggerSuccessAlert(`Whitelisted "${domainToStore}".`);
      });
    } else {
      alert("This domain is already on your whitelist.");
    }
  });

  // Reset Stats Counter
  resetStatsBtn.addEventListener("click", () => {
    if (confirm("Are you sure you want to reset all shields protection statistics?")) {
      const defaultStats = {
        linksScanned: 0,
        piiBlockedCount: 0,
        threatsDetected: 0,
        sitesProtected: 0
      };

      chrome.storage.local.set({ stats: defaultStats }, () => {
        renderStats(defaultStats);
        triggerSuccessAlert("Metrics counter reset to zero.");
      });
    }
  });

  // Factory Reset All settings
  factoryResetBtn.addEventListener("click", () => {
    if (confirm("Warning: This will restore default shields settings and erase all custom PII rules and whitelists. Proceed?")) {
      chrome.storage.local.clear(() => {
        const defaultSettings = {
          shields: {
            pii: true,
            url: true,
            content: true,
            security: true
          },
          stats: {
            linksScanned: 0,
            piiBlockedCount: 0,
            threatsDetected: 0,
            sitesProtected: 0
          },
          whitelistedDomains: [],
          customPiiPatterns: []
        };

        chrome.storage.local.set(defaultSettings, () => {
          loadConfig();
          triggerSuccessAlert("Factory defaults restored.");
        });
      });
    }
  });

  // Load initially
  loadConfig();
});
