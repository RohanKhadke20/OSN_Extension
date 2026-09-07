// JS Logic for OSN Guard Options Configuration
document.addEventListener("DOMContentLoaded", () => {
  "use strict";

  // Elements
  const closeBtn = document.getElementById("close-options-btn");
  const saveSuccessAlert = document.getElementById("save-success");
  const saveErrorAlert = document.getElementById("save-error");

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

  // Backup & Portability Elements
  const exportConfigBtn = document.getElementById("export-config-btn");
  const importConfigFile = document.getElementById("import-config-file");

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

  // Helper to show inline validation errors without blocking thread
  const triggerErrorAlert = (message) => {
    if (!saveErrorAlert) {
      alert(message);
      return;
    }
    saveErrorAlert.textContent = `⚠ ${message}`;
    saveErrorAlert.style.display = "block";
    setTimeout(() => {
      saveErrorAlert.style.display = "none";
    }, 4000);
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
    let pattern = newPiiPattern.value.trim();
    const severity = newPiiSeverity.value;

    if (!name || !pattern) {
      triggerErrorAlert("Please provide both a Rule Name and a Regex Pattern.");
      return;
    }

    // Strip wrapping slashes if user pasted a regex literal e.g. /^[0-9]+$/
    if (pattern.startsWith("/") && pattern.lastIndexOf("/") > 0) {
      pattern = pattern.substring(1, pattern.lastIndexOf("/"));
    }

    // Verify valid Regular Expression syntax
    try {
      new RegExp(pattern);
    } catch {
      triggerErrorAlert("Invalid Regular Expression syntax. Please check your pattern.");
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
    const rawInput = newWhitelistDomain.value.trim().toLowerCase().replace(/\.+$/, "");
    if (!rawInput) return;

    let cleanDomain = rawInput;

    // Handle wildcard domains like *.example.com
    let isWildcard = cleanDomain.startsWith("*.");
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

    // Re-check wildcard if entered as https://*.example.com
    if (cleanDomain.startsWith("*.")) {
      isWildcard = true;
      cleanDomain = cleanDomain.substring(2);
    }

    if (cleanDomain.startsWith("www.")) {
      cleanDomain = cleanDomain.substring(4);
    }

    // Strip trailing paths, ports, queries, or dots
    cleanDomain = cleanDomain.split("/")[0].split("?")[0].split(":")[0].replace(/\.+$/, "");

    // Basic domain validation
    if (!cleanDomain || cleanDomain.length < 3 || (!cleanDomain.includes(".") && cleanDomain !== "localhost")) {
      triggerErrorAlert("Please enter a valid domain format (e.g. example.com or *.internal.net).");
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
      triggerErrorAlert("This domain is already on your whitelist.");
    }
  });

  // Export Settings Backup
  if (exportConfigBtn) {
    exportConfigBtn.addEventListener("click", () => {
      chrome.storage.local.get(["shields", "whitelistedDomains", "customPiiPatterns"], (data) => {
        const backup = {
          app: "OSN Guard",
          version: "1.2.0",
          exportedAt: new Date().toISOString(),
          shields: data.shields || { pii: true, url: true, content: true, security: true },
          whitelistedDomains: data.whitelistedDomains || [],
          customPiiPatterns: data.customPiiPatterns || []
        };

        const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `osn-guard-backup-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        triggerSuccessAlert("Configuration backup exported.");
      });
    });
  }

  // Import Settings Backup
  if (importConfigFile) {
    importConfigFile.addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const parsed = JSON.parse(event.target.result);
          if (!parsed || typeof parsed !== "object") {
            throw new Error("File does not contain a valid JSON object.");
          }

          const updates = {};

          if (parsed.shields && typeof parsed.shields === "object") {
            updates.shields = {
              pii: parsed.shields.pii !== false,
              url: parsed.shields.url !== false,
              content: parsed.shields.content !== false,
              security: parsed.shields.security !== false
            };
          }

          if (Array.isArray(parsed.whitelistedDomains)) {
            updates.whitelistedDomains = parsed.whitelistedDomains
              .filter(d => typeof d === "string" && d.trim().length > 0)
              .map(d => d.trim().toLowerCase().replace(/\.+$/, ""));
          }

          if (Array.isArray(parsed.customPiiPatterns)) {
            updates.customPiiPatterns = parsed.customPiiPatterns.filter(p => {
              if (!p || !p.pattern || typeof p.pattern !== "string") return false;
              try {
                new RegExp(p.pattern, "g");
                return true;
              } catch {
                return false;
              }
            });
          }

          if (Object.keys(updates).length === 0) {
            triggerErrorAlert("No recognized settings found in imported file.");
            return;
          }

          chrome.storage.local.set(updates, () => {
            loadConfig();
            triggerSuccessAlert("Configuration imported successfully!");
            importConfigFile.value = "";
          });
        } catch (err) {
          triggerErrorAlert(`Failed to import configuration: ${err.message}`);
          importConfigFile.value = "";
        }
      };
      reader.readAsText(file);
    });
  }

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
