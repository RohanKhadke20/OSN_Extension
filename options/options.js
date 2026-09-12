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

  // Audit Log Elements
  const auditLogContainer = document.getElementById("audit-log-container");
  const exportAuditBtn = document.getElementById("export-audit-btn");
  const clearAuditBtn = document.getElementById("clear-audit-btn");

  // Live PII Sandbox Elements
  const sandboxInput = document.getElementById("sandbox-input-text");
  const sandboxOutput = document.getElementById("sandbox-output-text");
  const copySanitizedBtn = document.getElementById("copy-sanitized-btn");
  const sandboxFindings = document.getElementById("sandbox-findings");

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
  let localAuditLog = [];

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
    chrome.storage.local.get(["customPiiPatterns", "whitelistedDomains", "stats", "auditLog"], (data) => {
      localPiiRules = Array.isArray(data.customPiiPatterns) ? data.customPiiPatterns : [];
      localWhitelist = Array.isArray(data.whitelistedDomains) ? data.whitelistedDomains : [];
      localAuditLog = Array.isArray(data.auditLog) ? data.auditLog : [];

      // Ensure every rule has an ID
      localPiiRules.forEach((rule, idx) => {
        if (!rule.id) {
          rule.id = "rule_" + Date.now() + "_" + idx;
        }
      });

      renderPiiRules();
      renderWhitelist();
      renderStats(data.stats);
      renderAuditLog(localAuditLog);
      updateSandbox();
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
      updateSandbox();
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

    if (name.length > 50) {
      triggerErrorAlert("Rule name must not exceed 50 characters.");
      return;
    }

    // Strip wrapping slashes if user pasted a regex literal e.g. /^[0-9]+$/
    if (pattern.startsWith("/") && pattern.lastIndexOf("/") > 0) {
      pattern = pattern.substring(1, pattern.lastIndexOf("/"));
    }

    if (pattern.length > 250) {
      triggerErrorAlert("Regex pattern must not exceed 250 characters.");
      return;
    }

    // Verify valid Regular Expression syntax and ReDoS safety
    if (typeof OSNPiiAnalyzer !== "undefined" && OSNPiiAnalyzer.isSafeRegexPattern) {
      if (!OSNPiiAnalyzer.isSafeRegexPattern(pattern)) {
        triggerErrorAlert("Pattern rejected: Vulnerable to catastrophic backtracking (ReDoS) or invalid syntax.");
        return;
      }
    } else {
      try {
        new RegExp(pattern);
      } catch {
        triggerErrorAlert("Invalid Regular Expression syntax. Please check your pattern.");
        return;
      }
    }

    const newRule = {
      id: "rule_" + Date.now() + "_" + Math.random().toString(36).substring(2, 7),
      name,
      pattern,
      severity: (severity === "critical" || severity === "warning") ? severity : "warning"
    };

    localPiiRules.push(newRule);
    chrome.storage.local.set({ customPiiPatterns: localPiiRules }, () => {
      newPiiName.value = "";
      newPiiPattern.value = "";
      renderPiiRules();
      updateSandbox();
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
              pii: Boolean(parsed.shields.pii),
              url: Boolean(parsed.shields.url),
              content: Boolean(parsed.shields.content),
              security: Boolean(parsed.shields.security)
            };
          }

          if (Array.isArray(parsed.whitelistedDomains)) {
            updates.whitelistedDomains = parsed.whitelistedDomains
              .filter(d => typeof d === "string" && d.trim().length > 0 && d.trim().length <= 100)
              .map(d => d.trim().toLowerCase().replace(/\.+$/, ""))
              .slice(0, 200);
          }

          if (Array.isArray(parsed.customPiiPatterns)) {
            updates.customPiiPatterns = parsed.customPiiPatterns
              .filter(p => {
                if (!p || typeof p !== "object") return false;
                if (!p.name || typeof p.name !== "string" || p.name.trim().length === 0 || p.name.length > 50) return false;
                if (!p.pattern || typeof p.pattern !== "string" || p.pattern.trim().length === 0 || p.pattern.length > 250) return false;
                if (typeof OSNPiiAnalyzer !== "undefined" && OSNPiiAnalyzer.isSafeRegexPattern) {
                  return OSNPiiAnalyzer.isSafeRegexPattern(p.pattern);
                }
                try {
                  new RegExp(p.pattern, "g");
                  return true;
                } catch {
                  return false;
                }
              })
              .map(p => ({
                id: (typeof p.id === "string" && /^rule_[a-zA-Z0-9_-]+$/.test(p.id))
                  ? p.id
                  : "rule_" + Date.now() + "_" + Math.random().toString(36).substring(2, 7),
                name: p.name.trim().slice(0, 50),
                pattern: p.pattern.trim(),
                severity: (p.severity === "critical" || p.severity === "warning") ? p.severity : "warning"
              }))
              .slice(0, 50);
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

  // Live PII Sandbox Analysis & Sanitization
  const updateSandbox = () => {
    if (!sandboxInput || !sandboxOutput) return;
    const raw = sandboxInput.value;
    if (!raw || raw.trim().length === 0) {
      sandboxOutput.value = "";
      if (sandboxFindings) sandboxFindings.replaceChildren();
      return;
    }

    if (typeof OSNPiiAnalyzer !== "undefined" && OSNPiiAnalyzer.maskPii) {
      const masked = OSNPiiAnalyzer.maskPii(raw, localPiiRules);
      const detected = OSNPiiAnalyzer.detectPii(raw, localPiiRules);
      sandboxOutput.value = masked;

      if (sandboxFindings) {
        sandboxFindings.replaceChildren();
        if (detected.length > 0) {
          const counts = {};
          detected.forEach(d => {
            counts[d.name] = (counts[d.name] || 0) + 1;
          });
          const summaryParts = Object.entries(counts).map(([name, count]) => `${count} ${name}`);

          const badge = document.createElement("span");
          badge.style.cssText = "color: #f59e0b; font-weight: 600;";
          badge.textContent = `⚠ Redacted ${detected.length} item(s): `;

          const detailsText = document.createTextNode(summaryParts.join(", "));
          sandboxFindings.appendChild(badge);
          sandboxFindings.appendChild(detailsText);
        } else {
          const safeBadge = document.createElement("span");
          safeBadge.style.cssText = "color: #10b981; font-weight: 600;";
          safeBadge.textContent = "✓ No sensitive PII detected in sample text.";
          sandboxFindings.appendChild(safeBadge);
        }
      }
    } else {
      sandboxOutput.value = raw;
    }
  };

  if (sandboxInput) {
    sandboxInput.addEventListener("input", updateSandbox);
  }

  function copyTextToClipboard(text, btn) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1500);
      }).catch(() => {
        fallbackCopy();
      });
    } else {
      fallbackCopy();
    }

    function fallbackCopy() {
      if (sandboxOutput) {
        sandboxOutput.select();
        try {
          const successful = document.execCommand("copy");
          if (successful) {
            const orig = btn.textContent;
            btn.textContent = "Copied!";
            setTimeout(() => { btn.textContent = orig; }, 1500);
          } else {
            triggerErrorAlert("Clipboard copy unavailable in current context.");
          }
        } catch {
          triggerErrorAlert("Failed to copy text to clipboard.");
        }
      }
    }
  }

  if (copySanitizedBtn && sandboxOutput) {
    copySanitizedBtn.addEventListener("click", () => {
      copyTextToClipboard(sandboxOutput.value, copySanitizedBtn);
    });
  }

  // Render Security Incident Audit Log safely without innerHTML
  const renderAuditLog = (auditEntries = []) => {
    if (!auditLogContainer) return;
    auditLogContainer.replaceChildren();

    if (!Array.isArray(auditEntries) || auditEntries.length === 0) {
      const emptyRow = document.createElement("div");
      emptyRow.style.cssText = "color: var(--text-secondary); font-size: 12px; font-style: italic; padding: 12px; text-align: center; background: rgba(0,0,0,0.1); border-radius: 8px;";
      emptyRow.textContent = "No security threat incidents logged yet. Clean browser session.";
      auditLogContainer.appendChild(emptyRow);
      return;
    }

    auditEntries.forEach((entry) => {
      const card = document.createElement("div");
      card.className = "audit-entry";

      const header = document.createElement("div");
      header.className = "audit-entry-header";

      const title = document.createElement("div");
      title.className = "audit-entry-title";
      const icon = document.createElement("span");
      icon.textContent = entry.severity === "critical" ? "🔴" : "🟠";
      const name = document.createElement("span");
      name.textContent = entry.type || "Incident";
      title.appendChild(icon);
      title.appendChild(name);

      const time = document.createElement("div");
      time.className = "audit-entry-time";
      let timeStr = "";
      try {
        timeStr = new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      } catch {
        timeStr = entry.timestamp || "";
      }
      time.textContent = timeStr;

      header.appendChild(title);
      header.appendChild(time);

      const msg = document.createElement("div");
      msg.className = "audit-entry-msg";
      msg.textContent = entry.message || "";

      card.appendChild(header);
      card.appendChild(msg);

      if (entry.target || entry.domain) {
        const target = document.createElement("div");
        target.className = "audit-entry-target";
        target.textContent = `Target: ${entry.target || entry.domain}`;
        card.appendChild(target);
      }

      auditLogContainer.appendChild(card);
    });
  };

  if (clearAuditBtn) {
    clearAuditBtn.addEventListener("click", () => {
      chrome.storage.local.set({ auditLog: [] }, () => {
        localAuditLog = [];
        renderAuditLog([]);
        triggerSuccessAlert("Security audit log cleared.");
      });
    });
  }

  if (exportAuditBtn) {
    exportAuditBtn.addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(localAuditLog, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `osn-guard-audit-log-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        a.remove();
        URL.revokeObjectURL(url);
      }, 100);
    });
  }

  // Live storage synchronization
  if (chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === "local" && changes.auditLog) {
        localAuditLog = Array.isArray(changes.auditLog.newValue) ? changes.auditLog.newValue : [];
        renderAuditLog(localAuditLog);
      }
    });
  }

  // Load initially
  loadConfig();
});
