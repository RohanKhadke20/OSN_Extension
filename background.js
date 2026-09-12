// Background service worker for OSN Guard (Manifest V3)
// Cross-browser namespace normalization (Chromium chrome.* / Firefox browser.*)
if (typeof globalThis.chrome === "undefined" && typeof globalThis.browser !== "undefined") {
  globalThis.chrome = globalThis.browser;
}

// In Service Workers, dynamically import dependencies; in Firefox event pages, dependencies load via manifest scripts array
if (typeof importScripts === "function") {
  importScripts("core/url-analyzer.js", "core/pii-analyzer.js", "core/scam-analyzer.js");
}

// Storage adapter prioritizing session storage for ephemeral tab state
const getSessionStorage = () => {
  return chrome.storage && chrome.storage.session ? chrome.storage.session : chrome.storage.local;
};

// Set up Chrome context menus for on-demand inspection
function setupContextMenus() {
  if (!chrome.contextMenus) return;

  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "osn_scan_link",
      title: "Scan link with OSN Guard",
      contexts: ["link"]
    });

    chrome.contextMenus.create({
      id: "osn_scan_selection",
      title: "Analyze selection for scams & PII",
      contexts: ["selection"]
    });
  });
}

// Clean up orphaned tab data when service worker starts or on install
function reconcileOrphanedTabs() {
  if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) return;

  chrome.tabs.query({}, (activeTabs) => {
    if (chrome.runtime.lastError || !Array.isArray(activeTabs)) return;
    const activeTabIds = new Set(activeTabs.map(t => t.id));
    const storage = getSessionStorage();

    storage.get(null, (items) => {
      if (!items || typeof items !== "object") return;
      const keysToRemove = [];
      for (const key of Object.keys(items)) {
        if (key.startsWith("tab_")) {
          const tabId = parseInt(key.slice(4), 10);
          if (!activeTabIds.has(tabId)) {
            keysToRemove.push(key);
          }
        }
      }
      if (keysToRemove.length > 0) {
        storage.remove(keysToRemove);
      }
    });
  });
}

// Throttled reconciliation to prune crashed/closed tabs during service worker dormancy (at most once every 3 minutes)
let lastReconcileTime = 0;
const RECONCILE_THROTTLE_MS = 3 * 60 * 1000;

function throttledReconcileOrphanedTabs() {
  const now = Date.now();
  if (now - lastReconcileTime > RECONCILE_THROTTLE_MS) {
    lastReconcileTime = now;
    reconcileOrphanedTabs();
  }
}

/**
 * Verifies and self-heals local extension storage schema.
 * Restores defaults for missing or corrupted keys without overwriting intact user data.
 * @param {Object} data - Raw storage items retrieved from chrome.storage.local
 * @returns {{ updates: Object, needsRepair: boolean }}
 */
function sanitizeAndRepairStorage(data) {
  const updates = {};
  let needsRepair = false;

  // 1. Shields verification (must be an object of 4 booleans)
  if (!data || !data.shields || typeof data.shields !== "object" || Array.isArray(data.shields)) {
    updates.shields = { pii: true, url: true, content: true, security: true };
    needsRepair = true;
  } else {
    const s = data.shields;
    const repairedShields = {
      pii: typeof s.pii === "boolean" ? s.pii : true,
      url: typeof s.url === "boolean" ? s.url : true,
      content: typeof s.content === "boolean" ? s.content : true,
      security: typeof s.security === "boolean" ? s.security : true
    };
    if (s.pii !== repairedShields.pii || s.url !== repairedShields.url ||
        s.content !== repairedShields.content || s.security !== repairedShields.security) {
      updates.shields = repairedShields;
      needsRepair = true;
    }
  }

  // 2. Stats verification (must be an object with non-negative integer counters)
  if (!data || !data.stats || typeof data.stats !== "object" || Array.isArray(data.stats)) {
    updates.stats = { linksScanned: 0, piiBlockedCount: 0, threatsDetected: 0, sitesProtected: 0 };
    needsRepair = true;
  } else {
    const st = data.stats;
    const repairedStats = {
      linksScanned: (typeof st.linksScanned === "number" && Number.isFinite(st.linksScanned) && st.linksScanned >= 0)
        ? Math.floor(st.linksScanned) : 0,
      piiBlockedCount: (typeof st.piiBlockedCount === "number" && Number.isFinite(st.piiBlockedCount) && st.piiBlockedCount >= 0)
        ? Math.floor(st.piiBlockedCount) : 0,
      threatsDetected: (typeof st.threatsDetected === "number" && Number.isFinite(st.threatsDetected) && st.threatsDetected >= 0)
        ? Math.floor(st.threatsDetected) : 0,
      sitesProtected: (typeof st.sitesProtected === "number" && Number.isFinite(st.sitesProtected) && st.sitesProtected >= 0)
        ? Math.floor(st.sitesProtected) : 0
    };
    if (st.linksScanned !== repairedStats.linksScanned || st.piiBlockedCount !== repairedStats.piiBlockedCount ||
        st.threatsDetected !== repairedStats.threatsDetected || st.sitesProtected !== repairedStats.sitesProtected) {
      updates.stats = repairedStats;
      needsRepair = true;
    }
  }

  // 3. Whitelisted domains verification (must be an array of strings)
  if (!data || !Array.isArray(data.whitelistedDomains)) {
    updates.whitelistedDomains = [];
    needsRepair = true;
  } else {
    const filteredDomains = data.whitelistedDomains.filter(d => typeof d === "string" && d.trim().length > 0 && d.trim().length <= 100);
    if (filteredDomains.length !== data.whitelistedDomains.length) {
      updates.whitelistedDomains = filteredDomains;
      needsRepair = true;
    }
  }

  // 4. Custom PII Patterns verification (must be an array of objects)
  if (!data || !Array.isArray(data.customPiiPatterns)) {
    updates.customPiiPatterns = [];
    needsRepair = true;
  } else {
    const filteredPatterns = data.customPiiPatterns.filter(p => p && typeof p === "object" && typeof p.name === "string" && typeof p.pattern === "string");
    if (filteredPatterns.length !== data.customPiiPatterns.length) {
      updates.customPiiPatterns = filteredPatterns;
      needsRepair = true;
    }
  }

  // 5. Audit log verification (must be an array)
  if (!data || !Array.isArray(data.auditLog)) {
    updates.auditLog = [];
    needsRepair = true;
  }

  // 6. Review state verification (if key is present in data)
  if (data && data.reviewState !== undefined) {
    if (!data.reviewState || typeof data.reviewState !== "object" || Array.isArray(data.reviewState)) {
      updates.reviewState = { dismissed: false, completed: false, lastPromptedAt: 0 };
      needsRepair = true;
    } else {
      const rs = data.reviewState;
      const repairedReview = {
        dismissed: typeof rs.dismissed === "boolean" ? rs.dismissed : false,
        completed: typeof rs.completed === "boolean" ? rs.completed : false,
        lastPromptedAt: (typeof rs.lastPromptedAt === "number" && Number.isFinite(rs.lastPromptedAt) && rs.lastPromptedAt >= 0)
          ? Math.floor(rs.lastPromptedAt) : 0
      };
      if (rs.dismissed !== repairedReview.dismissed || rs.completed !== repairedReview.completed || rs.lastPromptedAt !== repairedReview.lastPromptedAt) {
        updates.reviewState = repairedReview;
        needsRepair = true;
      }
    }
  }

  // 7. Installed timestamp verification (if key is present in data)
  if (data && data.installedAt !== undefined) {
    if (typeof data.installedAt !== "number" || !Number.isFinite(data.installedAt) || data.installedAt <= 0) {
      updates.installedAt = Date.now();
      needsRepair = true;
    }
  }

  return { updates, needsRepair };
}

/**
 * Loads enterprise-enforced policies from chrome.storage.managed
 * @param {Function} callback - ({ forcedWhitelistedDomains, mandatoryCustomPiiRules, enforcedShields }) => void
 */
function getManagedPolicy(callback) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.managed) {
    if (callback) callback({});
    return;
  }

  chrome.storage.managed.get(["forcedWhitelistedDomains", "mandatoryCustomPiiRules", "enforcedShields"], (managedData) => {
    if (chrome.runtime.lastError || !managedData || typeof managedData !== "object") {
      if (callback) callback({});
      return;
    }
    if (callback) callback(managedData);
  });
}

/**
 * Merges enterprise-managed policies with local configuration.
 * Managed settings take precedence and cannot be disabled by users.
 * @param {Object} localData - User local storage settings
 * @param {Object} managedData - Enterprise managed policy data
 * @returns {Object} Merged effective configuration
 */
function mergeManagedSettings(localData, managedData) {
  const effective = { ...localData };

  if (!managedData || typeof managedData !== "object") {
    return effective;
  }

  // 1. Forced whitelisted domains
  if (Array.isArray(managedData.forcedWhitelistedDomains) && managedData.forcedWhitelistedDomains.length > 0) {
    const existing = Array.isArray(effective.whitelistedDomains) ? effective.whitelistedDomains : [];
    effective.whitelistedDomains = [...new Set([...existing, ...managedData.forcedWhitelistedDomains])];
    effective.managedDomains = managedData.forcedWhitelistedDomains;
  }

  // 2. Mandatory custom PII rules
  if (Array.isArray(managedData.mandatoryCustomPiiRules) && managedData.mandatoryCustomPiiRules.length > 0) {
    const existing = Array.isArray(effective.customPiiPatterns) ? effective.customPiiPatterns : [];
    const managedNames = new Set(managedData.mandatoryCustomPiiRules.map(r => r.name));
    const filteredExisting = existing.filter(r => !managedNames.has(r.name));
    effective.customPiiPatterns = [
      ...managedData.mandatoryCustomPiiRules.map(r => ({ ...r, managed: true })),
      ...filteredExisting
    ];
    effective.managedPiiRules = managedData.mandatoryCustomPiiRules;
  }

  // 3. Enforced shields
  if (managedData.enforcedShields && typeof managedData.enforcedShields === "object") {
    effective.shields = {
      ...(effective.shields || { pii: true, url: true, content: true, security: true })
    };
    for (const [shieldKey, isEnforced] of Object.entries(managedData.enforcedShields)) {
      if (typeof isEnforced === "boolean") {
        effective.shields[shieldKey] = isEnforced;
      }
    }
    effective.managedShields = managedData.enforcedShields;
  }

  return effective;
}

/**
 * Synchronizes managed policy into chrome.storage.local to ensure
 * content scripts and extension pages reflect enterprise enforcement immediately.
 * @param {Function} callback - Optional completion callback
 */
function syncManagedPolicy(callback) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    if (callback) callback();
    return;
  }

  getManagedPolicy((managedData) => {
    if (!managedData || Object.keys(managedData).length === 0) {
      if (callback) callback();
      return;
    }

    chrome.storage.local.get(["whitelistedDomains", "customPiiPatterns", "shields"], (localData) => {
      const merged = mergeManagedSettings(localData, managedData);
      const updates = {};
      if (merged.whitelistedDomains) updates.whitelistedDomains = merged.whitelistedDomains;
      if (merged.customPiiPatterns) updates.customPiiPatterns = merged.customPiiPatterns;
      if (merged.shields) updates.shields = merged.shields;
      if (merged.managedDomains) updates.managedDomains = merged.managedDomains;
      if (merged.managedPiiRules) updates.managedPiiRules = merged.managedPiiRules;
      if (merged.managedShields) updates.managedShields = merged.managedShields;

      chrome.storage.local.set(updates, () => {
        if (callback) callback();
      });
    });
  });
}

// Watch for live enterprise policy updates via MDM / GPO
if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "managed") {
      syncManagedPolicy();
    }
  });
}

// Auto-repair storage schema and ensure defaults
function ensureStorageIntegrity(callback) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    if (callback) callback();
    return;
  }

  chrome.storage.local.get(["shields", "stats", "whitelistedDomains", "customPiiPatterns", "auditLog", "installedAt", "reviewState"], (data) => {
    if (chrome.runtime.lastError) {
      if (callback) callback();
      return;
    }

    const { updates, needsRepair } = sanitizeAndRepairStorage(data);
    if (needsRepair && Object.keys(updates).length > 0) {
      chrome.storage.local.set(updates, () => {
        if (callback) callback();
      });
    } else {
      if (callback) callback();
    }
  });
}

// Reconcile tabs and ensure storage integrity on browser startup
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    reconcileOrphanedTabs();
    ensureStorageIntegrity(() => {
      syncManagedPolicy();
    });
  });
}

// Initialize default settings on install or update
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => {
    setupContextMenus();
    reconcileOrphanedTabs();
    chrome.storage.local.get(["installedAt", "reviewState"], (data) => {
      const updates = {};
      if (!data || typeof data.installedAt !== "number" || data.installedAt <= 0) {
        updates.installedAt = Date.now();
      }
      if (!data || !data.reviewState || typeof data.reviewState !== "object" || Array.isArray(data.reviewState)) {
        updates.reviewState = { dismissed: false, completed: false, lastPromptedAt: 0 };
      }
      if (Object.keys(updates).length > 0) {
        chrome.storage.local.set(updates);
      }
    });
    ensureStorageIntegrity(() => {
      syncManagedPolicy();
      console.log("[OSN Guard] Service worker initialized and storage integrity verified.");
    });
  });
}

// Rolling security audit log buffer limit
const MAX_AUDIT_LOG_ENTRIES = 50;

function appendAuditLog(entries) {
  if (!Array.isArray(entries) || entries.length === 0) return;

  const sanitizedEntries = entries.map(entry => {
    if (!entry || typeof entry !== "object") return null;
    const target = typeof entry.target === "string"
      ? entry.target.trim().replace(/[\r\n\t]/g, " ").slice(0, 150)
      : "";
    const message = typeof entry.message === "string"
      ? entry.message.trim().slice(0, 200)
      : "";
    return {
      id: typeof entry.id === "string" ? entry.id : ("evt-" + Math.random().toString(36).slice(2, 10)),
      timestamp: typeof entry.timestamp === "string" ? entry.timestamp : new Date().toISOString(),
      type: typeof entry.type === "string" ? entry.type.slice(0, 80) : "Threat Detected",
      severity: (entry.severity === "critical" || entry.severity === "warning") ? entry.severity : "warning",
      message: message,
      target: target,
      domain: typeof entry.domain === "string" ? entry.domain.slice(0, 100) : ""
    };
  }).filter(Boolean);

  if (sanitizedEntries.length === 0) return;

  chrome.storage.local.get("auditLog", (data) => {
    const existingLog = Array.isArray(data.auditLog) ? data.auditLog : [];
    const updated = [...sanitizedEntries, ...existingLog].slice(0, MAX_AUDIT_LOG_ENTRIES);
    chrome.storage.local.set({ auditLog: updated });
  });
}

// Serialized promise queue to eliminate race conditions in stats updates
let statsUpdateQueue = Promise.resolve();

function updateGlobalStats(update) {
  if (!update || typeof update !== "object") return;

  statsUpdateQueue = statsUpdateQueue.then(() => new Promise((resolve) => {
    chrome.storage.local.get("stats", (result) => {
      const currentStats = result.stats || {
        linksScanned: 0,
        piiBlockedCount: 0,
        threatsDetected: 0,
        sitesProtected: 0
      };

      if (update.linksScanned) currentStats.linksScanned += update.linksScanned;
      if (update.piiBlocked) currentStats.piiBlockedCount += update.piiBlocked;
      if (update.threats) currentStats.threatsDetected += update.threats;
      if (update.siteProtected) currentStats.sitesProtected += 1;

      chrome.storage.local.set({ stats: currentStats }, resolve);
    });
  })).catch((err) => {
    console.error("[OSN Guard] Failed to update global stats:", err);
  });
}

// Update action toolbar badge
function updateTabBadge(tabId, threats = []) {
  if (!chrome.action || !tabId) return;

  const count = threats.length;
  const badgeText = count > 0 ? (count > 99 ? "99+" : String(count)) : "";
  const hasCritical = threats.some(t => t.severity === "critical");

  chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({
    color: hasCritical ? "#ef4444" : "#f59e0b",
    tabId: tabId
  });
}

// Handle extension messages
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Validate sender context and internal origin
    if (sender && sender.id && chrome.runtime && chrome.runtime.id && sender.id !== chrome.runtime.id) {
      return false;
    }

    if (!message || typeof message !== "object" || typeof message.action !== "string") {
      return false;
    }

    const tabId = sender.tab ? sender.tab.id : null;

    if (message.action === "reportThreats" && tabId) {
      const { threats, statsUpdate } = message;
      const tabKey = `tab_${tabId}`;
      const tabRecord = {
        url: sender.tab.url || "",
        threats: Array.isArray(threats) ? threats : [],
        updatedAt: Date.now()
      };

      // Store in session storage so it survives service worker dormancy
      getSessionStorage().set({ [tabKey]: tabRecord }, () => {
        updateTabBadge(tabId, tabRecord.threats);
        if (statsUpdate) {
          updateGlobalStats(statsUpdate);
        }

        // Record new threats in audit event buffer
        if (Array.isArray(threats) && threats.length > 0) {
          const pageUrl = sender.tab.url || "";
          let host = "";
          try {
            host = new URL(pageUrl).hostname;
          } catch {
            host = pageUrl;
          }
          const timestamp = new Date().toISOString();
          const logEntries = threats.map(t => ({
            id: t.id || ("evt-" + Math.random().toString(36).slice(2, 10)),
            timestamp: timestamp,
            type: t.type || "Threat Detected",
            severity: t.severity || "warning",
            message: t.message || "",
            target: t.target || "",
            domain: host
          }));
          appendAuditLog(logEntries);
        }

        sendResponse({ status: "success" });
      });

      return true; // Keep message channel open for async response
    }

    else if (message.action === "getThreatsForTab") {
      const requestTabId = Number.parseInt(message.tabId, 10);
      if (!requestTabId || isNaN(requestTabId) || requestTabId <= 0) {
        sendResponse({ url: "", threats: [] });
        return false;
      }

      const tabKey = `tab_${requestTabId}`;
      getSessionStorage().get([tabKey], (result) => {
        const data = result && result[tabKey] ? result[tabKey] : { url: "", threats: [] };
        sendResponse(data);
      });

      return true;
    }

    else if (message.action === "getManagedPolicy") {
      getManagedPolicy((policy) => {
        sendResponse({ managed: policy });
      });
      return true;
    }

    else if (message.action === "checkUrlSafety") {
      const { url } = message;
      if (typeof url !== "string" || !url) {
        sendResponse({ safe: true, reason: "Empty URL" });
        return false;
      }

      chrome.storage.local.get("whitelistedDomains", (data) => {
        let whitelist = Array.isArray(data.whitelistedDomains) ? data.whitelistedDomains : [];
        getManagedPolicy((managed) => {
          if (Array.isArray(managed.forcedWhitelistedDomains)) {
            whitelist = [...new Set([...whitelist, ...managed.forcedWhitelistedDomains])];
          }
          const safetyResult = OSNUrlAnalyzer.analyzeUrlSafety(url, whitelist);
          sendResponse(safetyResult);
        });
      });

      return true;
    }

    else if (message.action === "incrementPiiBlocked") {
      updateGlobalStats({ piiBlocked: 1 });
      sendResponse({ status: "success" });
      return true;
    }

    else if (message.action === "rescanTab") {
      const targetTabId = Number.parseInt(message.tabId, 10);
      if (targetTabId && !isNaN(targetTabId) && targetTabId > 0) {
        chrome.tabs.sendMessage(targetTabId, { action: "triggerRescan" }, (res) => {
          if (chrome.runtime.lastError) {
            sendResponse({ status: "error", error: chrome.runtime.lastError.message });
          } else {
            sendResponse({ status: "success", result: res });
          }
        });
        return true;
      }
      sendResponse({ status: "error", error: "Invalid target tab ID" });
      return false;
    }

    return false;
  });
}

// Clean up tab data when tab begins navigating to a new URL
if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === "loading") {
      const tabKey = `tab_${tabId}`;
      getSessionStorage().remove(tabKey);
      if (chrome.action) {
        chrome.action.setBadgeText({ text: "", tabId: tabId });
      }
    }
  });
}

// Clean up tab data when tab is closed
if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    const tabKey = `tab_${tabId}`;
    getSessionStorage().remove(tabKey);
  });
}

// Synchronize toolbar badge immediately upon active tab switch and reconcile dormant tabs
if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onActivated) {
  chrome.tabs.onActivated.addListener((activeInfo) => {
    const tabId = activeInfo.tabId;
    if (!tabId) return;

    // Prune tabs that closed or crashed while service worker was dormant
    throttledReconcileOrphanedTabs();

    const tabKey = `tab_${tabId}`;
    getSessionStorage().get([tabKey], (result) => {
      const tabRecord = result && result[tabKey] ? result[tabKey] : null;
      if (tabRecord && Array.isArray(tabRecord.threats) && tabRecord.threats.length > 0) {
        updateTabBadge(tabId, tabRecord.threats);
      } else {
        updateTabBadge(tabId, []);
      }
    });
  });
}

// Handle context menu clicks for link and selection scanning
if (typeof chrome !== "undefined" && chrome.contextMenus && chrome.contextMenus.onClicked) {
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab || !tab.id) return;

    if (info.menuItemId === "osn_scan_link" && info.linkUrl) {
      chrome.storage.local.get("whitelistedDomains", (data) => {
        const whitelist = data.whitelistedDomains || [];
        let result = { safe: false, reason: "URL safety analyzer unavailable" };
        if (typeof OSNUrlAnalyzer !== "undefined" && OSNUrlAnalyzer.analyzeUrlSafety) {
          result = OSNUrlAnalyzer.analyzeUrlSafety(info.linkUrl, whitelist);
        }

        if (!result.safe) {
          let host = "";
          try { host = tab.url ? new URL(tab.url).hostname : ""; } catch { /* ignore */ }
          appendAuditLog([{
            id: "evt-" + Math.random().toString(36).slice(2, 10),
            timestamp: new Date().toISOString(),
            type: "Manual Link Scan",
            severity: result.severity || "warning",
            message: result.reason || "Suspicious link flagged via manual scan",
            target: info.linkUrl,
            domain: host
          }]);
        }

        chrome.tabs.sendMessage(tab.id, {
          action: "displayScanResult",
          targetType: "link",
          targetValue: info.linkUrl,
          result: result
        }, () => {
          if (chrome.runtime.lastError) {
            // Ignored if content script is not yet active on the tab
          }
        });
      });
    } else if (info.menuItemId === "osn_scan_selection" && info.selectionText) {
      const truncatedSelection = info.selectionText.slice(0, 5000);
      chrome.storage.local.get("customPiiPatterns", (data) => {
        const customPatterns = data.customPiiPatterns || [];
        let scamResult = { flagged: false };
        let piiResult = [];

        if (typeof OSNScamAnalyzer !== "undefined" && OSNScamAnalyzer.detectScamContent) {
          scamResult = OSNScamAnalyzer.detectScamContent(truncatedSelection);
        }

        if (typeof OSNPiiAnalyzer !== "undefined" && OSNPiiAnalyzer.detectPii) {
          piiResult = OSNPiiAnalyzer.detectPii(truncatedSelection, customPatterns);
        }

        if (scamResult.flagged || piiResult.length > 0) {
          let host = "";
          try { host = tab.url ? new URL(tab.url).hostname : ""; } catch { /* ignore */ }
          const type = scamResult.flagged ? (scamResult.category || "Scam Detected") : "PII Detected";
          const severity = scamResult.severity || (piiResult[0] ? piiResult[0].severity : "warning");
          appendAuditLog([{
            id: "evt-" + Math.random().toString(36).slice(2, 10),
            timestamp: new Date().toISOString(),
            type: `Manual Scan: ${type}`,
            severity: severity,
            message: scamResult.flagged ? scamResult.reason : `Detected ${piiResult.length} sensitive items`,
            target: truncatedSelection.slice(0, 60),
            domain: host
          }]);
        }

        chrome.tabs.sendMessage(tab.id, {
          action: "displayScanResult",
          targetType: "selection",
          targetValue: truncatedSelection,
          scamResult: scamResult,
          piiResult: piiResult
        }, () => {
          if (chrome.runtime.lastError) {
            // Ignored if content script is not yet active on the tab
          }
        });
      });
    }
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    reconcileOrphanedTabs,
    throttledReconcileOrphanedTabs,
    sanitizeAndRepairStorage,
    ensureStorageIntegrity,
    appendAuditLog,
    updateGlobalStats,
    getSessionStorage,
    getManagedPolicy,
    mergeManagedSettings,
    syncManagedPolicy
  };
}


