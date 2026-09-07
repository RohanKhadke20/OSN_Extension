// Background service worker for OSN Guard (Manifest V3)
importScripts("core/url-analyzer.js", "core/pii-analyzer.js", "core/scam-analyzer.js");

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

// Initialize default settings on install or update
chrome.runtime.onInstalled.addListener(() => {
  setupContextMenus();

  chrome.storage.local.get(["shields", "stats", "whitelistedDomains", "customPiiPatterns"], (data) => {
    const defaults = {};

    if (!data.shields) {
      defaults.shields = {
        pii: true,
        url: true,
        content: true,
        security: true
      };
    }

    if (!data.stats) {
      defaults.stats = {
        linksScanned: 0,
        piiBlockedCount: 0,
        threatsDetected: 0,
        sitesProtected: 0
      };
    }

    if (!data.whitelistedDomains) {
      defaults.whitelistedDomains = [];
    }

    if (!data.customPiiPatterns) {
      defaults.customPiiPatterns = [];
    }

    if (Object.keys(defaults).length > 0) {
      chrome.storage.local.set(defaults);
    }
  });

  console.log("[OSN Guard] Service worker initialized and defaults ensured.");
});

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
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
      sendResponse({ status: "success" });
    });

    return true; // Keep message channel open for async response
  }

  else if (message.action === "getThreatsForTab") {
    const requestTabId = message.tabId;
    if (!requestTabId) {
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

  else if (message.action === "checkUrlSafety") {
    const { url } = message;

    chrome.storage.local.get("whitelistedDomains", (data) => {
      const whitelist = data.whitelistedDomains || [];
      const safetyResult = OSNUrlAnalyzer.analyzeUrlSafety(url, whitelist);
      sendResponse(safetyResult);
    });

    return true;
  }

  else if (message.action === "incrementPiiBlocked") {
    updateGlobalStats({ piiBlocked: 1 });
    sendResponse({ status: "success" });
    return true;
  }

  else if (message.action === "rescanTab") {
    const targetTabId = message.tabId;
    if (targetTabId) {
      chrome.tabs.sendMessage(targetTabId, { action: "triggerRescan" }, (res) => {
        if (chrome.runtime.lastError) {
          sendResponse({ status: "error", error: chrome.runtime.lastError.message });
        } else {
          sendResponse({ status: "success", result: res });
        }
      });
      return true;
    }
  }

  return false;
});

// Clean up tab data when tab begins navigating to a new URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    const tabKey = `tab_${tabId}`;
    getSessionStorage().remove(tabKey);
    if (chrome.action) {
      chrome.action.setBadgeText({ text: "", tabId: tabId });
    }
  }
});

// Clean up tab data when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  const tabKey = `tab_${tabId}`;
  getSessionStorage().remove(tabKey);
});

// Synchronize toolbar badge immediately upon active tab switch
if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onActivated) {
  chrome.tabs.onActivated.addListener((activeInfo) => {
    const tabId = activeInfo.tabId;
    if (!tabId) return;

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
      chrome.storage.local.get("customPiiPatterns", (data) => {
        const customPatterns = data.customPiiPatterns || [];
        let scamResult = { flagged: false };
        let piiResult = [];

        if (typeof OSNScamAnalyzer !== "undefined" && OSNScamAnalyzer.detectScamContent) {
          scamResult = OSNScamAnalyzer.detectScamContent(info.selectionText);
        }

        if (typeof OSNPiiAnalyzer !== "undefined" && OSNPiiAnalyzer.detectPii) {
          piiResult = OSNPiiAnalyzer.detectPii(info.selectionText, customPatterns);
        }

        chrome.tabs.sendMessage(tab.id, {
          action: "displayScanResult",
          targetType: "selection",
          targetValue: info.selectionText,
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


