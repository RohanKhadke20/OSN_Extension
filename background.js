// Background service worker for OSN Guard (Manifest V3)
importScripts("core/url-analyzer.js");

// Storage adapter prioritizing session storage for ephemeral tab state
const getSessionStorage = () => {
  return chrome.storage && chrome.storage.session ? chrome.storage.session : chrome.storage.local;
};

// Initialize default settings on install or update
chrome.runtime.onInstalled.addListener(() => {
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

// Clean up tab data when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  const tabKey = `tab_${tabId}`;
  getSessionStorage().remove(tabKey);
});
