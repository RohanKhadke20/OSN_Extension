const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { HeadlessBrowser, CdpPage, findBrowserPath } = require("./cdp-client.js");

describe("E2E Headless Extension Lifecycle & UI Test Suite", () => {
  const browserPath = findBrowserPath();
  const hasBrowser = browserPath !== null;

  if (!hasBrowser) {
    it.skip("skipped because no local Chrome/Edge browser binary was found", () => {});
    return;
  }

  let browser;
  let extensionId;
  let httpServer;
  let httpPort;

  before(async () => {
    // Start local HTTP server to serve test-page.html
    httpServer = http.createServer((req, res) => {
      const filePath = path.resolve(__dirname, "../../test-page.html");
      const html = fs.readFileSync(filePath);
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(html);
    });

    await new Promise(resolve => {
      httpServer.listen(0, "127.0.0.1", () => {
        httpPort = httpServer.address().port;
        resolve();
      });
    });

    browser = new HeadlessBrowser({
      extensionPath: path.resolve(__dirname, "../..")
    });
    await browser.launch();
    extensionId = await browser.getExtensionId();
  });

  after(async () => {
    if (browser) {
      await browser.close();
    }
    if (httpServer) {
      httpServer.close();
    }
  });

  it("loads unpacked extension and activates background service worker", async () => {
    assert.ok(extensionId, "Expected valid 32-character extension ID");
    assert.match(extensionId, /^[a-z0-9]{32}$/, `Extension ID "${extensionId}" has invalid format`);

    const targets = await browser.getTargets();
    const serviceWorkerTarget = targets.find(t => t.type === "service_worker" && (t.url || "").includes(extensionId));
    assert.ok(serviceWorkerTarget, "Expected active service_worker target in browser DevTools");
  });

  it("renders options page (options.html) with intact controls and backup utilities", async () => {
    assert.ok(extensionId);
    const optionsUrl = `chrome-extension://${extensionId}/options/options.html`;
    const page = await browser.openPage(optionsUrl);

    await page.waitForFunction(() => document.title && document.title.includes("OSN Guard"));

    const pageData = await page.evaluate(`
      (() => {
        return {
          title: document.title,
          hasPiiNameInput: Boolean(document.getElementById("new-pii-name")),
          hasPiiPatternInput: Boolean(document.getElementById("new-pii-pattern")),
          hasAddPiiBtn: Boolean(document.getElementById("add-pii-btn")),
          hasWhitelistInput: Boolean(document.getElementById("new-whitelist-domain")),
          hasAddWhitelistBtn: Boolean(document.getElementById("add-whitelist-btn")),
          hasExportBtn: Boolean(document.getElementById("export-config-btn")),
          hasImportInput: Boolean(document.getElementById("import-config-file")),
          hasResetStatsBtn: Boolean(document.getElementById("reset-stats-btn")),
          hasSandboxInput: Boolean(document.getElementById("sandbox-input-text")),
          hasSandboxOutput: Boolean(document.getElementById("sandbox-output-text")),
          hasCopySanitizedBtn: Boolean(document.getElementById("copy-sanitized-btn")),
          hasSandboxFindings: Boolean(document.getElementById("sandbox-findings")),
          hasAuditContainer: Boolean(document.getElementById("audit-log-container")),
          hasExportAuditBtn: Boolean(document.getElementById("export-audit-btn")),
          hasClearAuditBtn: Boolean(document.getElementById("clear-audit-btn"))
        };
      })()
    `);

    assert.ok(pageData.title.includes("OSN Guard"), `Unexpected title: ${pageData.title}`);
    assert.equal(pageData.hasPiiNameInput, true);
    assert.equal(pageData.hasPiiPatternInput, true);
    assert.equal(pageData.hasAddPiiBtn, true);
    assert.equal(pageData.hasWhitelistInput, true);
    assert.equal(pageData.hasAddWhitelistBtn, true);
    assert.equal(pageData.hasExportBtn, true);
    assert.equal(pageData.hasImportInput, true);
    assert.equal(pageData.hasResetStatsBtn, true);
    assert.equal(pageData.hasSandboxInput, true);
    assert.equal(pageData.hasSandboxOutput, true);
    assert.equal(pageData.hasCopySanitizedBtn, true);
    assert.equal(pageData.hasSandboxFindings, true);
    assert.equal(pageData.hasAuditContainer, true);
    assert.equal(pageData.hasExportAuditBtn, true);
    assert.equal(pageData.hasClearAuditBtn, true);

    // Verify live PII sandbox sanitizes input text in real time
    const sanitizedOutput = await page.evaluate(`
      (() => {
        const input = document.getElementById("sandbox-input-text");
        const output = document.getElementById("sandbox-output-text");
        input.value = "Contact me at alice@testcompany.org or 4111 1111 1111 1111.";
        input.dispatchEvent(new Event("input"));
        return output.value;
      })()
    `);

    assert.ok(sanitizedOutput.includes("a***e@testcompany.org"), `Expected masked email, got: ${sanitizedOutput}`);
    assert.ok(sanitizedOutput.includes("****-****-****-1111"), `Expected masked card, got: ${sanitizedOutput}`);

    page.close();
  });

  it("renders popup page (popup.html) with score gauge and shield status cards", async () => {
    assert.ok(extensionId);
    const popupUrl = `chrome-extension://${extensionId}/popup/popup.html`;
    const page = await browser.openPage(popupUrl);

    await page.waitForFunction(() => document.title && document.title.includes("OSN Guard"));

    const popupData = await page.evaluate(`
      (() => {
        return {
          title: document.title,
          hasScoreVal: Boolean(document.getElementById("score-value")),
          hasStatusText: Boolean(document.getElementById("status-text")),
          hasPiiShield: Boolean(document.getElementById("shield-pii")),
          hasUrlShield: Boolean(document.getElementById("shield-url")),
          hasContentShield: Boolean(document.getElementById("shield-content")),
          hasSecurityShield: Boolean(document.getElementById("shield-security")),
          hasOptionsLink: Boolean(document.getElementById("view-options-link")),
          hasRescanBtn: Boolean(document.getElementById("rescan-btn"))
        };
      })()
    `);

    assert.ok(popupData.title.includes("OSN Guard"));
    assert.equal(popupData.hasScoreVal, true);
    assert.equal(popupData.hasStatusText, true);
    assert.equal(popupData.hasPiiShield, true);
    assert.equal(popupData.hasUrlShield, true);
    assert.equal(popupData.hasContentShield, true);
    assert.equal(popupData.hasSecurityShield, true);
    assert.equal(popupData.hasOptionsLink, true);
    assert.equal(popupData.hasRescanBtn, true);

    page.close();
  });

  it("injects content script and analyzes DOM on interactive pages", async () => {
    const testPageUrl = `http://127.0.0.1:${httpPort}/test-page.html`;
    const page = await browser.openPage(testPageUrl);

    // Wait for content script initial scan (content.js has 1000ms initial scan delay)
    await page.waitForFunction(() => {
      return document.querySelectorAll("[data-osn-scanned]").length > 0;
    }, 8000, 200);

    const scanData = await page.evaluate(`
      (() => {
        return {
          urlBadges: document.querySelectorAll("[data-threat-type='url']").length,
          contentBadges: document.querySelectorAll("[data-threat-type='content']").length,
          formBadges: document.querySelectorAll("[data-threat-type='security']").length,
          scannedNodes: document.querySelectorAll("[data-osn-scanned]").length
        };
      })()
    `);

    assert.ok(scanData.scannedNodes > 0, "Content script did not scan any nodes on test-page.html");
    assert.ok(
      scanData.urlBadges > 0 || scanData.contentBadges > 0 || scanData.formBadges > 0,
      `Expected badges on test page, found: ${JSON.stringify(scanData)}`
    );
    assert.ok(scanData.formBadges >= 1, `Expected at least 1 form badge on test-page.html, found ${scanData.formBadges}`);

    // Verify accessible keyboard interaction on warning badges
    const badgeAccessibility = await page.evaluate(`
      (() => {
        const badge = document.querySelector(".osn-guard-warning-badge");
        if (!badge) return null;
        return {
          role: badge.getAttribute("role"),
          tabindex: badge.getAttribute("tabindex"),
          ariaExpanded: badge.getAttribute("aria-expanded"),
          ariaHaspopup: badge.getAttribute("aria-haspopup"),
          hasAriaLabel: Boolean(badge.getAttribute("aria-label"))
        };
      })()
    `);

    assert.ok(badgeAccessibility, "Warning badge was not found in DOM");
    assert.equal(badgeAccessibility.role, "button");
    assert.equal(badgeAccessibility.tabindex, "0");
    assert.equal(badgeAccessibility.ariaExpanded, "false");
    assert.equal(badgeAccessibility.ariaHaspopup, "dialog");
    assert.equal(badgeAccessibility.hasAriaLabel, true);

    // Trigger Enter keydown to toggle tooltip
    const enterResult = await page.evaluate(`
      (() => {
        const badge = document.querySelector(".osn-guard-warning-badge");
        badge.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
        const tooltip = document.querySelector(".osn-guard-floating-tooltip");
        return {
          ariaExpanded: badge.getAttribute("aria-expanded"),
          tooltipDisplay: tooltip ? tooltip.style.display : "none",
          tooltipText: tooltip ? tooltip.textContent : ""
        };
      })()
    `);

    assert.equal(enterResult.ariaExpanded, "true");
    assert.equal(enterResult.tooltipDisplay, "block");
    assert.ok(enterResult.tooltipText.includes("OSN Guard"));

    // Trigger Escape keydown to dismiss tooltip
    const escResult = await page.evaluate(`
      (() => {
        const badge = document.querySelector(".osn-guard-warning-badge");
        badge.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
        const tooltip = document.querySelector(".osn-guard-floating-tooltip");
        return {
          ariaExpanded: badge.getAttribute("aria-expanded"),
          tooltipDisplay: tooltip ? tooltip.style.display : "none"
        };
      })()
    `);

    assert.equal(escResult.ariaExpanded, "false");
    assert.equal(escResult.tooltipDisplay, "none");

    // Verify scan result toast dispatch to content script
    const targets = await browser.getTargets();
    const swTarget = targets.find(t => t.type === "service_worker" && (t.url || "").includes(extensionId));
    if (swTarget && swTarget.webSocketDebuggerUrl) {
      const swClient = new CdpPage(swTarget.webSocketDebuggerUrl);
      await swClient.connect();
      await swClient.evaluate(`
        new Promise((resolve) => {
          chrome.tabs.query({}, (tabs) => {
            const targetTab = Array.isArray(tabs)
              ? (tabs.find(t => (t.url || "").includes("test-page.html")) || tabs[tabs.length - 1])
              : null;
            if (targetTab && targetTab.id) {
              chrome.tabs.sendMessage(targetTab.id, {
                action: "displayScanResult",
                targetType: "link",
                targetValue: "https://win-iphone-now.xyz",
                result: {
                  safe: false,
                  reason: "Matched known phishing/malicious database pattern",
                  severity: "critical"
                }
              }, resolve);
            } else {
              resolve();
            }
          });
        })
      `);
      swClient.close();

      await page.waitForFunction(() => {
        return Boolean(document.getElementById("osn-guard-toast-container"));
      }, 6000, 150);

      const toastData = await page.evaluate(`
        (() => {
          const toast = document.querySelector(".osn-guard-toast");
          const title = toast ? toast.querySelector(".osn-guard-toast-title")?.textContent : "";
          const msg = toast ? toast.querySelector(".osn-guard-toast-message")?.textContent : "";
          const hasClose = Boolean(toast ? toast.querySelector(".osn-guard-toast-close") : false);
          return { exists: Boolean(toast), title, msg, hasClose };
        })()
      `);

      assert.equal(toastData.exists, true, "Toast did not appear after displayScanResult");
      assert.match(toastData.title, /dangerous link/i);
      assert.equal(toastData.hasClose, true);
    }

    page.close();
  });
});
