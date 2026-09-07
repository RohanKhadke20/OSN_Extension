/**
 * Zero-Dependency Chrome DevTools Protocol (CDP) Test Client
 *
 * Automates Chrome/Edge in headless mode using native Node.js (child_process, WebSocket, fetch)
 * to test MV3 Chrome Extension lifecycle, options page, popup, and content script injection.
 */

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

/**
 * Finds a free TCP port for Chrome remote debugging.
 * @returns {Promise<number>}
 */
function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

/**
 * Locates available Chrome or Edge browser binary.
 * @returns {string | null}
 */
function findBrowserPath() {
  if (process.env.CHROME_BIN && fs.existsSync(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN;
  }

  const candidates = [];
  if (process.platform === "win32") {
    // Prefer Microsoft Edge on Windows as headless extension loading is stable and enabled by default
    candidates.push(
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    );
  } else if (process.platform === "darwin") {
    candidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
    );
  } else {
    candidates.push(
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium-browser",
      "/usr/bin/chromium"
    );
  }

  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

class CdpPage {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.msgId = 1;
    this.pendingRequests = new Map();
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onopen = () => resolve();
      this.ws.onerror = (err) => reject(err);
      this.ws.onmessage = (event) => {
        try {
          const res = JSON.parse(event.data);
          if (res.id && this.pendingRequests.has(res.id)) {
            const { resolve, reject } = this.pendingRequests.get(res.id);
            this.pendingRequests.delete(res.id);
            if (res.error) {
              reject(new Error(res.error.message));
            } else {
              resolve(res.result);
            }
          }
        } catch (err) {
          // ignore unparseable
        }
      };
    });
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      this.pendingRequests.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async navigate(url) {
    await this.send("Page.enable");
    const result = await this.send("Page.navigate", { url });
    await new Promise(r => setTimeout(r, 600));
    return result;
  }

  async evaluate(expression) {
    const res = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true
    });
    return res && res.result ? res.result.value : undefined;
  }

  async waitForFunction(fnExpression, timeoutMs = 6000, intervalMs = 150) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const val = await this.evaluate(`(${fnExpression})()`);
        if (val) return val;
      } catch {
        // continue polling
      }
      await new Promise(r => setTimeout(r, intervalMs));
    }
    throw new Error(`waitForFunction timed out after ${timeoutMs}ms`);
  }

  close() {
    if (this.ws) {
      try {
        this.ws.close();
      } catch {}
    }
  }
}

class HeadlessBrowser {
  constructor(options = {}) {
    this.extensionPath = options.extensionPath || path.resolve(__dirname, "../..");
    this.browserPath = options.browserPath || findBrowserPath();
    this.port = null;
    this.proc = null;
    this.tempProfileDir = null;
  }

  isAvailable() {
    return this.browserPath !== null;
  }

  async launch() {
    if (!this.browserPath) {
      throw new Error("No supported Chrome/Edge browser executable detected.");
    }

    this.port = await getFreePort();
    this.tempProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), "osn-e2e-profile-"));

    const args = [
      "--headless=new",
      `--remote-debugging-port=${this.port}`,
      `--load-extension=${this.extensionPath}`,
      `--user-data-dir=${this.tempProfileDir}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-default-apps",
      "--disable-background-networking",
      "--disable-sync",
      "about:blank"
    ];

    this.proc = spawn(this.browserPath, args, { stdio: "ignore" });

    // Wait until DevTools HTTP endpoint is responsive
    const startTime = Date.now();
    const timeout = 10000;
    while (Date.now() - startTime < timeout) {
      try {
        const res = await fetch(`http://127.0.0.1:${this.port}/json/version`);
        if (res.ok) break;
      } catch {
        // Retry
      }
      await new Promise(r => setTimeout(r, 150));
    }

    // Give extension time to initialize background service worker
    await new Promise(r => setTimeout(r, 1200));
  }

  async getTargets() {
    const res = await fetch(`http://127.0.0.1:${this.port}/json/list`);
    return res.json();
  }

  async getExtensionId() {
    const targets = await this.getTargets();
    for (const target of targets) {
      if ((target.url || "").includes("background.js") || (target.title || "").includes("OSN Guard")) {
        const match = (target.url || "").match(/chrome-extension:\/\/([a-z0-9]+)\//);
        if (match) return match[1];
      }
    }
    for (const target of targets) {
      if (target.type === "service_worker" && !(target.url || "").includes("nkeimhogjdpnpccoofpliimaahmaaome")) {
        const match = (target.url || "").match(/chrome-extension:\/\/([a-z0-9]+)\//);
        if (match) return match[1];
      }
    }
    return null;
  }

  async openPage(url = "about:blank") {
    const newRes = await fetch(`http://127.0.0.1:${this.port}/json/new?${encodeURIComponent(url)}`, { method: "PUT" });
    const target = await newRes.json();

    const page = new CdpPage(target.webSocketDebuggerUrl);
    await page.connect();
    await new Promise(r => setTimeout(r, 600));
    return page;
  }

  async close() {
    if (this.proc) {
      try {
        this.proc.kill("SIGTERM");
      } catch {}
      this.proc = null;
    }

    if (this.tempProfileDir && fs.existsSync(this.tempProfileDir)) {
      setTimeout(() => {
        try {
          fs.rmSync(this.tempProfileDir, { recursive: true, force: true });
        } catch {}
      }, 500);
    }
  }
}

module.exports = {
  HeadlessBrowser,
  CdpPage,
  findBrowserPath
};
