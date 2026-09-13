/**
 * OSN Guard - Comprehensive Cross-Browser Compatibility Test Suite
 * 
 * Verifies cross-browser namespace unification, dual callback/Promise invocation,
 * storage session and managed fallbacks, action/contextMenu normalization,
 * internal URL detection, review store URL resolution, boundary error handling,
 * idempotency, prototype pollution defenses, pairwise browser matrix, and
 * real-world simulated browser execution.
 */

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Target path for production shim; fallback to explorer proposed artifact during staged authoring
const CORE_COMPAT_PATH = path.resolve(__dirname, "../core/compat.js");
const EXPLORER_COMPAT_PATH = path.resolve(__dirname, "../.agents/m1_explorer_1/proposed_compat.js");

const COMPAT_PATH = fs.existsSync(CORE_COMPAT_PATH)
  ? CORE_COMPAT_PATH
  : (fs.existsSync(EXPLORER_COMPAT_PATH) ? EXPLORER_COMPAT_PATH : null);

if (!COMPAT_PATH) {
  throw new Error("Compatibility shim not found at core/compat.js or explorer workspace fallback.");
}

const compatSource = fs.readFileSync(COMPAT_PATH, "utf8");
const OSNCompat = require(COMPAT_PATH);

// ---------------------------------------------------------------------------
// Isolated Test Sandbox Factory
// ---------------------------------------------------------------------------

function createSandbox(options = {}) {
  const userAgent = options.userAgent ||
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

  const sandbox = {
    globalThis: null,
    self: null,
    window: null,
    navigator: { userAgent },
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    Promise: Promise,
    Error: Error,
    TypeError: TypeError,
    Array: Array,
    Object: Object,
    String: String,
    Boolean: Boolean,
    Number: Number,
    Function: Function,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
  };

  if ("chrome" in options) sandbox.chrome = options.chrome;
  if ("browser" in options) sandbox.browser = options.browser;

  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;

  const context = vm.createContext(sandbox);

  if (options.runShim !== false) {
    vm.runInContext(compatSource, context);
  }

  return context;
}

// ---------------------------------------------------------------------------
// Mock Environment Builders
// ---------------------------------------------------------------------------

function createMockChromiumApi(initialStore = {}) {
  const localStore = { ...initialStore };
  const sessionStore = {};
  return {
    runtime: {
      id: "osn-guard-chrome-mv3",
      getURL: (p) => "chrome-extension://osn-guard-chrome-mv3/" + p,
      sendMessage: (...args) => {
        const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
        const msg = args.length > 0 && args[0] !== cb ? args[0] : null;
        setTimeout(() => {
          if (cb) cb({ status: "chrome-ack", echoed: msg });
        }, 0);
      }
    },
    storage: {
      local: {
        get: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          const keys = args.length > 0 && args[0] !== cb ? args[0] : null;
          setTimeout(() => {
            if (cb) {
              if (keys === null || keys === undefined) return cb({ ...localStore });
              if (typeof keys === "string") return cb({ [keys]: localStore[keys] });
              if (Array.isArray(keys)) {
                const res = {};
                keys.forEach((k) => { res[k] = localStore[k]; });
                return cb(res);
              }
              if (typeof keys === "object") {
                const res = {};
                Object.keys(keys).forEach((k) => { res[k] = k in localStore ? localStore[k] : keys[k]; });
                return cb(res);
              }
              cb({ ...localStore });
            }
          }, 0);
        },
        set: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          const items = args.length > 0 && args[0] !== cb ? args[0] : null;
          setTimeout(() => {
            if (items && typeof items === "object") {
              Object.assign(localStore, items);
            }
            if (cb) cb();
          }, 0);
        },
        remove: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          const keys = args.length > 0 && args[0] !== cb ? args[0] : null;
          setTimeout(() => {
            if (keys) {
              const list = Array.isArray(keys) ? keys : [keys];
              list.forEach((k) => delete localStore[k]);
            }
            if (cb) cb();
          }, 0);
        },
        clear: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          setTimeout(() => {
            Object.keys(localStore).forEach((k) => delete localStore[k]);
            if (cb) cb();
          }, 0);
        }
      },
      session: {
        get: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          const keys = args.length > 0 && args[0] !== cb ? args[0] : null;
          setTimeout(() => {
            if (cb) {
              if (keys === null || keys === undefined) return cb({ ...sessionStore });
              if (typeof keys === "string") return cb({ [keys]: sessionStore[keys] });
              cb({ ...sessionStore });
            }
          }, 0);
        },
        set: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          const items = args.length > 0 && args[0] !== cb ? args[0] : null;
          setTimeout(() => {
            if (items && typeof items === "object") {
              Object.assign(sessionStore, items);
            }
            if (cb) cb();
          }, 0);
        },
        remove: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          const keys = args.length > 0 && args[0] !== cb ? args[0] : null;
          setTimeout(() => {
            if (keys) {
              const list = Array.isArray(keys) ? keys : [keys];
              list.forEach((k) => delete sessionStore[k]);
            }
            if (cb) cb();
          }, 0);
        },
        clear: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          setTimeout(() => {
            Object.keys(sessionStore).forEach((k) => delete sessionStore[k]);
            if (cb) cb();
          }, 0);
        }
      },
      managed: {
        get: (...args) => {
          const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
          setTimeout(() => {
            if (cb) cb({ forcedWhitelistedDomains: ["enterprise.internal"] });
          }, 0);
        }
      }
    },
    tabs: {
      query: (...args) => {
        const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
        setTimeout(() => {
          if (cb) cb([{ id: 101, url: "https://example.com", active: true }]);
        }, 0);
      },
      create: (...args) => {
        const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
        const props = args.length > 0 && args[0] !== cb ? args[0] : {};
        setTimeout(() => {
          if (cb) cb({ id: 202, url: props.url });
        }, 0);
      },
      sendMessage: (...args) => {
        const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
        const tabId = args[0];
        const msg = args[1];
        setTimeout(() => {
          if (cb) cb({ tabId, received: true, msg });
        }, 0);
      }
    },
    action: {
      setBadgeText: (details) => {},
      setBadgeBackgroundColor: (details) => {}
    },
    contextMenus: {
      removeAll: (...args) => {
        const cb = typeof args[args.length - 1] === "function" ? args[args.length - 1] : null;
        setTimeout(() => { if (cb) cb(); }, 0);
      },
      create: (item) => {}
    }
  };
}

function createMockFirefoxApi(initialStore = {}) {
  const localStore = { ...initialStore };
  return {
    runtime: {
      id: "osn-guard-firefox-uuid",
      getURL: (p) => "moz-extension://osn-guard-firefox-uuid/" + p,
      sendMessage: (msg) => Promise.resolve({ status: "firefox-ack", echoed: msg })
    },
    storage: {
      local: {
        get: (keys) => {
          if (keys === null || keys === undefined) return Promise.resolve({ ...localStore });
          if (typeof keys === "string") return Promise.resolve({ [keys]: localStore[keys] });
          if (Array.isArray(keys)) {
            const res = {};
            keys.forEach((k) => { res[k] = localStore[k]; });
            return Promise.resolve(res);
          }
          return Promise.resolve({ ...localStore });
        },
        set: (items) => {
          Object.assign(localStore, items);
          return Promise.resolve();
        },
        remove: (keys) => {
          const list = Array.isArray(keys) ? keys : [keys];
          list.forEach((k) => delete localStore[k]);
          return Promise.resolve();
        },
        clear: () => {
          Object.keys(localStore).forEach((k) => delete localStore[k]);
          return Promise.resolve();
        }
      }
      // Note: storage.session and storage.managed intentionally undefined to test polyfill
    },
    tabs: {
      query: (queryInfo) => Promise.resolve([{ id: 303, url: "https://mozilla.org", active: true }]),
      create: (props) => Promise.resolve({ id: 404, url: props.url }),
      sendMessage: (tabId, msg) => Promise.resolve({ tabId, ack: true })
    },
    browserAction: {
      setBadgeText: (details) => {},
      setBadgeBackgroundColor: (details) => {}
    },
    menus: {
      removeAll: () => Promise.resolve(),
      create: (item) => {}
    }
  };
}

// ===========================================================================
// TIER 1: FEATURE COVERAGE (>=5 tests per feature)
// ===========================================================================

describe("Tier 1: Feature Coverage", () => {

  // -------------------------------------------------------------------------
  // Feature 1.1: Bidirectional Namespace Mirror
  // -------------------------------------------------------------------------
  describe("1.1 Bidirectional Namespace Mirror", () => {
    it("mirrors chrome to browser when only chrome is defined", () => {
      const mockChrome = { runtime: { id: "test-id" }, storage: {} };
      const ctx = createSandbox({ chrome: mockChrome, browser: undefined });

      assert.ok(ctx.browser, "browser namespace should be created");
      assert.equal(ctx.browser.runtime.id, "test-id", "browser should mirror chrome.runtime.id");
      assert.equal(ctx.chrome.runtime.id, "test-id", "chrome.runtime.id should be preserved");
    });

    it("mirrors browser to chrome when only browser is defined", () => {
      const mockBrowser = { runtime: { id: "ff-uuid" }, tabs: {} };
      const ctx = createSandbox({
        userAgent: "Mozilla/5.0 Firefox/128.0",
        chrome: undefined,
        browser: mockBrowser
      });

      assert.ok(ctx.chrome, "chrome namespace should be created");
      assert.equal(ctx.chrome.runtime.id, "ff-uuid", "chrome should mirror browser.runtime.id");
      assert.equal(ctx.browser.runtime.id, "ff-uuid", "browser.runtime.id should be preserved");
    });

    it("synchronizes sub-namespaces when present on only one side", () => {
      const mockChrome = { runtime: { id: "sub-test" } };
      const mockBrowser = { tabs: { query: () => {} } };
      const ctx = createSandbox({ chrome: mockChrome, browser: mockBrowser });

      assert.ok(ctx.chrome.tabs, "chrome should receive tabs from browser");
      assert.ok(ctx.browser.runtime, "browser should receive runtime from chrome");
      assert.equal(ctx.browser.runtime.id, "sub-test");
    });

    it("synchronizes runtime properties across existing runtimes", () => {
      const mockChrome = { runtime: { id: "sync-id" } };
      const mockBrowser = { runtime: { getURL: (p) => "moz://" + p } };
      const ctx = createSandbox({ chrome: mockChrome, browser: mockBrowser });

      assert.equal(ctx.browser.runtime.id, "sync-id", "browser.runtime.id synced from chrome");
      assert.equal(typeof ctx.chrome.runtime.getURL, "function", "chrome.runtime.getURL synced from browser");
      assert.equal(ctx.chrome.runtime.getURL("test"), "moz://test");
    });

    it("invoking a method through mirrored namespace invokes underlying implementation", async () => {
      let invoked = false;
      const mockChrome = {
        tabs: {
          query: (q, cb) => {
            invoked = true;
            cb([{ id: 99 }]);
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome, browser: undefined });

      const tabs = await ctx.browser.tabs.query({});
      assert.equal(invoked, true, "underlying chrome.tabs.query was invoked");
      assert.equal(tabs[0].id, 99);
    });

    it("creates empty namespaces gracefully when neither chrome nor browser is defined", () => {
      const ctx = createSandbox({ chrome: undefined, browser: undefined });
      assert.ok(ctx.chrome, "chrome namespace created");
      assert.ok(ctx.browser, "browser namespace created");
      assert.ok(ctx.OSNCompat, "OSNCompat created");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.2: Asynchronous Dual-Mode (Callback vs Promise)
  // -------------------------------------------------------------------------
  describe("1.2 Asynchronous Dual-Mode Invocation", () => {
    it("supports storage.local.get with callback style", (t, done) => {
      const mockChrome = createMockChromiumApi({ pref: "enabled" });
      const ctx = createSandbox({ chrome: mockChrome });

      ctx.chrome.storage.local.get("pref", (res) => {
        assert.equal(res.pref, "enabled");
        done();
      });
    });

    it("supports storage.local.get with Promise style", async () => {
      const mockChrome = createMockChromiumApi({ pref: "promise-enabled" });
      const ctx = createSandbox({ chrome: mockChrome });

      const res = await ctx.chrome.storage.local.get("pref");
      assert.equal(res.pref, "promise-enabled");
    });

    it("supports storage.local.set and remove in both styles", async () => {
      const mockChrome = createMockChromiumApi();
      const ctx = createSandbox({ chrome: mockChrome });

      // Callback set
      await new Promise((resolve) => {
        ctx.chrome.storage.local.set({ key1: "val1" }, resolve);
      });

      // Promise get
      const got = await ctx.chrome.storage.local.get("key1");
      assert.equal(got.key1, "val1");

      // Promise remove
      await ctx.chrome.storage.local.remove("key1");

      // Callback get
      const after = await new Promise((resolve) => {
        ctx.chrome.storage.local.get("key1", resolve);
      });
      assert.equal(after.key1, undefined);
    });

    it("supports runtime.sendMessage in both callback and Promise styles", async () => {
      const mockChrome = createMockChromiumApi();
      const ctx = createSandbox({ chrome: mockChrome });

      // Callback
      const cbRes = await new Promise((resolve) => {
        ctx.chrome.runtime.sendMessage({ test: "cb" }, resolve);
      });
      assert.equal(cbRes.status, "chrome-ack");

      // Promise
      const pRes = await ctx.chrome.runtime.sendMessage({ test: "promise" });
      assert.equal(pRes.status, "chrome-ack");
    });

    it("supports tabs.query and tabs.create in both styles", async () => {
      const mockChrome = createMockChromiumApi();
      const ctx = createSandbox({ chrome: mockChrome });

      // Query via Promise
      const tabs = await ctx.chrome.tabs.query({ active: true });
      assert.equal(tabs[0].id, 101);

      // Create via Callback
      const created = await new Promise((resolve) => {
        ctx.chrome.tabs.create({ url: "https://safe.test" }, resolve);
      });
      assert.equal(created.id, 202);
      assert.equal(created.url, "https://safe.test");
    });

    it("bridges native Promise methods to callback style in Firefox", (t, done) => {
      const mockFirefox = createMockFirefoxApi({ ffKey: "gecko" });
      const ctx = createSandbox({
        userAgent: "Mozilla/5.0 Firefox/128.0",
        browser: mockFirefox
      });

      ctx.chrome.storage.local.get("ffKey", (res) => {
        assert.equal(res.ffKey, "gecko");
        done();
      });
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.3: Storage Session Fallback
  // -------------------------------------------------------------------------
  describe("1.3 Storage Session Fallback", () => {
    it("attaches fallback when storage.session is undefined", () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      assert.ok(ctx.chrome.storage.session, "storage.session must be created");
      assert.equal(typeof ctx.chrome.storage.session.get, "function");
      assert.equal(typeof ctx.chrome.storage.session.set, "function");
      assert.equal(typeof ctx.chrome.storage.session.remove, "function");
      assert.equal(typeof ctx.chrome.storage.session.clear, "function");
    });

    it("prefixes keys stored in underlying storage to prevent collision", async () => {
      const localStore = {};
      const mockChrome = {
        storage: {
          local: {
            get: (k, cb) => cb(localStore),
            set: (it, cb) => { Object.assign(localStore, it); if (cb) cb(); },
            remove: (k, cb) => { if (cb) cb(); },
            clear: (cb) => { if (cb) cb(); }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ tab_1: { threat: "none" } });
      assert.ok(localStore["__osn_session_:tab_1"], "underlying storage should contain prefixed key");
      assert.equal(localStore["__osn_session_:tab_1"].threat, "none");
    });

    it("retrieves single and multiple keys stripping prefix transparently", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ alpha: 1, beta: 2 });

      const single = await ctx.chrome.storage.session.get("alpha");
      assert.equal(single.alpha, 1);
      assert.equal(single["__osn_session_:alpha"], undefined, "prefix must be stripped");

      const multi = await ctx.chrome.storage.session.get(["alpha", "beta"]);
      assert.equal(multi.alpha, 1);
      assert.equal(multi.beta, 2);
    });

    it("get(null) retrieves all session keys without prefix", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.local.set({ persistentKey: "keep" });
      await ctx.chrome.storage.session.set({ sessionKey: "ephemeral" });

      const allSession = await ctx.chrome.storage.session.get(null);
      assert.equal(allSession.sessionKey, "ephemeral");
      assert.equal(allSession.persistentKey, undefined, "persistent local keys must not leak into session get(null)");
    });

    it("session.remove and session.clear purge only session items", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.local.set({ permanent: "safe" });
      await ctx.chrome.storage.session.set({ s1: "val1", s2: "val2" });

      await ctx.chrome.storage.session.remove("s1");
      const check1 = await ctx.chrome.storage.session.get("s1");
      assert.equal(check1.s1, undefined);

      await ctx.chrome.storage.session.clear();
      const allSession = await ctx.chrome.storage.session.get(null);
      assert.deepEqual(Object.keys(allSession), []);

      const permanent = await ctx.chrome.storage.local.get("permanent");
      assert.equal(permanent.permanent, "safe", "session.clear must not purge non-session local keys");
    });

    it("uses in-memory store when storage.local is also absent", async () => {
      const mockChrome = { storage: {} };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ inMem: "ok" });
      const res = await ctx.chrome.storage.session.get("inMem");
      assert.equal(res.inMem, "ok");
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.4: Storage Managed Fallback
  // -------------------------------------------------------------------------
  describe("1.4 Storage Managed Fallback", () => {
    it("creates safe managed storage dummy when storage.managed is undefined", () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      assert.ok(ctx.chrome.storage.managed, "storage.managed must be defined");
      assert.equal(typeof ctx.chrome.storage.managed.get, "function");
    });

    it("returns empty object via callback without throwing", (t, done) => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      ctx.chrome.storage.managed.get(null, (res) => {
        assert.ok(res, "result should be defined");
        assert.deepEqual(Object.keys(res), []);
        done();
      });
    });

    it("returns empty object via Promise without throwing", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      const res = await ctx.chrome.storage.managed.get(["forcedWhitelistedDomains", "enforcedShields"]);
      assert.ok(res);
      assert.deepEqual(Object.keys(res), []);
    });

    it("returns empty object for specific string key query", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      const res = await ctx.chrome.storage.managed.get("enforcedShields");
      assert.ok(res);
      assert.equal(res.enforcedShields, undefined);
    });

    it("rejects mutation attempts (set, remove, clear) as read-only", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      await assert.rejects(async () => {
        await ctx.chrome.storage.managed.set({ test: 1 });
      }, /read-only/i);

      await assert.rejects(async () => {
        await ctx.chrome.storage.managed.remove("test");
      }, /read-only/i);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.5: Action / BrowserAction Normalization
  // -------------------------------------------------------------------------
  describe("1.5 Action & BrowserAction Normalization", () => {
    it("aliases action to browserAction when action is provided", () => {
      const mockChrome = {
        action: {
          setBadgeText: (d) => {},
          setBadgeBackgroundColor: (d) => {}
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      assert.ok(ctx.chrome.browserAction, "browserAction should be aliased");
      assert.equal(ctx.chrome.browserAction, ctx.chrome.action);
      assert.equal(ctx.browser.action, ctx.chrome.action);
    });

    it("aliases browserAction to action when only browserAction is provided (Firefox legacy)", () => {
      const mockBrowser = {
        browserAction: {
          setBadgeText: (d) => {},
          setBadgeBackgroundColor: (d) => {}
        }
      };
      const ctx = createSandbox({ browser: mockBrowser });

      assert.ok(ctx.chrome.action, "action should be aliased from browserAction");
      assert.ok(ctx.browser.action, "browser.action should be aliased");
      assert.equal(ctx.browser.action, ctx.browser.browserAction);
    });

    it("invoking setBadgeText via action or browserAction calls the same underlying method", () => {
      let passedText = "";
      const mockChrome = {
        action: {
          setBadgeText: (details) => { passedText = details.text; }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      ctx.chrome.browserAction.setBadgeText({ text: "WARN" });
      assert.equal(passedText, "WARN");

      ctx.browser.action.setBadgeText({ text: "SAFE" });
      assert.equal(passedText, "SAFE");
    });

    it("cross-mirrors action between chrome and browser namespaces", () => {
      const mockChrome = { action: { id: "act" } };
      const ctx = createSandbox({ chrome: mockChrome, browser: {} });

      assert.equal(ctx.browser.action.id, "act");
      assert.equal(ctx.browser.browserAction.id, "act");
    });

    it("does not crash if neither action nor browserAction exists", () => {
      const ctx = createSandbox({ chrome: {}, browser: {} });
      assert.equal(ctx.chrome.action, undefined);
      assert.equal(ctx.chrome.browserAction, undefined);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.6: ContextMenus / Menus Normalization
  // -------------------------------------------------------------------------
  describe("1.6 ContextMenus & Menus Normalization", () => {
    it("aliases contextMenus to menus when contextMenus is provided", () => {
      const mockChrome = {
        contextMenus: {
          removeAll: (cb) => cb(),
          create: (item) => {}
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      assert.ok(ctx.chrome.menus, "chrome.menus should be aliased");
      assert.ok(ctx.browser.contextMenus, "browser.contextMenus should be aliased");
      assert.ok(ctx.browser.menus, "browser.menus should be aliased");
    });

    it("aliases menus to contextMenus when only menus is provided (Firefox)", () => {
      const mockBrowser = {
        menus: {
          removeAll: () => Promise.resolve(),
          create: (item) => {}
        }
      };
      const ctx = createSandbox({ browser: mockBrowser });

      assert.ok(ctx.chrome.contextMenus, "chrome.contextMenus should be aliased from menus");
      assert.ok(ctx.browser.contextMenus, "browser.contextMenus should be aliased from menus");
    });

    it("wraps removeAll for dual callback and Promise invocation", async () => {
      let removed = false;
      const mockChrome = {
        contextMenus: {
          removeAll: (cb) => {
            removed = true;
            if (cb) cb();
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      // Promise style
      await ctx.chrome.contextMenus.removeAll();
      assert.equal(removed, true);

      // Callback style
      removed = false;
      await new Promise((resolve) => {
        ctx.browser.menus.removeAll(resolve);
      });
      assert.equal(removed, true);
    });

    it("preserves native menus object if already defined", () => {
      const mockMenus = { id: "native-menus" };
      const mockContextMenus = { id: "native-cm" };
      const ctx = createSandbox({
        chrome: { contextMenus: mockContextMenus, menus: mockMenus }
      });

      assert.equal(ctx.chrome.contextMenus.id, "native-cm");
      assert.equal(ctx.chrome.menus.id, "native-menus");
    });

    it("does not crash if neither contextMenus nor menus is defined", () => {
      const ctx = createSandbox({ chrome: {}, browser: {} });
      assert.equal(ctx.chrome.contextMenus, undefined);
      assert.equal(ctx.chrome.menus, undefined);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.7: isInternalUrl Scheme Detection
  // -------------------------------------------------------------------------
  describe("1.7 isInternalUrl Detection", () => {
    it("detects Chromium internal URL schemes", () => {
      assert.equal(OSNCompat.isInternalUrl("chrome://settings"), true);
      assert.equal(OSNCompat.isInternalUrl("chrome-extension://abcdef12345/options.html"), true);
      assert.equal(OSNCompat.isInternalUrl("chrome-search://local-ntp/"), true);
    });

    it("detects Firefox internal URL schemes", () => {
      assert.equal(OSNCompat.isInternalUrl("moz-extension://a54b3c2d-1111-2222-3333-444455556666/popup.html"), true);
      assert.equal(OSNCompat.isInternalUrl("about:blank"), true);
      assert.equal(OSNCompat.isInternalUrl("about:config"), true);
      assert.equal(OSNCompat.isInternalUrl("about:addons"), true);
    });

    it("detects Safari internal URL schemes", () => {
      assert.equal(OSNCompat.isInternalUrl("safari-web-extension://7B943A1C-1234-5678-ABCD-EF0123456789/options.html"), true);
      assert.equal(OSNCompat.isInternalUrl("safari://startpage"), true);
      assert.equal(OSNCompat.isInternalUrl("safari-resource://apple.png"), true);
      assert.equal(OSNCompat.isInternalUrl("applewebdata://uuid/index.html"), true);
    });

    it("detects Edge, DevTools, and view-source internal URLs", () => {
      assert.equal(OSNCompat.isInternalUrl("edge://extensions"), true);
      assert.equal(OSNCompat.isInternalUrl("edge://flags"), true);
      assert.equal(OSNCompat.isInternalUrl("devtools://devtools/bundled/inspector.html"), true);
      assert.equal(OSNCompat.isInternalUrl("view-source:https://example.com"), true);
    });

    it("returns false for regular web and internet URLs", () => {
      assert.equal(OSNCompat.isInternalUrl("https://www.google.com"), false);
      assert.equal(OSNCompat.isInternalUrl("http://localhost:8080/dashboard"), false);
      assert.equal(OSNCompat.isInternalUrl("https://addons.mozilla.org"), false);
      assert.equal(OSNCompat.isInternalUrl("ftp://files.example.org"), false);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 1.8: Store Review URL Resolution
  // -------------------------------------------------------------------------
  describe("1.8 Store Review URL Resolution", () => {
    it("returns Chrome Web Store review URL for Chromium environment", () => {
      const ctx = createSandbox({
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
        chrome: { runtime: { id: "ext-123" } }
      });

      const url = ctx.OSNCompat.getStoreReviewUrl("ext-123");
      assert.ok(url.startsWith("https://chromewebstore.google.com/detail/ext-123/reviews"));
    });

    it("defaults to runtime.id or osn-guard when extensionId argument is omitted", () => {
      const ctx = createSandbox({
        userAgent: "Chrome/128.0.0.0",
        chrome: { runtime: { id: "resolved-runtime-id" } }
      });

      const url = ctx.OSNCompat.getStoreReviewUrl();
      assert.ok(url.includes("resolved-runtime-id"));
    });

    it("returns Mozilla AMO URL for Firefox environment", () => {
      const ctx = createSandbox({
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        browser: { runtime: { id: "ff-ext" } }
      });

      const url = ctx.OSNCompat.getStoreReviewUrl("ff-ext");
      assert.equal(url, "https://addons.mozilla.org/firefox/addon/osn-guard/");
    });

    it("returns Apple App Store URL for Safari environment", () => {
      const ctx = createSandbox({
        userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
        browser: { runtime: { id: "safari-ext" } }
      });

      const url = ctx.OSNCompat.getStoreReviewUrl("safari-ext");
      assert.equal(url, "https://apps.apple.com/app/osn-guard");
    });

    it("properly URI-encodes special characters in extensionId", () => {
      const ctx = createSandbox({ userAgent: "Chrome/128.0" });
      const url = ctx.OSNCompat.getStoreReviewUrl("id with spaces&symbols#hash");
      assert.ok(url.includes("id%20with%20spaces%26symbols%23hash"));
    });
  });
});

// ===========================================================================
// TIER 2: BOUNDARY & CORNER CASES (>=5 tests per feature)
// ===========================================================================

describe("Tier 2: Boundary & Corner Cases", () => {

  // -------------------------------------------------------------------------
  // Feature 2.1: Error Handling & lastError Propagation
  // -------------------------------------------------------------------------
  describe("2.1 Error Handling & lastError Propagation", () => {
    it("sets chrome.runtime.lastError when underlying callback produces an error", (t, done) => {
      const mockChrome = {
        runtime: { id: "err-test" },
        storage: {
          local: {
            get: (k, cb) => {
              mockChrome.runtime.lastError = { message: "Disk full" };
              cb(undefined);
            }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      ctx.chrome.storage.local.get("foo", (res) => {
        assert.ok(ctx.chrome.runtime.lastError, "lastError should be set inside callback");
        assert.equal(ctx.chrome.runtime.lastError.message, "Disk full");
        done();
      });
    });

    it("rejects Promise when underlying callback sets lastError", async () => {
      const mockChrome = {
        runtime: { id: "err-test" },
        storage: {
          local: {
            get: (k, cb) => {
              mockChrome.runtime.lastError = { message: "Disk quota exceeded" };
              cb(undefined);
            }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      await assert.rejects(async () => {
        await ctx.chrome.storage.local.get("foo");
      }, /Disk quota exceeded/);
    });

    it("converts rejected native Promise into lastError in callback mode", (t, done) => {
      const mockBrowser = {
        runtime: { id: "gecko-err" },
        storage: {
          local: {
            get: (k) => Promise.reject(new Error("IndexedDB corruption"))
          }
        }
      };
      const ctx = createSandbox({
        userAgent: "Firefox/128.0",
        browser: mockBrowser
      });

      ctx.chrome.storage.local.get("foo", (res) => {
        assert.equal(res, undefined);
        assert.ok(ctx.chrome.runtime.lastError);
        assert.equal(ctx.chrome.runtime.lastError.message, "IndexedDB corruption");
        done();
      });
    });

    it("clears lastError immediately after user callback executes", () => {
      const mockChrome = {
        runtime: { id: "err-cleanup" },
        storage: {
          local: {
            get: (k, cb) => {
              mockChrome.runtime.lastError = { message: "Temporary failure" };
              cb(undefined);
            }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      ctx.chrome.storage.local.get("foo", (res) => {});
      assert.equal(ctx.chrome.runtime.lastError, undefined, "lastError must be cleared after callback completes");
    });

    it("catches synchronous exceptions in underlying API and routes to lastError / rejection", async () => {
      const mockChrome = {
        runtime: { id: "throw-test" },
        storage: {
          local: {
            get: () => { throw new Error("Sync panic"); }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      // Promise mode catches sync throw
      await assert.rejects(async () => {
        await ctx.chrome.storage.local.get("foo");
      }, /Sync panic/);

      // Callback mode sets lastError on sync throw
      await new Promise((resolve) => {
        ctx.chrome.storage.local.get("foo", (res) => {
          assert.equal(res, undefined);
          assert.ok(ctx.chrome.runtime.lastError);
          assert.equal(ctx.chrome.runtime.lastError.message, "Sync panic");
          resolve();
        });
      });
    });

    it("guarantees lastError is null/undefined on successful callback execution", (t, done) => {
      const mockChrome = createMockChromiumApi({ safe: true });
      const ctx = createSandbox({ chrome: mockChrome });

      ctx.chrome.storage.local.get("safe", (res) => {
        assert.equal(ctx.chrome.runtime.lastError, undefined);
        assert.equal(res.safe, true);
        done();
      });
    });
  });

  // -------------------------------------------------------------------------
  // Feature 2.2: Missing Arguments & Undefined Callbacks
  // -------------------------------------------------------------------------
  describe("2.2 Missing Arguments & Undefined Callbacks", () => {
    it("invoking async method with 0 arguments returns a Promise", async () => {
      const mockChrome = createMockChromiumApi({ all: "keys" });
      const ctx = createSandbox({ chrome: mockChrome });

      const promise = ctx.chrome.storage.local.get();
      assert.ok(promise instanceof ctx.Promise || typeof promise.then === "function");
      const res = await promise;
      assert.equal(res.all, "keys");
    });

    it("invoking with undefined or null as callback argument returns a Promise", async () => {
      const mockChrome = createMockChromiumApi({ test: 123 });
      const ctx = createSandbox({ chrome: mockChrome });

      const pUndefined = ctx.chrome.storage.local.get("test", undefined);
      assert.ok(typeof pUndefined.then === "function");
      const resU = await pUndefined;
      assert.equal(resU.test, 123);

      const pNull = ctx.chrome.storage.local.get("test", null);
      assert.ok(typeof pNull.then === "function");
      const resN = await pNull;
      assert.equal(resN.test, 123);
    });

    it("invoking with non-function object as last argument passes argument and returns Promise", async () => {
      const mockChrome = createMockChromiumApi({ keyA: 1, keyB: 2 });
      const ctx = createSandbox({ chrome: mockChrome });

      const res = await ctx.chrome.storage.local.get({ keyA: 0 });
      assert.ok(res);
    });

    it("calling storage.set with empty object resolves without error", async () => {
      const mockChrome = createMockChromiumApi();
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.local.set({});
      await new Promise((resolve) => {
        ctx.chrome.storage.local.set({}, resolve);
      });
    });

    it("calling storage.remove with empty array or single key operates cleanly", async () => {
      const mockChrome = createMockChromiumApi({ k1: 1 });
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.local.remove([]);
      await ctx.chrome.storage.local.remove("k1");
      const res = await ctx.chrome.storage.local.get("k1");
      assert.equal(res.k1, undefined);
    });

    it("promisifyOrCallback handles empty and invalid args gracefully", () => {
      assert.doesNotThrow(() => {
        OSNCompat.promisifyOrCallback(() => "immediate", null, []);
      });
    });
  });

  // -------------------------------------------------------------------------
  // Feature 2.3: URL Scheme Corner Cases
  // -------------------------------------------------------------------------
  describe("2.3 URL Scheme Corner Cases", () => {
    it("handles uppercase schemes correctly", () => {
      assert.equal(OSNCompat.isInternalUrl("CHROME://SETTINGS"), true);
      assert.equal(OSNCompat.isInternalUrl("MOZ-EXTENSION://UUID/POPUP.HTML"), true);
      assert.equal(OSNCompat.isInternalUrl("ABOUT:BLANK"), true);
      assert.equal(OSNCompat.isInternalUrl("EDGE://FLAGS"), true);
    });

    it("handles mixed-case schemes correctly", () => {
      assert.equal(OSNCompat.isInternalUrl("cHrOmE-eXtEnSiOn://abc123/options.html"), true);
      assert.equal(OSNCompat.isInternalUrl("SaFaRi-WeB-eXtEnSiOn://uuid/index.html"), true);
      assert.equal(OSNCompat.isInternalUrl("aBoUt:CoNfIg"), true);
    });

    it("returns false for empty string without error", () => {
      assert.equal(OSNCompat.isInternalUrl(""), false);
    });

    it("returns false for non-string inputs without throwing", () => {
      assert.equal(OSNCompat.isInternalUrl(null), false);
      assert.equal(OSNCompat.isInternalUrl(undefined), false);
      assert.equal(OSNCompat.isInternalUrl(12345), false);
      assert.equal(OSNCompat.isInternalUrl({ url: "chrome://settings" }), false);
      assert.equal(OSNCompat.isInternalUrl(["about:blank"]), false);
    });

    it("handles URLs with leading and trailing whitespace", () => {
      assert.equal(OSNCompat.isInternalUrl("   chrome://settings   "), true);
      assert.equal(OSNCompat.isInternalUrl("\nabout:blank\t"), true);
    });

    it("handles complex path variations, query strings, and hash fragments", () => {
      assert.equal(OSNCompat.isInternalUrl("chrome://settings/privacy?section=cookies#manage"), true);
      assert.equal(OSNCompat.isInternalUrl("moz-extension://uuid/options.html?tab=pii#sandbox"), true);
    });

    it("rejects deceptive substring spoofing attacks", () => {
      assert.equal(OSNCompat.isInternalUrl("https://chrome.google.com/webstore"), false);
      assert.equal(OSNCompat.isInternalUrl("https://about.me"), false);
      assert.equal(OSNCompat.isInternalUrl("http://fake-chrome://settings"), false);
      assert.equal(OSNCompat.isInternalUrl("https://edge.microsoft.com"), false);
    });
  });

  // -------------------------------------------------------------------------
  // Feature 2.4: Idempotency & Prototype Pollution Defenses
  // -------------------------------------------------------------------------
  describe("2.4 Idempotency & Prototype Pollution Defenses", () => {
    it("calling init() multiple times does not break or overwrite existing references", () => {
      const mockChrome = createMockChromiumApi({ initial: 1 });
      const ctx = createSandbox({ chrome: mockChrome });

      const firstBrowser = ctx.browser;
      const firstChrome = ctx.chrome;

      // Execute init multiple times
      ctx.OSNCompat.init(ctx);
      ctx.OSNCompat.init(ctx);

      assert.equal(ctx.browser, firstBrowser, "browser namespace reference preserved");
      assert.equal(ctx.chrome, firstChrome, "chrome namespace reference preserved");
      assert.equal(ctx.chrome.storage.local, firstChrome.storage.local);
    });

    it("repeated method wrapping does not create double-wrapping or nested promises", async () => {
      const mockChrome = createMockChromiumApi({ val: "flat" });
      const ctx = createSandbox({ chrome: mockChrome });

      // Run shim again inside same context
      vm.runInContext(compatSource, ctx);

      const res = await ctx.chrome.storage.local.get("val");
      assert.equal(res.val, "flat", "nested wrapping must not alter resolved payload");
    });

    it("preserves custom user-defined properties during namespace sync", () => {
      const mockChrome = {
        runtime: { id: "custom-id" },
        customModule: { active: true }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      assert.ok(ctx.browser.customModule, "customModule mirrored");
      assert.equal(ctx.browser.customModule.active, true);
    });

    it("ignores __proto__, constructor, and prototype pollution attack keys during sync", () => {
      const maliciousChrome = JSON.parse(
        '{"runtime": {"id": "safe"}, "__proto__": {"polluted": true}, "constructor": {"prototype": {"polluted": true}}}'
      );
      const ctx = createSandbox({ chrome: maliciousChrome });

      assert.equal(ctx.Object.prototype.polluted, undefined, "Object.prototype must not be polluted");
      assert.equal(({}).polluted, undefined, "Empty object must not have polluted property");
    });

    it("storage fallback set ignores prototype pollution attempts", async () => {
      const fallback = OSNCompat.createSessionStorageFallback(null);
      const attackPayload = JSON.parse(
        '{"__proto__": {"injected": "evil"}, "validKey": "safeValue"}'
      );

      await new Promise((resolve) => {
        fallback.set(attackPayload, resolve);
      });
      assert.equal(Object.prototype.injected, undefined, "Object.prototype must not be polluted by fallback.set");
      const res = await new Promise((resolve) => {
        fallback.get("validKey", resolve);
      });
      assert.equal(res.validKey, "safeValue");
    });
  });
});

// ===========================================================================
// TIER 3: PAIRWISE COMBINATIONS
// ===========================================================================

describe("Tier 3: Pairwise Combinations", () => {
  const environments = [
    { name: "Chromium", userAgent: "Chrome/128.0", apiBuilder: createMockChromiumApi },
    { name: "Firefox", userAgent: "Firefox/128.0", apiBuilder: createMockFirefoxApi }
  ];

  for (const env of environments) {
    describe(`${env.name} Environment Combinations`, () => {

      it(`[${env.name} x Callback x storage.local.get x Success]`, (t, done) => {
        const mockApi = env.apiBuilder({ [env.name + "_key"]: 100 });
        const ctx = createSandbox({
          userAgent: env.userAgent,
          chrome: env.name === "Chromium" ? mockApi : undefined,
          browser: env.name === "Firefox" ? mockApi : undefined
        });

        ctx.chrome.storage.local.get(env.name + "_key", (res) => {
          assert.equal(res[env.name + "_key"], 100);
          done();
        });
      });

      it(`[${env.name} x Promise x storage.local.get x Success]`, async () => {
        const mockApi = env.apiBuilder({ [env.name + "_key"]: 200 });
        const ctx = createSandbox({
          userAgent: env.userAgent,
          chrome: env.name === "Chromium" ? mockApi : undefined,
          browser: env.name === "Firefox" ? mockApi : undefined
        });

        const res = await ctx.chrome.storage.local.get(env.name + "_key");
        assert.equal(res[env.name + "_key"], 200);
      });

      it(`[${env.name} x Callback x runtime.sendMessage x Success]`, (t, done) => {
        const mockApi = env.apiBuilder();
        const ctx = createSandbox({
          userAgent: env.userAgent,
          chrome: env.name === "Chromium" ? mockApi : undefined,
          browser: env.name === "Firefox" ? mockApi : undefined
        });

        ctx.chrome.runtime.sendMessage({ test: "pairwise-cb" }, (res) => {
          assert.ok(res);
          assert.ok(res.status.includes("ack"));
          done();
        });
      });

      it(`[${env.name} x Promise x runtime.sendMessage x Success]`, async () => {
        const mockApi = env.apiBuilder();
        const ctx = createSandbox({
          userAgent: env.userAgent,
          chrome: env.name === "Chromium" ? mockApi : undefined,
          browser: env.name === "Firefox" ? mockApi : undefined
        });

        const res = await ctx.chrome.runtime.sendMessage({ test: "pairwise-p" });
        assert.ok(res);
        assert.ok(res.status.includes("ack"));
      });

      it(`[${env.name} x Callback x tabs.query x Success]`, (t, done) => {
        const mockApi = env.apiBuilder();
        const ctx = createSandbox({
          userAgent: env.userAgent,
          chrome: env.name === "Chromium" ? mockApi : undefined,
          browser: env.name === "Firefox" ? mockApi : undefined
        });

        ctx.chrome.tabs.query({ active: true }, (tabs) => {
          assert.ok(Array.isArray(tabs));
          assert.ok(tabs.length > 0);
          done();
        });
      });

      it(`[${env.name} x Promise x tabs.query x Success]`, async () => {
        const mockApi = env.apiBuilder();
        const ctx = createSandbox({
          userAgent: env.userAgent,
          chrome: env.name === "Chromium" ? mockApi : undefined,
          browser: env.name === "Firefox" ? mockApi : undefined
        });

        const tabs = await ctx.chrome.tabs.query({ active: true });
        assert.ok(Array.isArray(tabs));
        assert.ok(tabs.length > 0);
      });
    });
  }

  // Cross-cutting error pairs
  describe("Cross-cutting Error Pairs", () => {
    it("[Chromium x Callback x runtime.sendMessage x Error -> lastError populated]", (t, done) => {
      const mockApi = createMockChromiumApi();
      mockApi.runtime.sendMessage = (msg, cb) => {
        mockApi.runtime.lastError = { message: "Port closed" };
        cb(undefined);
      };
      const ctx = createSandbox({ userAgent: "Chrome/128.0", chrome: mockApi });

      ctx.chrome.runtime.sendMessage({ fail: true }, (res) => {
        assert.equal(res, undefined);
        assert.ok(ctx.chrome.runtime.lastError);
        assert.equal(ctx.chrome.runtime.lastError.message, "Port closed");
        done();
      });
    });

    it("[Chromium x Promise x runtime.sendMessage x Error -> Promise rejects]", async () => {
      const mockApi = createMockChromiumApi();
      mockApi.runtime.sendMessage = (msg, cb) => {
        mockApi.runtime.lastError = { message: "Port closed" };
        cb(undefined);
      };
      const ctx = createSandbox({ userAgent: "Chrome/128.0", chrome: mockApi });

      await assert.rejects(async () => {
        await ctx.chrome.runtime.sendMessage({ fail: true });
      }, /Port closed/);
    });

    it("[Firefox x Callback x tabs.query x Error -> converted to lastError]", (t, done) => {
      const mockApi = createMockFirefoxApi();
      mockApi.tabs.query = () => Promise.reject(new Error("Tab query permission denied"));
      const ctx = createSandbox({ userAgent: "Firefox/128.0", browser: mockApi });

      ctx.chrome.tabs.query({}, (tabs) => {
        assert.equal(tabs, undefined);
        assert.ok(ctx.chrome.runtime.lastError);
        assert.equal(ctx.chrome.runtime.lastError.message, "Tab query permission denied");
        done();
      });
    });

    it("[Safari x Fallback x storage.session x Callback & Promise duality]", async () => {
      const localStore = {};
      const mockSafari = {
        runtime: { id: "safari-pw" },
        storage: {
          local: {
            get: (k, cb) => cb(localStore),
            set: (it, cb) => { Object.assign(localStore, it); if (cb) cb(); },
            remove: (k, cb) => { if (cb) cb(); },
            clear: (cb) => { if (cb) cb(); }
          }
          // session and managed undefined
        }
      };
      const ctx = createSandbox({
        userAgent: "Version/17.0 Safari/605.1.15",
        chrome: mockSafari,
        browser: mockSafari
      });

      // Callback set
      await new Promise((resolve) => {
        ctx.chrome.storage.session.set({ sKey: "sVal" }, resolve);
      });

      // Promise get
      const res = await ctx.browser.storage.session.get("sKey");
      assert.equal(res.sKey, "sVal");
    });
  });
});

// ===========================================================================
// TIER 4: REAL-WORLD APPLICATION SIMULATIONS
// ===========================================================================

describe("Tier 4: Real-World Workload Simulations", () => {

  it("Scenario 1: Simulated Firefox Event Page Lifecycle", async () => {
    // Firefox event page runs in a background document where browser.* is standard,
    // chrome.* is partial callback, and scripts run in ordered sequence.
    const mockFirefox = createMockFirefoxApi({
      whitelistedDomains: ["mozilla.org", "internal.corp"],
      shields: { pii: true, url: true }
    });
    let listenerRegistered = false;
    let contextMenuCreated = false;

    mockFirefox.runtime.onMessage = {
      addListener: (fn) => { listenerRegistered = true; }
    };
    mockFirefox.menus.create = (opts) => { contextMenuCreated = true; };

    const ctx = createSandbox({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
      browser: mockFirefox,
      chrome: undefined // Native Firefox starts without chrome shim or partial
    });

    // 1. Verify chrome is created and unified
    assert.ok(ctx.chrome, "chrome namespace unified in Firefox event page");
    assert.equal(ctx.chrome.runtime.id, "osn-guard-firefox-uuid");

    // 2. Extension registers message listener using chrome.runtime.onMessage
    ctx.chrome.runtime.onMessage.addListener(() => {});
    assert.equal(listenerRegistered, true);

    // 3. Extension clears and creates context menus
    await ctx.chrome.contextMenus.removeAll();
    ctx.chrome.contextMenus.create({ id: "scan_selection", title: "Scan Selection" });
    assert.equal(contextMenuCreated, true);

    // 4. Extension checks storage with callback (background.js pattern)
    const storageData = await new Promise((resolve) => {
      ctx.chrome.storage.local.get(["whitelistedDomains", "shields"], resolve);
    });
    assert.deepEqual(storageData.whitelistedDomains, ["mozilla.org", "internal.corp"]);
    assert.equal(storageData.shields.pii, true);

    // 5. Review link resolver detects Firefox
    const reviewUrl = ctx.OSNCompat.getStoreReviewUrl();
    assert.equal(reviewUrl, "https://addons.mozilla.org/firefox/addon/osn-guard/");
  });

  it("Scenario 2: Simulated Safari WebExtension Environment", async () => {
    // Safari 15.4+ WebExtension: chrome and browser both present,
    // storage.session and storage.managed are missing, action is present.
    const localStore = {};
    const mockSafari = {
      runtime: {
        id: "com.apple.safari.osn-guard",
        getURL: (p) => "safari-web-extension://uuid/" + p,
        sendMessage: (m, cb) => setTimeout(() => cb({ safariAck: true }), 0)
      },
      storage: {
        local: {
          get: (k, cb) => cb(localStore),
          set: (it, cb) => { Object.assign(localStore, it); if (cb) cb(); },
          remove: (k, cb) => { if (cb) cb(); },
          clear: (cb) => { if (cb) cb(); }
        }
        // session and managed absent
      },
      action: {
        setBadgeText: (d) => {},
        setBadgeBackgroundColor: (d) => {}
      }
    };

    const ctx = createSandbox({
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
      chrome: mockSafari,
      browser: { ...mockSafari }
    });

    // 1. Session storage fallback works smoothly
    assert.ok(ctx.chrome.storage.session, "session storage fallback attached");
    await ctx.chrome.storage.session.set({ tab_88: { threatCount: 2, timestamp: Date.now() } });
    const sessionRecord = await ctx.browser.storage.session.get("tab_88");
    assert.equal(sessionRecord.tab_88.threatCount, 2);

    // 2. Managed policy request degrades safely without error
    const managedPolicy = await ctx.chrome.storage.managed.get("enforcedShields");
    assert.ok(managedPolicy);
    assert.deepEqual(Object.keys(managedPolicy), []);

    // 3. Review store points to Apple App Store
    const reviewUrl = ctx.OSNCompat.getStoreReviewUrl();
    assert.equal(reviewUrl, "https://apps.apple.com/app/osn-guard");

    // 4. Internal URL recognizes Safari schemes
    assert.equal(ctx.OSNCompat.isInternalUrl("safari-web-extension://uuid/options.html"), true);
    assert.equal(ctx.OSNCompat.isInternalUrl("safari://startpage"), true);
    assert.equal(ctx.OSNCompat.isInternalUrl("applewebdata://uuid/index.html"), true);
  });

  it("Scenario 3: Simulated Chrome MV3 Service Worker Environment", async () => {
    // Chromium MV3 Service Worker: chrome native with callbacks,
    // browser initially undefined, storage.session and managed native.
    const mockChrome = createMockChromiumApi({
      installedAt: Date.now() - 300000,
      shields: { pii: true, url: true, content: true, security: true }
    });

    const ctx = createSandbox({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
      chrome: mockChrome,
      browser: undefined
    });

    // 1. browser namespace created and mirrors chrome
    assert.ok(ctx.browser);
    assert.equal(ctx.browser.runtime.id, "osn-guard-chrome-mv3");

    // 2. Modern async/await works on both namespaces
    const settings = await ctx.browser.storage.local.get(["installedAt", "shields"]);
    assert.equal(settings.shields.pii, true);

    // 3. Native session storage wrapped and functional
    await ctx.browser.storage.session.set({ activeTabScan: 1 });
    const sess = await ctx.chrome.storage.session.get("activeTabScan");
    assert.equal(sess.activeTabScan, 1);

    // 4. Review URL points to Chrome Web Store with ID
    const reviewUrl = ctx.OSNCompat.getStoreReviewUrl();
    assert.ok(reviewUrl.includes("chromewebstore.google.com"));
    assert.ok(reviewUrl.includes("osn-guard-chrome-mv3"));
  });

  it("Scenario 4: Dynamic Tab Scanning & Rescan IPC Notification", async () => {
    // Emulate content script scanning a link, reporting to background,
    // background writing to session storage and notifying tab.
    const mockChrome = createMockChromiumApi();
    let sentMessage = null;
    mockChrome.tabs.sendMessage = (tabId, msg, cb) => {
      sentMessage = { tabId, msg };
      if (cb) cb({ received: true });
    };

    const ctx = createSandbox({ chrome: mockChrome });

    // Step 1: Content script sends scan link message
    const response = await ctx.chrome.runtime.sendMessage({
      action: "scanLink",
      url: "https://suspicious.phishing.test/login"
    });
    assert.ok(response);

    // Step 2: Background coordinator records findings in session storage
    await ctx.chrome.storage.session.set({
      tab_101: {
        url: "https://suspicious.phishing.test/login",
        threatScore: 85,
        risk: "critical"
      }
    });

    // Step 3: Background queries active tabs and triggers rescan
    const activeTabs = await ctx.chrome.tabs.query({ active: true });
    assert.equal(activeTabs.length, 1);

    await new Promise((resolve) => {
      ctx.chrome.tabs.sendMessage(activeTabs[0].id, { action: "triggerRescan" }, resolve);
    });

    assert.ok(sentMessage);
    assert.equal(sentMessage.tabId, 101);
    assert.equal(sentMessage.msg.action, "triggerRescan");
  });

  it("Scenario 5: Enterprise Managed Policy Fallback Degradation", async () => {
    // Options & Popup load managed settings. If storage.managed is missing,
    // options UI safely receives {} without throwing and applies default user settings.
    const localStore = {
      whitelistedDomains: ["user-added.com"],
      shields: { pii: true, url: true, content: true, security: true }
    };

    const mockUnmanaged = {
      runtime: { id: "unmanaged-env" },
      storage: {
        local: {
          get: (k, cb) => cb(localStore),
          set: (it, cb) => { Object.assign(localStore, it); if (cb) cb(); }
        }
        // storage.managed is missing
      }
    };

    const ctx = createSandbox({ chrome: mockUnmanaged });

    // Simulate options.js getManagedPolicy()
    async function getEffectivePolicy() {
      let managedData = {};
      try {
        managedData = await ctx.chrome.storage.managed.get([
          "forcedWhitelistedDomains",
          "mandatoryCustomPiiRules",
          "enforcedShields"
        ]);
      } catch (err) {
        // Should not happen because compat shim provides safe fallback
        managedData = {};
      }

      const localData = await new Promise((resolve) => {
        ctx.chrome.storage.local.get(["whitelistedDomains", "shields"], resolve);
      });

      const effectiveWhitelist = [
        ...(localData.whitelistedDomains || []),
        ...(managedData.forcedWhitelistedDomains || [])
      ];

      return {
        isManaged: Boolean(managedData && Object.keys(managedData).length > 0),
        effectiveWhitelist,
        shields: localData.shields
      };
    }

    const policy = await getEffectivePolicy();
    assert.equal(policy.isManaged, false);
    assert.deepEqual(policy.effectiveWhitelist, ["user-added.com"]);
    assert.equal(policy.shields.pii, true);
  });
});

// ===========================================================================
// TIER 5: ROUND 2 HARDENING & ADVERSARIAL EDGE-CASE VERIFICATIONS
// ===========================================================================

describe("Tier 5: Round 2 Hardening & Adversarial Edge-Case Verifications", () => {

  // -------------------------------------------------------------------------
  // Test 1: storage.session.get() with 0 arguments (Promise style)
  // -------------------------------------------------------------------------
  describe("5.1 storage.session.get() with 0 Arguments (Promise style)", () => {
    it("storage.session.get() with 0 arguments returns all session items via Promise (local-backed fallback)", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ alpha: "val1", beta: "val2" });
      await ctx.chrome.storage.local.set({ persistentKey: "shouldNotAppearInSession" });

      // 0 arguments invocation
      const result = await ctx.chrome.storage.session.get();
      assert.ok(result, "Result must be defined");
      assert.equal(result.alpha, "val1");
      assert.equal(result.beta, "val2");
      assert.equal(result.persistentKey, undefined, "Persistent local keys must not leak into session get()");
    });

    it("storage.session.get() with 0 arguments returns all session items via Promise (in-memory fallback)", async () => {
      const mockChrome = { runtime: { id: "in-mem-test" }, storage: {} }; // no storage.local
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ memA: 100, memB: 200 });
      const result = await ctx.chrome.storage.session.get();
      assert.deepEqual({ ...result }, { memA: 100, memB: 200 });
    });
  });

  // -------------------------------------------------------------------------
  // Test 2: storage.session.get(cb) with 1 argument (callback only)
  // -------------------------------------------------------------------------
  describe("5.2 storage.session.get(cb) with 1 Argument (Callback style)", () => {
    it("storage.session.get(cb) with 1 argument invokes callback with all session items (local-backed fallback)", async () => {
      const mockChrome = {
        runtime: { id: "test-runtime" },
        storage: { local: createMockChromiumApi().storage.local }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ token: "abc-123", expiry: 99999 });

      await new Promise((resolve, reject) => {
        ctx.chrome.storage.session.get((items) => {
          try {
            assert.equal(ctx.chrome.runtime.lastError, undefined, "lastError must be undefined");
            assert.ok(items, "items object must be passed to callback");
            assert.equal(items.token, "abc-123");
            assert.equal(items.expiry, 99999);
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      });
    });

    it("storage.session.get(cb) with 1 argument invokes callback with all session items (in-memory fallback)", async () => {
      const mockChrome = {
        runtime: { id: "test-runtime" },
        storage: {}
      };
      const ctx = createSandbox({ chrome: mockChrome });

      await ctx.chrome.storage.session.set({ ephemeralId: 42 });

      await new Promise((resolve, reject) => {
        ctx.chrome.storage.session.get((items) => {
          try {
            assert.equal(ctx.chrome.runtime.lastError, undefined);
            assert.deepEqual({ ...items }, { ephemeralId: 42 });
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      });
    });
  });

  // -------------------------------------------------------------------------
  // Test 3: storage.managed.get() with 0 arguments & get(cb) with 1 argument
  // -------------------------------------------------------------------------
  describe("5.3 storage.managed.get() 0-Arg and 1-Arg Normalization", () => {
    it("storage.managed.get() with 0 arguments resolves to empty object via Promise", async () => {
      const mockChrome = { storage: { local: createMockChromiumApi().storage.local } };
      const ctx = createSandbox({ chrome: mockChrome });

      const result = await ctx.chrome.storage.managed.get();
      assert.ok(result, "Result must be defined");
      assert.deepEqual(Object.keys(result), [], "Result must be empty object");
    });

    it("storage.managed.get(cb) with 1 argument invokes callback with empty object", async () => {
      const mockChrome = {
        runtime: { id: "test-runtime" },
        storage: { local: createMockChromiumApi().storage.local }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      await new Promise((resolve, reject) => {
        ctx.chrome.storage.managed.get((items) => {
          try {
            assert.equal(ctx.chrome.runtime.lastError, undefined, "lastError must be undefined");
            assert.ok(items, "Items must be defined");
            assert.deepEqual(Object.keys(items), [], "Items must be empty object");
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      });
    });
  });

  // -------------------------------------------------------------------------
  // Test 4: Sequential Promise calls verifying no stale lastError poisoning
  // -------------------------------------------------------------------------
  describe("5.4 Sequential Promise Calls lastError Isolation", () => {
    it("sequential Promise calls verify no stale lastError cross-call poisoning", async () => {
      let ctx;
      const mockChrome = {
        runtime: { id: "test-id" },
        storage: {
          local: {
            get: (key, cb) => {
              if (key === "failingKey") {
                ctx.OSNCompat.setLastError("Underlying simulated quota error");
                cb(undefined);
              } else {
                cb({ [key]: "healthyValue" });
              }
            }
          }
        }
      };
      ctx = createSandbox({ chrome: mockChrome });

      // Call 1: Intentionally triggers an error in Promise mode
      let call1Rejected = false;
      try {
        await ctx.chrome.storage.local.get("failingKey");
      } catch (err) {
        call1Rejected = true;
        assert.match(err.message, /quota error/i);
      }
      assert.ok(call1Rejected, "Call 1 must reject with simulated error");

      // Call 2: Completely healthy call in Promise mode immediately after Call 1
      // Must NOT be poisoned by Call 1's uncleared lastError
      const call2Result = await ctx.chrome.storage.local.get("healthyKey");
      assert.ok(call2Result, "Call 2 must resolve successfully");
      assert.equal(call2Result.healthyKey, "healthyValue");

      // Verify module state and runtime.lastError are completely cleared
      assert.equal(ctx.chrome.runtime.lastError, undefined, "chrome.runtime.lastError must be undefined");
      assert.equal(ctx.OSNCompat.getLastError(), null, "OSNCompat.getLastError() must be null");
    });
  });

  // -------------------------------------------------------------------------
  // Test 5: API calls passing null as callback (api(arg, null) and trailing null/undefined)
  // -------------------------------------------------------------------------
  describe("5.5 Trailing Null/Undefined Callback Argument Trimming", () => {
    it("API calls passing null as callback (api(arg, null)) return Promise and resolve cleanly", async () => {
      const mockChrome = {
        storage: {
          local: {
            get: (key, cb) => {
              if (typeof cb !== "function") {
                throw new TypeError("cb is not a function: received " + typeof cb);
              }
              cb({ [key]: "dataForNullCallback" });
            }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      // Pass null explicitly as the callback argument
      const promise = ctx.chrome.storage.local.get("targetKey", null);
      assert.ok(promise && typeof promise.then === "function", "Must return a Promise");
      const result = await promise;
      assert.deepEqual(result, { targetKey: "dataForNullCallback" });
    });

    it("API calls passing multiple trailing null and undefined arguments trim properly", async () => {
      const mockChrome = {
        storage: {
          local: {
            get: (key, cb) => {
              if (typeof cb !== "function") {
                throw new TypeError("cb is not a function");
              }
              cb({ [key]: "trimmedResult" });
            }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      const result = await ctx.chrome.storage.local.get("k", null, undefined);
      assert.deepEqual(result, { k: "trimmedResult" });
    });
  });

  // -------------------------------------------------------------------------
  // Test 6: storage.session.clear(null)
  // -------------------------------------------------------------------------
  describe("5.6 storage.session.clear(null) Hang Prevention", () => {
    it("storage.session.clear(null) resolves cleanly via Promise without throwing or hanging", async () => {
      const mockLocalStore = {
        whitelistedDomains: ["safe-domain.org"],
        "__osn_session_:activeScan": { id: 101 }
      };
      const mockChrome = {
        storage: {
          local: {
            get: (keys, cb) => {
              if (keys === null) {
                cb({ ...mockLocalStore });
              } else {
                cb({});
              }
            },
            remove: (keys, cb) => {
              const list = Array.isArray(keys) ? keys : [keys];
              list.forEach((k) => delete mockLocalStore[k]);
              if (cb) cb();
            }
          }
        }
      };
      const ctx = createSandbox({ chrome: mockChrome });

      // Call clear(null)
      const clearPromise = ctx.chrome.storage.session.clear(null);
      assert.ok(clearPromise && typeof clearPromise.then === "function", "Must return a Promise");

      // Guard against indefinite Promise hang with timeout race
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("storage.session.clear(null) timed out / hung")), 1000)
      );

      await Promise.race([clearPromise, timeoutPromise]);

      // Session keys must be cleared, user settings must be preserved
      assert.equal(mockLocalStore["__osn_session_:activeScan"], undefined, "Session key must be removed");
      assert.deepEqual(mockLocalStore.whitelistedDomains, ["safe-domain.org"], "User keys must remain intact");
    });
  });

  // -------------------------------------------------------------------------
  // Test 7: Prototype pollution targeting __osnWrapped
  // -------------------------------------------------------------------------
  describe("5.7 Prototype Pollution Hardening on __osnWrapped", () => {
    it("prototype pollution targeting Object.prototype.__osnWrapped does not disable API wrapping", async () => {
      const mockStorage = {
        local: {
          get: (k, cb) => {
            if (typeof cb === "function") {
              cb({ [k]: "unpollutedResult" });
            }
          }
        }
      };

      const sandbox = {
        console,
        setTimeout,
        clearTimeout,
        Promise,
        Error,
        TypeError,
        Array,
        Object,
        String,
        Boolean,
        Number,
        Function,
        encodeURIComponent,
        decodeURIComponent,
        navigator: { userAgent: "Mozilla/5.0 Chrome/128.0" },
        chrome: {
          runtime: { id: "pollution-defense-test" },
          storage: mockStorage
        }
      };
      sandbox.globalThis = sandbox;
      sandbox.self = sandbox;
      sandbox.window = sandbox;

      // Simulate adversarial prototype pollution prior to shim execution
      sandbox.Object.prototype.__osnWrapped = true;

      try {
        const ctx = vm.createContext(sandbox);
        vm.runInContext(compatSource, ctx);

        // Verify storage.local.get was wrapped despite Object.prototype.__osnWrapped
        assert.ok(
          Object.prototype.hasOwnProperty.call(ctx.chrome.storage.local.get, "__osnWrapped"),
          "get method must own property __osnWrapped"
        );

        // Verify Promise-style call succeeds and returns data
        const promise = ctx.chrome.storage.local.get("sampleKey");
        assert.ok(promise && typeof promise.then === "function", "Must return a Promise");
        const res = await promise;
        assert.deepEqual(res, { sampleKey: "unpollutedResult" });

        // Verify idempotency: re-running init does not re-wrap or break wrapping
        const firstWrapped = ctx.chrome.storage.local.get;
        ctx.OSNCompat.init(ctx);
        assert.equal(ctx.chrome.storage.local.get, firstWrapped, "Re-init must preserve existing wrapper");
      } finally {
        delete sandbox.Object.prototype.__osnWrapped;
      }
    });

    it("prototype pollution targeting Function.prototype.__osnWrapped does not disable API wrapping", async () => {
      const mockStorage = {
        local: {
          get: (k, cb) => {
            if (typeof cb === "function") {
              cb({ [k]: "fnProtoResult" });
            }
          }
        }
      };

      const sandbox = {
        console,
        setTimeout,
        clearTimeout,
        Promise,
        Error,
        TypeError,
        Array,
        Object,
        String,
        Boolean,
        Number,
        Function,
        encodeURIComponent,
        decodeURIComponent,
        navigator: { userAgent: "Mozilla/5.0 Chrome/128.0" },
        chrome: {
          runtime: { id: "fn-proto-pollution-test" },
          storage: mockStorage
        }
      };
      sandbox.globalThis = sandbox;
      sandbox.self = sandbox;
      sandbox.window = sandbox;

      // Pollute Function.prototype
      sandbox.Function.prototype.__osnWrapped = true;

      try {
        const ctx = vm.createContext(sandbox);
        vm.runInContext(compatSource, ctx);

        const promise = ctx.chrome.storage.local.get("fnKey");
        assert.ok(promise && typeof promise.then === "function", "Must return a Promise");
        const res = await promise;
        assert.deepEqual(res, { fnKey: "fnProtoResult" });
      } finally {
        delete sandbox.Function.prototype.__osnWrapped;
      }
    });
  });

});

