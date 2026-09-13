/**
 * OSN Guard - Cross-Browser Namespace & API Compatibility Shim
 * 
 * Provides zero-dependency bidirectional unification between Chromium (chrome.*)
 * and Firefox/Safari (browser.*) namespaces with dual Callback/Promise support,
 * storage session/managed fallbacks, UI normalization, and strict prototype
 * pollution defenses.
 * 
 * Target environments:
 * - Chromium MV3 Background Service Worker & Content Scripts
 * - Firefox Gecko Event Pages & Content Scripts
 * - Safari WebExtension Background & Content Scripts
 * - Extension Pages (popup/popup.html, options/options.html)
 * - Node.js Automated Test Suites (node --test)
 */

(function (root, factory) {
  const exports = factory(root);
  if (typeof module === "object" && module.exports) {
    module.exports = exports;
  }
  if (root) {
    root.OSNCompat = exports;
  }
})(
  typeof globalThis !== "undefined"
    ? globalThis
    : (typeof self !== "undefined"
        ? self
        : (typeof window !== "undefined" ? window : this)),
  function (targetGlobal) {
    "use strict";

    // ---------------------------------------------------------------------------
    // 1. Prototype Pollution Defenses & Utilities
    // ---------------------------------------------------------------------------

    const hasOwn = function (obj, key) {
      if (obj === null || obj === undefined) return false;
      return Object.prototype.hasOwnProperty.call(obj, key);
    };

    const isPollutionKey = function (key) {
      return key === "__proto__" || key === "constructor" || key === "prototype";
    };

    // ---------------------------------------------------------------------------
    // 2. Browser Environment Detection
    // ---------------------------------------------------------------------------

    function detectEngine() {
      const userAgent = (typeof navigator !== "undefined" && typeof navigator.userAgent === "string")
        ? navigator.userAgent
        : "";
      const firefox = userAgent.includes("Firefox");
      const safari = userAgent.includes("Safari") &&
        !userAgent.includes("Chrome") &&
        !userAgent.includes("Chromium") &&
        !userAgent.includes("Edg");
      const chromium = !firefox && !safari;
      return { isFirefox: firefox, isSafari: safari, isChromium: chromium };
    }

    // ---------------------------------------------------------------------------
    // 3. Browser-Aware URL & Store Resolvers
    // ---------------------------------------------------------------------------

    const INTERNAL_URL_PREFIXES = Object.freeze([
      "chrome://",
      "chrome-extension://",
      "chrome-search://",
      "moz-extension://",
      "about:",
      "safari-web-extension://",
      "safari://",
      "safari-resource://",
      "applewebdata://",
      "edge://",
      "opera://",
      "brave://",
      "devtools://",
      "view-source:"
    ]);

    function isInternalUrl(urlString) {
      if (typeof urlString !== "string" || !urlString) {
        return false;
      }
      const lower = urlString.trim().toLowerCase();
      for (let i = 0; i < INTERNAL_URL_PREFIXES.length; i++) {
        if (lower.startsWith(INTERNAL_URL_PREFIXES[i])) {
          return true;
        }
      }
      return false;
    }

    function getStoreReviewUrl(extensionId, targetOverride) {
      let target = targetOverride ? String(targetOverride).toLowerCase() : null;
      if (!target) {
        const engine = detectEngine();
        if (engine.isFirefox) target = "firefox";
        else if (engine.isSafari) target = "safari";
        else target = "chrome";
      }

      if (target === "firefox") {
        return "https://addons.mozilla.org/firefox/addon/osn-guard/";
      }
      if (target === "safari") {
        return "https://apps.apple.com/app/osn-guard";
      }
      const resolvedId = extensionId ||
        (targetGlobal.chrome && targetGlobal.chrome.runtime && targetGlobal.chrome.runtime.id) ||
        (targetGlobal.browser && targetGlobal.browser.runtime && targetGlobal.browser.runtime.id) ||
        "osn-guard";
      return "https://chromewebstore.google.com/detail/" + encodeURIComponent(resolvedId) + "/reviews";
    }

    // ---------------------------------------------------------------------------
    // 4. Runtime lastError Management
    // ---------------------------------------------------------------------------

    let currentLastError = null;

    function getLastError() {
      if (targetGlobal.chrome && targetGlobal.chrome.runtime && targetGlobal.chrome.runtime.lastError) {
        return targetGlobal.chrome.runtime.lastError;
      }
      if (targetGlobal.browser && targetGlobal.browser.runtime && targetGlobal.browser.runtime.lastError) {
        return targetGlobal.browser.runtime.lastError;
      }
      return currentLastError;
    }

    function setLastError(err) {
      const message = (err && typeof err.message === "string")
        ? err.message
        : (typeof err === "string" ? err : "Unknown extension error");

      const errObj = Object.create(null);
      errObj.message = message;
      Object.freeze(errObj);
      currentLastError = errObj;

      const runtimes = [];
      if (targetGlobal.chrome && targetGlobal.chrome.runtime) runtimes.push(targetGlobal.chrome.runtime);
      if (targetGlobal.browser && targetGlobal.browser.runtime && targetGlobal.browser.runtime !== targetGlobal.chrome?.runtime) {
        runtimes.push(targetGlobal.browser.runtime);
      }

      for (let i = 0; i < runtimes.length; i++) {
        const rt = runtimes[i];
        try {
          rt.lastError = errObj;
        } catch {
          try {
            Object.defineProperty(rt, "lastError", {
              value: errObj,
              configurable: true,
              writable: true,
              enumerable: true
            });
          } catch { /* ignore */ }
        }
      }
    }

    function clearLastError() {
      currentLastError = null;
      const runtimes = [];
      if (targetGlobal.chrome && targetGlobal.chrome.runtime) runtimes.push(targetGlobal.chrome.runtime);
      if (targetGlobal.browser && targetGlobal.browser.runtime && targetGlobal.browser.runtime !== targetGlobal.chrome?.runtime) {
        runtimes.push(targetGlobal.browser.runtime);
      }

      for (let i = 0; i < runtimes.length; i++) {
        const rt = runtimes[i];
        try {
          delete rt.lastError;
        } catch {
          try {
            rt.lastError = undefined;
          } catch { /* ignore */ }
        }
      }
    }

    // ---------------------------------------------------------------------------
    // 5. Dual Callback / Promise Bridge Invoker
    // ---------------------------------------------------------------------------

    function promisifyOrCallback(fn, context, args, callbackIndex) {
      const callArgs = Array.prototype.slice.call(args || []);
      let candidate = undefined;
      let cbIndex = -1;

      if (typeof callbackIndex === "number" && callbackIndex >= 0 && callbackIndex < callArgs.length) {
        candidate = callArgs[callbackIndex];
        cbIndex = callbackIndex;
      } else if (callArgs.length > 0 && typeof callArgs[callArgs.length - 1] === "function") {
        candidate = callArgs[callArgs.length - 1];
        cbIndex = callArgs.length - 1;
      }

      const hasCallback = typeof candidate === "function";

      if (hasCallback) {
        const userCallback = candidate;
        const argsWithoutCb = callArgs.slice();
        argsWithoutCb.splice(cbIndex, 1);

        let invoked = false;
        function invokeUserCallback(err, ...results) {
          if (invoked) return;
          invoked = true;
          if (err) {
            setLastError(err);
            try {
              userCallback.apply(context, results);
            } finally {
              clearLastError();
            }
          } else {
            clearLastError();
            userCallback.apply(context, results);
          }
        }

        const interceptCallback = function (...cbArgs) {
          const currentErr = getLastError();
          if (currentErr) {
            invokeUserCallback(currentErr, ...cbArgs);
          } else {
            invokeUserCallback(null, ...cbArgs);
          }
        };

        const invocationArgs = argsWithoutCb.concat([interceptCallback]);

        try {
          const result = fn.apply(context, invocationArgs);
          if (result && typeof result.then === "function") {
            result.then(
              function (val) {
                invokeUserCallback(null, val);
              },
              function (err) {
                invokeUserCallback(err, undefined);
              }
            );
          }
        } catch (syncErr) {
          invokeUserCallback(syncErr, undefined);
        }
        return undefined;
      }

      // No callback provided -> return native Promise
      return new Promise(function (resolve, reject) {
        let settled = false;

        function safeResolve(val) {
          if (settled) return;
          settled = true;
          resolve(val);
        }

        function safeReject(err) {
          if (settled) return;
          settled = true;
          reject(err instanceof Error ? err : new Error(err && err.message ? err.message : String(err)));
        }

        const interceptCallback = function (...cbArgs) {
          const currentErr = getLastError();
          if (currentErr) {
            clearLastError();
            safeReject(currentErr);
          } else {
            clearLastError();
            safeResolve(cbArgs.length <= 1 ? cbArgs[0] : cbArgs);
          }
        };

        // Trim trailing undefined and null values from callArgs before appending interceptCallback
        while (
          callArgs.length > 0 &&
          (callArgs[callArgs.length - 1] === undefined || callArgs[callArgs.length - 1] === null)
        ) {
          callArgs.pop();
        }

        const invocationArgs = callArgs.concat([interceptCallback]);

        try {
          const result = fn.apply(context, invocationArgs);
          if (result && typeof result.then === "function") {
            result.then(
              function (val) {
                safeResolve(val);
              },
              function (err) {
                safeReject(err);
              }
            );
          }
        } catch (syncErr) {
          safeReject(syncErr);
        }
      });
    }

    // ---------------------------------------------------------------------------
    // 6. Storage API Fallbacks (storage.session & storage.managed)
    // ---------------------------------------------------------------------------

    function createSessionStorageFallback(localStorage) {
      const PREFIX = "__osn_session_:";

      if (!localStorage) {
        const memStore = Object.create(null);
        const fallback = {
          get: function (keys, cb) {
            let queryKeys = keys;
            let callback = cb;
            if (typeof queryKeys === "function") {
              callback = queryKeys;
              queryKeys = null;
            } else if (queryKeys === undefined) {
              queryKeys = null;
            }
            const args = typeof callback === "function" ? [queryKeys, callback] : [queryKeys];
            return promisifyOrCallback(function (k, callbackFn) {
              let queryK = k;
              let cbFn = callbackFn;
              if (typeof queryK === "function" && cbFn === undefined) {
                cbFn = queryK;
                queryK = null;
              }
              const result = {};
              if (queryK === null || queryK === undefined) {
                const allKeys = Object.keys(memStore);
                for (let i = 0; i < allKeys.length; i++) {
                  const keyName = allKeys[i];
                  if (!isPollutionKey(keyName)) {
                    result[keyName] = memStore[keyName];
                  }
                }
              } else if (typeof queryK === "string") {
                if (!isPollutionKey(queryK) && hasOwn(memStore, queryK)) result[queryK] = memStore[queryK];
              } else if (Array.isArray(queryK)) {
                for (let i = 0; i < queryK.length; i++) {
                  const keyName = queryK[i];
                  if (!isPollutionKey(keyName) && hasOwn(memStore, keyName)) result[keyName] = memStore[keyName];
                }
              } else if (typeof queryK === "object") {
                const queryKeys = Object.keys(queryK);
                for (let i = 0; i < queryKeys.length; i++) {
                  const keyName = queryKeys[i];
                  if (!isPollutionKey(keyName)) {
                    result[keyName] = hasOwn(memStore, keyName) ? memStore[keyName] : queryK[keyName];
                  }
                }
              }
              cbFn(result);
            }, null, args);
          },
          set: function (items, cb) {
            const args = cb !== undefined ? [items, cb] : [items];
            return promisifyOrCallback(function (it, callback) {
              if (it && typeof it === "object") {
                const keys = Object.keys(it);
                for (let i = 0; i < keys.length; i++) {
                  const k = keys[i];
                  if (isPollutionKey(k)) continue;
                  if (hasOwn(it, k)) memStore[k] = it[k];
                }
              }
              callback();
            }, null, args);
          },
          remove: function (keys, cb) {
            const args = cb !== undefined ? [keys, cb] : [keys];
            return promisifyOrCallback(function (k, callback) {
              const toRemove = Array.isArray(k) ? k : [k];
              for (let i = 0; i < toRemove.length; i++) {
                delete memStore[toRemove[i]];
              }
              callback();
            }, null, args);
          },
          clear: function (cb) {
            const args = typeof cb === "function" ? [cb] : [];
            return promisifyOrCallback(function (callback) {
              const keys = Object.keys(memStore);
              for (let i = 0; i < keys.length; i++) {
                delete memStore[keys[i]];
              }
              callback();
            }, null, args);
          }
        };
        fallback.get.__osnWrapped = true;
        fallback.set.__osnWrapped = true;
        fallback.remove.__osnWrapped = true;
        fallback.clear.__osnWrapped = true;
        return fallback;
      }

      const fallback = {
        get: function (keys, cb) {
          let queryKeys = keys;
          let callback = cb;
          if (typeof queryKeys === "function") {
            callback = queryKeys;
            queryKeys = null;
          } else if (queryKeys === undefined) {
            queryKeys = null;
          }
          const args = typeof callback === "function" ? [queryKeys, callback] : [queryKeys];
          return promisifyOrCallback(function (k, callbackFn) {
            let queryK = k;
            let cbFn = callbackFn;
            if (typeof queryK === "function" && cbFn === undefined) {
              cbFn = queryK;
              queryK = null;
            }
            if (queryK === null || queryK === undefined) {
              localStorage.get(null, function (allItems) {
                const currentErr = getLastError();
                if (currentErr) {
                  cbFn(undefined);
                  return;
                }
                const result = {};
                if (allItems) {
                  const itemKeys = Object.keys(allItems);
                  for (let i = 0; i < itemKeys.length; i++) {
                    const ik = itemKeys[i];
                    if (ik.startsWith(PREFIX)) {
                      const realKey = ik.slice(PREFIX.length);
                      if (!isPollutionKey(realKey)) {
                        result[realKey] = allItems[ik];
                      }
                    }
                  }
                }
                cbFn(result);
              });
            } else if (typeof queryK === "string") {
              const prefixedKey = PREFIX + queryK;
              localStorage.get([prefixedKey], function (items) {
                const currentErr = getLastError();
                if (currentErr) {
                  cbFn(undefined);
                  return;
                }
                const result = {};
                if (!isPollutionKey(queryK) && items && hasOwn(items, prefixedKey)) {
                  result[queryK] = items[prefixedKey];
                }
                cbFn(result);
              });
            } else if (Array.isArray(queryK)) {
              const prefixedQuery = queryK.map(function (keyName) { return PREFIX + keyName; });
              localStorage.get(prefixedQuery, function (items) {
                const currentErr = getLastError();
                if (currentErr) {
                  cbFn(undefined);
                  return;
                }
                const result = {};
                if (items) {
                  for (let i = 0; i < queryK.length; i++) {
                    const originalKey = queryK[i];
                    if (isPollutionKey(originalKey)) continue;
                    const pKey = PREFIX + originalKey;
                    if (hasOwn(items, pKey)) {
                      result[originalKey] = items[pKey];
                    }
                  }
                }
                cbFn(result);
              });
            } else if (typeof queryK === "object") {
              const queryKeys = Object.keys(queryK);
              const prefixedQuery = queryKeys.map(function (keyName) { return PREFIX + keyName; });
              localStorage.get(prefixedQuery, function (items) {
                const currentErr = getLastError();
                if (currentErr) {
                  cbFn(undefined);
                  return;
                }
                const result = {};
                for (let i = 0; i < queryKeys.length; i++) {
                  const originalKey = queryKeys[i];
                  if (isPollutionKey(originalKey)) continue;
                  const pKey = PREFIX + originalKey;
                  result[originalKey] = (items && hasOwn(items, pKey)) ? items[pKey] : queryK[originalKey];
                }
                cbFn(result);
              });
            } else {
              cbFn({});
            }
          }, null, args);
        },

        set: function (items, cb) {
          const args = cb !== undefined ? [items, cb] : [items];
          return promisifyOrCallback(function (it, callback) {
            if (!it || typeof it !== "object") {
              callback();
              return;
            }
            const keys = Object.keys(it);
            const prefixedItems = {};
            for (let i = 0; i < keys.length; i++) {
              const k = keys[i];
              if (isPollutionKey(k)) continue;
              if (hasOwn(it, k)) {
                prefixedItems[PREFIX + k] = it[k];
              }
            }
            localStorage.set(prefixedItems, function () {
              callback();
            });
          }, null, args);
        },

        remove: function (keys, cb) {
          const args = cb !== undefined ? [keys, cb] : [keys];
          return promisifyOrCallback(function (k, callback) {
            const keyList = Array.isArray(k) ? k : [k];
            const prefixedKeys = keyList.map(function (keyName) { return PREFIX + keyName; });
            localStorage.remove(prefixedKeys, function () {
              callback();
            });
          }, null, args);
        },

        clear: function (cb) {
          const args = typeof cb === "function" ? [cb] : [];
          return promisifyOrCallback(function (callback) {
            localStorage.get(null, function (allItems) {
              const currentErr = getLastError();
              if (currentErr) {
                callback();
                return;
              }
              const keysToRemove = [];
              if (allItems) {
                const itemKeys = Object.keys(allItems);
                for (let i = 0; i < itemKeys.length; i++) {
                  const ik = itemKeys[i];
                  if (ik.startsWith(PREFIX)) {
                    keysToRemove.push(ik);
                  }
                }
              }
              if (keysToRemove.length > 0) {
                localStorage.remove(keysToRemove, function () {
                  callback();
                });
              } else {
                callback();
              }
            });
          }, null, args);
        }
      };
      fallback.get.__osnWrapped = true;
      fallback.set.__osnWrapped = true;
      fallback.remove.__osnWrapped = true;
      fallback.clear.__osnWrapped = true;
      return fallback;
    }

    function createManagedStorageFallback() {
      const fallback = {
        get: function (keys, cb) {
          let queryKeys = keys;
          let callback = cb;
          if (typeof queryKeys === "function") {
            callback = queryKeys;
            queryKeys = null;
          } else if (queryKeys === undefined) {
            queryKeys = null;
          }
          const args = typeof callback === "function" ? [queryKeys, callback] : [queryKeys];
          return promisifyOrCallback(function (k, callbackFn) {
            const cb = typeof k === "function" && callbackFn === undefined ? k : callbackFn;
            const result = {};
            cb(result);
          }, null, args);
        },
        set: function (items, cb) {
          const args = cb !== undefined ? [items, cb] : [items];
          return promisifyOrCallback(function (it, callback) {
            throw new Error("storage.managed is read-only");
          }, null, args);
        },
        remove: function (keys, cb) {
          const args = cb !== undefined ? [keys, cb] : [keys];
          return promisifyOrCallback(function (k, callback) {
            throw new Error("storage.managed is read-only");
          }, null, args);
        },
        clear: function (cb) {
          const args = typeof cb === "function" ? [cb] : [];
          return promisifyOrCallback(function (callback) {
            throw new Error("storage.managed is read-only");
          }, null, args);
        }
      };
      fallback.get.__osnWrapped = true;
      fallback.set.__osnWrapped = true;
      fallback.remove.__osnWrapped = true;
      fallback.clear.__osnWrapped = true;
      return fallback;
    }

    // ---------------------------------------------------------------------------
    // 7. Method Wrapping & Namespace Augmentation Helper
    // ---------------------------------------------------------------------------

    function wrapMethod(targetObj, methodName) {
      if (!targetObj || typeof targetObj[methodName] !== "function") return;
      const original = targetObj[methodName];
      if (hasOwn(original, "__osnWrapped")) return;

      const wrapped = function (...args) {
        return promisifyOrCallback(original, targetObj, args);
      };
      wrapped.__osnWrapped = true;
      targetObj[methodName] = wrapped;
    }

    function normalizeAction(chromeNs, browserNs) {
      const action = (chromeNs && chromeNs.action) ||
        (browserNs && browserNs.action) ||
        (chromeNs && chromeNs.browserAction) ||
        (browserNs && browserNs.browserAction) ||
        null;

      if (action) {
        if (chromeNs) {
          if (!chromeNs.action) chromeNs.action = action;
          if (!chromeNs.browserAction) chromeNs.browserAction = action;
        }
        if (browserNs) {
          if (!browserNs.action) browserNs.action = action;
          if (!browserNs.browserAction) browserNs.browserAction = action;
        }
      }
    }

    function normalizeMenus(chromeNs, browserNs) {
      const menus = (chromeNs && chromeNs.contextMenus) ||
        (browserNs && browserNs.contextMenus) ||
        (browserNs && browserNs.menus) ||
        (chromeNs && chromeNs.menus) ||
        null;

      if (menus) {
        if (chromeNs) {
          if (!chromeNs.contextMenus) chromeNs.contextMenus = menus;
          if (!chromeNs.menus) chromeNs.menus = menus;
        }
        if (browserNs) {
          if (!browserNs.contextMenus) browserNs.contextMenus = menus;
          if (!browserNs.menus) browserNs.menus = menus;
        }
      }
    }

    // ---------------------------------------------------------------------------
    // 8. Bidirectional Namespace Synchronization
    // ---------------------------------------------------------------------------

    function init(globalScope) {
      const g = globalScope || targetGlobal;

      // Unify roots
      if (!g.chrome && !g.browser) {
        g.chrome = Object.create(null);
        g.browser = g.chrome;
      } else if (g.chrome && !g.browser) {
        g.browser = g.chrome;
      } else if (!g.chrome && g.browser) {
        g.chrome = g.browser;
      }

      const chromeNs = g.chrome;
      const browserNs = g.browser;

      // Synchronize sub-namespaces
      const subNamespaces = ["runtime", "storage", "tabs", "action", "contextMenus", "menus", "browserAction"];
      for (let i = 0; i < subNamespaces.length; i++) {
        const name = subNamespaces[i];
        if (isPollutionKey(name)) continue;

        if (!chromeNs[name] && browserNs[name]) {
          chromeNs[name] = browserNs[name];
        } else if (chromeNs[name] && !browserNs[name]) {
          browserNs[name] = chromeNs[name];
        }
      }

      // Synchronize runtime properties
      if (chromeNs.runtime && browserNs.runtime) {
        if (!chromeNs.runtime.id && browserNs.runtime.id) {
          chromeNs.runtime.id = browserNs.runtime.id;
        } else if (chromeNs.runtime.id && !browserNs.runtime.id) {
          browserNs.runtime.id = chromeNs.runtime.id;
        }
        if (!chromeNs.runtime.getURL && browserNs.runtime.getURL) {
          chromeNs.runtime.getURL = browserNs.runtime.getURL;
        } else if (chromeNs.runtime.getURL && !browserNs.runtime.getURL) {
          browserNs.runtime.getURL = chromeNs.runtime.getURL;
        }
        if (!chromeNs.runtime.openOptionsPage && browserNs.runtime.openOptionsPage) {
          chromeNs.runtime.openOptionsPage = browserNs.runtime.openOptionsPage;
        } else if (chromeNs.runtime.openOptionsPage && !browserNs.runtime.openOptionsPage) {
          browserNs.runtime.openOptionsPage = chromeNs.runtime.openOptionsPage;
        }
      }

      // Synchronize storage fallbacks
      const storages = [chromeNs.storage, browserNs.storage].filter(Boolean);
      for (let i = 0; i < storages.length; i++) {
        const st = storages[i];
        if (!st.session) {
          st.session = createSessionStorageFallback(st.local);
        }
        if (!st.managed) {
          st.managed = createManagedStorageFallback();
        }
      }

      // Normalization of action and menus
      normalizeAction(chromeNs, browserNs);
      normalizeMenus(chromeNs, browserNs);

      // Wrap asynchronous methods on both namespaces
      const namespacesToWrap = [chromeNs, browserNs];
      for (let n = 0; n < namespacesToWrap.length; n++) {
        const ns = namespacesToWrap[n];
        if (!ns) continue;

        if (ns.storage) {
          if (ns.storage.local) {
            wrapMethod(ns.storage.local, "get");
            wrapMethod(ns.storage.local, "set");
            wrapMethod(ns.storage.local, "remove");
            wrapMethod(ns.storage.local, "clear");
          }
          if (ns.storage.session) {
            wrapMethod(ns.storage.session, "get");
            wrapMethod(ns.storage.session, "set");
            wrapMethod(ns.storage.session, "remove");
            wrapMethod(ns.storage.session, "clear");
          }
          if (ns.storage.managed) {
            wrapMethod(ns.storage.managed, "get");
          }
        }

        if (ns.runtime) {
          wrapMethod(ns.runtime, "sendMessage");
        }

        if (ns.tabs) {
          wrapMethod(ns.tabs, "query");
          wrapMethod(ns.tabs, "create");
          wrapMethod(ns.tabs, "sendMessage");
        }

        if (ns.contextMenus) {
          wrapMethod(ns.contextMenus, "removeAll");
        }
        if (ns.menus) {
          wrapMethod(ns.menus, "removeAll");
        }
      }

      return { chrome: chromeNs, browser: browserNs };
    }

    // Auto-initialize on evaluation in current global scope
    init(targetGlobal);

    // ---------------------------------------------------------------------------
    // 9. Public OSNCompat API Export
    // ---------------------------------------------------------------------------

    const OSNCompat = Object.create(null);

    Object.defineProperty(OSNCompat, "isFirefox", {
      get: function () { return detectEngine().isFirefox; },
      enumerable: true
    });

    Object.defineProperty(OSNCompat, "isSafari", {
      get: function () { return detectEngine().isSafari; },
      enumerable: true
    });

    Object.defineProperty(OSNCompat, "isChromium", {
      get: function () { return detectEngine().isChromium; },
      enumerable: true
    });

    OSNCompat.isInternalUrl = isInternalUrl;
    OSNCompat.getStoreReviewUrl = getStoreReviewUrl;
    OSNCompat.promisifyOrCallback = promisifyOrCallback;
    OSNCompat.createSessionStorageFallback = createSessionStorageFallback;
    OSNCompat.createManagedStorageFallback = createManagedStorageFallback;
    OSNCompat.setLastError = setLastError;
    OSNCompat.clearLastError = clearLastError;
    OSNCompat.getLastError = getLastError;
    OSNCompat.init = init;

    return OSNCompat;
  }
);
