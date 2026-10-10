/**
 * Runs in the page MAIN world to observe fetch/XHR/WebSocket URLs
 * and post them to the content script.
 */
(function () {
  "use strict";
  if (window.__sfNetHookInstalled) return;
  window.__sfNetHookInstalled = true;

  const report = (url, kind) => {
    if (!url) return;
    try {
      window.postMessage(
        { source: "sf-subdomain-finder", kind: kind || "network", url: String(url) },
        "*"
      );
    } catch {
      /* ignore */
    }
  };

  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (...args) {
      try {
        const input = args[0];
        const url = typeof input === "string" ? input : input?.url;
        report(url, "fetch");
      } catch {
        /* ignore */
      }
      return origFetch.apply(this, args);
    };
  }

  const OrigXHR = window.XMLHttpRequest;
  if (OrigXHR) {
    const open = OrigXHR.prototype.open;
    OrigXHR.prototype.open = function (method, url, ...rest) {
      try {
        report(url, "xhr");
      } catch {
        /* ignore */
      }
      return open.call(this, method, url, ...rest);
    };
  }

  const OrigWS = window.WebSocket;
  if (OrigWS) {
    window.WebSocket = function (url, protocols) {
      report(url, "websocket");
      return protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
    };
    window.WebSocket.prototype = OrigWS.prototype;
    Object.assign(window.WebSocket, OrigWS);
  }

  if (window.PerformanceObserver) {
    try {
      const obs = new PerformanceObserver((list) => {
        list.getEntries().forEach((entry) => {
          if (entry.name) report(entry.name, "performance");
        });
      });
      obs.observe({ entryTypes: ["resource", "navigation"] });
    } catch {
      /* ignore */
    }
  }
})();
