/* global SF, importScripts */
importScripts("shared.js");

const {
  normalizeDomain,
  isSubdomainOf,
  isValidDomain,
  hostFromUrl,
  extractHostsFromText
} = SF;

// Open the side panel when the toolbar icon is clicked (instead of a popup).
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

/** @type {Map<number, { apex: string, deep: boolean }>} */
const monitoredTabs = new Map();

/** In-memory live findings keyed by apex */
const liveStore = {
  /** @type {Record<string, { subdomains: Set<string>, related: Set<string>, bySource: Record<string, Set<string>> }>} */
  byApex: {}
};

function ensureApexBucket(apex) {
  const key = normalizeDomain(apex);
  if (!liveStore.byApex[key]) {
    liveStore.byApex[key] = {
      subdomains: new Set(),
      related: new Set(),
      bySource: {
        network: new Set(),
        pagejs: new Set(),
        performance: new Set(),
        debugger: new Set()
      }
    };
  }
  return liveStore.byApex[key];
}

function addFinding(apex, host, source) {
  const bucket = ensureApexBucket(apex);
  const clean = normalizeDomain(host);
  if (!clean || !isValidDomain(clean)) return false;

  if (isSubdomainOf(clean, apex)) {
    bucket.subdomains.add(clean);
    if (!bucket.bySource[source]) bucket.bySource[source] = new Set();
    bucket.bySource[source].add(clean);
    return true;
  }

  bucket.related.add(clean);
  return true;
}

function snapshotApex(apex) {
  const bucket = ensureApexBucket(apex);
  const bySource = {};
  Object.entries(bucket.bySource).forEach(([k, set]) => {
    bySource[k] = Array.from(set).sort();
  });
  return {
    apex: normalizeDomain(apex),
    subdomains: Array.from(bucket.subdomains).sort(),
    related: Array.from(bucket.related).sort(),
    bySource,
    monitoredTabs: Array.from(monitoredTabs.entries())
      .filter(([, cfg]) => normalizeDomain(cfg.apex) === normalizeDomain(apex))
      .map(([tabId, cfg]) => ({ tabId, deep: cfg.deep }))
  };
}

function broadcastLiveUpdate(apex) {
  const payload = snapshotApex(apex);
  chrome.runtime.sendMessage({ type: "live-update", payload }).catch(() => {});
}

function recordUrl(url, tabId, source = "network") {
  if (!url || url.startsWith("chrome") || url.startsWith("devtools")) return;
  const cfg = tabId != null ? monitoredTabs.get(tabId) : null;
  const host = hostFromUrl(url);
  if (!host) return;

  if (cfg) {
    addFinding(cfg.apex, host, source);
    const { subdomains, related } = extractHostsFromText(url, {
      apex: cfg.apex,
      includeRelated: true
    });
    subdomains.forEach((h) => addFinding(cfg.apex, h, source));
    related.forEach((h) => addFinding(cfg.apex, h, source));
    broadcastLiveUpdate(cfg.apex);
    return;
  }

  monitoredTabs.forEach((tabCfg) => {
    if (isSubdomainOf(host, tabCfg.apex) || url.includes(tabCfg.apex)) {
      addFinding(tabCfg.apex, host, source);
      broadcastLiveUpdate(tabCfg.apex);
    }
  });
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!monitoredTabs.size) return;
    if (details.tabId >= 0 && monitoredTabs.has(details.tabId)) {
      recordUrl(details.url, details.tabId, "network");
    } else if (details.tabId === -1) {
      // Extension or service worker initiated — skip
    } else if (monitoredTabs.has(details.tabId)) {
      recordUrl(details.url, details.tabId, "network");
    } else {
      // Capture requests that mention a monitored apex even from other tabs when global watch is on
      monitoredTabs.forEach((cfg, tabId) => {
        if (details.url.includes(cfg.apex)) {
          recordUrl(details.url, tabId, "network");
        }
      });
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!monitoredTabs.size) return;
    if (details.tabId >= 0) {
      recordUrl(details.url, details.tabId, "network");
    }
  },
  { urls: ["<all_urls>"] }
);

async function attachDebugger(tabId) {
  try {
    await chrome.debugger.attach({ tabId }, "1.3");
    await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
    return true;
  } catch {
    return false;
  }
}

async function detachDebugger(tabId) {
  try {
    await chrome.debugger.detach({ tabId });
  } catch {
    /* ignore */
  }
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  const tabId = source.tabId;
  if (tabId == null || !monitoredTabs.has(tabId)) return;
  const cfg = monitoredTabs.get(tabId);

  if (method === "Network.requestWillBeSent" && params?.request?.url) {
    recordUrl(params.request.url, tabId, "debugger");
  }

  if (method === "Network.responseReceived" && params?.response?.url) {
    recordUrl(params.response.url, tabId, "debugger");
  }

  if (method === "Network.loadingFinished" && cfg.deep && params?.requestId) {
    chrome.debugger
      .sendCommand({ tabId }, "Network.getResponseBody", {
        requestId: params.requestId
      })
      .then((body) => {
        const text = body?.body || "";
        if (!text || text.length > 2_000_000) return;
        const { subdomains, related } = extractHostsFromText(text, {
          apex: cfg.apex,
          includeRelated: true
        });
        subdomains.forEach((h) => addFinding(cfg.apex, h, "debugger"));
        related.forEach((h) => addFinding(cfg.apex, h, "debugger"));
        broadcastLiveUpdate(cfg.apex);
      })
      .catch(() => {});
  }
});

chrome.debugger.onDetach.addListener((source) => {
  const tabId = source.tabId;
  if (tabId != null && monitoredTabs.has(tabId)) {
    const cfg = monitoredTabs.get(tabId);
    cfg.deep = false;
    monitoredTabs.set(tabId, cfg);
  }
});

async function injectCollector(tabId, apex) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["shared.js", "content.js"]
    });
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["injected.js"],
      world: "MAIN"
    });
    if (apex) {
      await chrome.tabs.sendMessage(tabId, { type: "set-apex", apex }).catch(() => {});
    }
    return true;
  } catch {
    return false;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handle = async () => {
    switch (message?.type) {
      case "start-monitor": {
        const tabId = message.tabId;
        const apex = normalizeDomain(message.apex);
        const deep = Boolean(message.deep);
        if (!tabId || !apex) return { ok: false, error: "tabId and apex required" };
        monitoredTabs.set(tabId, { apex, deep });
        ensureApexBucket(apex);
        await injectCollector(tabId, apex);
        if (deep) await attachDebugger(tabId);
        chrome.tabs.sendMessage(tabId, { type: "extract-page", apex }).catch(() => {});
        broadcastLiveUpdate(apex);
        return { ok: true, snapshot: snapshotApex(apex) };
      }
      case "stop-monitor": {
        const tabId = message.tabId;
        if (tabId != null) {
          await detachDebugger(tabId);
          chrome.tabs.sendMessage(tabId, { type: "stop-live" }).catch(() => {});
          monitoredTabs.delete(tabId);
        } else {
          for (const id of monitoredTabs.keys()) {
            await detachDebugger(id);
            chrome.tabs.sendMessage(id, { type: "stop-live" }).catch(() => {});
          }
          monitoredTabs.clear();
        }
        return { ok: true };
      }
      case "clear-live": {
        const apex = normalizeDomain(message.apex || "");
        if (apex && liveStore.byApex[apex]) {
          delete liveStore.byApex[apex];
        } else if (!apex) {
          liveStore.byApex = {};
        }
        return { ok: true };
      }
      case "get-live": {
        const apex = normalizeDomain(message.apex || "");
        if (!apex) return { ok: true, all: liveStore.byApex };
        return { ok: true, snapshot: snapshotApex(apex) };
      }
      case "page-findings": {
        let apex = normalizeDomain(message.apex);
        const tabId = sender.tab?.id;
        if ((!apex || !isValidDomain(apex)) && tabId != null && monitoredTabs.has(tabId)) {
          apex = monitoredTabs.get(tabId).apex;
        }
        if (!apex) return { ok: false, error: "no apex" };
        const source = message.source || "pagejs";
        (message.subdomains || []).forEach((h) => addFinding(apex, h, source));
        (message.related || []).forEach((h) => addFinding(apex, h, source));
        broadcastLiveUpdate(apex);
        return { ok: true };
      }
      case "content-ready": {
        const tabId = sender.tab?.id;
        if (tabId != null && monitoredTabs.has(tabId)) {
          const cfg = monitoredTabs.get(tabId);
          chrome.tabs
            .sendMessage(tabId, { type: "extract-page", apex: cfg.apex })
            .catch(() => {});
        }
        return { ok: true };
      }
      default:
        return { ok: false, error: "unknown message" };
    }
  };

  handle().then(sendResponse);
  return true;
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  if (monitoredTabs.has(tabId)) {
    await detachDebugger(tabId);
    monitoredTabs.delete(tabId);
  }
});
