/* global SF */
(function () {
  "use strict";

  if (window.__sfContentInstalled) return;
  window.__sfContentInstalled = true;

  const {
    normalizeDomain,
    isValidDomain,
    isSubdomainOf,
    extractHostsFromText,
    hostFromUrl
  } = globalThis.SF;

  let activeApex = normalizeDomain(location.hostname);
  let liveReporting = false;

  // Install MAIN-world network hooks (fetch/XHR/WS/PerformanceObserver)
  try {
    const script = document.createElement("script");
    script.src = chrome.runtime.getURL("injected.js");
    script.async = false;
    (document.documentElement || document.head || document.body).appendChild(script);
    script.remove();
  } catch {
    /* ignore */
  }

  function gatherDomText() {
    const chunks = [];
    chunks.push(document.documentElement?.innerHTML || "");
    document.querySelectorAll("script").forEach((script) => {
      if (script.src) chunks.push(script.src);
      if (script.textContent) chunks.push(script.textContent);
    });
    document.querySelectorAll("[href],[src],[action],[data-url],[data-src]").forEach((el) => {
      ["href", "src", "action", "data-url", "data-src", "content"].forEach((attr) => {
        const val = el.getAttribute?.(attr);
        if (val) chunks.push(val);
      });
    });
    return chunks.join("\n");
  }

  function gatherPerformanceHosts(apex) {
    const subdomains = new Set();
    const related = new Set();
    try {
      const entries = [
        ...performance.getEntriesByType("resource"),
        ...performance.getEntriesByType("navigation")
      ];
      entries.forEach((entry) => {
        const host = hostFromUrl(entry.name);
        if (!host || !isValidDomain(host)) return;
        if (isSubdomainOf(host, apex)) subdomains.add(host);
        else related.add(host);
      });
    } catch {
      /* ignore */
    }
    return { subdomains, related };
  }

  async function fetchScriptBodies() {
    const texts = [];
    const scripts = Array.from(document.querySelectorAll("script[src]"));
    const limit = Math.min(scripts.length, 40);
    for (let i = 0; i < limit; i++) {
      const src = scripts[i].src;
      if (!src) continue;
      try {
        const url = new URL(src, location.href);
        const res = await fetch(url.href, { credentials: "omit" });
        if (!res.ok) continue;
        const text = await res.text();
        if (text && text.length < 1_500_000) texts.push(text);
      } catch {
        /* CORS or network */
      }
    }
    return texts.join("\n");
  }

  async function extractPage(apex) {
    const target = normalizeDomain(apex || location.hostname);
    activeApex = target;
    const subdomains = new Set();
    const related = new Set();

    const merge = (result) => {
      result.subdomains.forEach((h) => subdomains.add(h));
      result.related.forEach((h) => related.add(h));
    };

    merge(extractHostsFromText(gatherDomText(), { apex: target, includeRelated: true }));

    const perf = gatherPerformanceHosts(target);
    perf.subdomains.forEach((h) => subdomains.add(h));
    perf.related.forEach((h) => related.add(h));

    const current = normalizeDomain(location.hostname);
    if (isSubdomainOf(current, target)) subdomains.add(current);

    const scriptText = await fetchScriptBodies();
    merge(extractHostsFromText(scriptText, { apex: target, includeRelated: true }));

    return {
      apex: target,
      subdomains: Array.from(subdomains).sort(),
      related: Array.from(related).sort(),
      performance: {
        subdomains: Array.from(perf.subdomains),
        related: Array.from(perf.related)
      }
    };
  }

  function reportFindings(apex, subdomains, related, source) {
    chrome.runtime
      .sendMessage({
        type: "page-findings",
        apex,
        subdomains: Array.from(subdomains || []),
        related: Array.from(related || []),
        source
      })
      .catch(() => {});
  }

  function classifyAndReport(url, kind) {
    if (!liveReporting) return;
    const host = hostFromUrl(url);
    if (!host || !isValidDomain(host)) return;
    const apex = activeApex;
    const source = kind === "performance" ? "performance" : "pagejs";
    if (isSubdomainOf(host, apex)) {
      reportFindings(apex, [host], [], source);
    } else {
      reportFindings(apex, [], [host], source);
    }
    const extracted = extractHostsFromText(String(url), { apex, includeRelated: true });
    if (extracted.subdomains.size || extracted.related.size) {
      reportFindings(apex, extracted.subdomains, extracted.related, source);
    }
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "sf-subdomain-finder" || !data.url) return;
    classifyAndReport(data.url, data.kind || "network");
  });

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "extract-page") {
      extractPage(message.apex)
        .then((result) => {
          // One-shot extraction always reports; continuous streaming stays gated by liveReporting
          reportFindings(result.apex, result.subdomains, result.related, "pagejs");
          if (result.performance.subdomains.length || result.performance.related.length) {
            reportFindings(
              result.apex,
              result.performance.subdomains,
              result.performance.related,
              "performance"
            );
          }
          sendResponse({ ok: true, result });
        })
        .catch((err) => sendResponse({ ok: false, error: String(err) }));
      return true;
    }
    if (message?.type === "set-apex") {
      activeApex = normalizeDomain(message.apex || activeApex);
      liveReporting = true;
      sendResponse({ ok: true, apex: activeApex });
      return false;
    }
    if (message?.type === "stop-live") {
      liveReporting = false;
      sendResponse({ ok: true });
      return false;
    }
    return false;
  });

  chrome.runtime.sendMessage({ type: "content-ready" }).catch(() => {});
})();
