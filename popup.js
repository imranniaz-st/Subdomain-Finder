/* global SF, SFSources */
(function () {
  "use strict";

  const {
    sleep,
    normalizeDomain,
    isValidDomain,
    isSubdomainOf,
    mergeSourceMaps,
    toCsv,
    downloadBlob,
    fetchJson
  } = SF;

  const { runPassiveSources } = SFSources;

  const form = document.getElementById("scan-form");
  const domainInput = document.getElementById("domain");
  const stopBtn = document.getElementById("stop");
  const useTabBtn = document.getElementById("use-tab");
  const summary = document.getElementById("summary");
  const statusEl = document.getElementById("status");
  const progressWrap = document.getElementById("progress-wrap");
  const progressFill = document.getElementById("progress-fill");
  const resultsBody = document.getElementById("results-body");
  const exportJsonBtn = document.getElementById("export-json");
  const exportCsvBtn = document.getElementById("export-csv");
  const exportTxtBtn = document.getElementById("export-txt");
  const copyBtn = document.getElementById("copy");
  const filterText = document.getElementById("filter-text");
  const filterDns = document.getElementById("filter-dns");
  const filterHttp = document.getElementById("filter-http");
  const filterHideRelated = document.getElementById("filter-hide-related");
  const filterSource = document.getElementById("filter-source");

  const validateDns = document.getElementById("validate-dns");
  const validateHttp = document.getElementById("validate-http");
  const includeRelated = document.getElementById("include-related");
  const concurrencyInput = document.getElementById("concurrency");
  const delayInput = document.getElementById("delay");
  const timeoutInput = document.getElementById("timeout");
  const autoResultsTab = document.getElementById("auto-results-tab");
  const sortAlpha = document.getElementById("sort-alpha");

  const liveStart = document.getElementById("live-start");
  const liveStop = document.getElementById("live-stop");
  const liveClear = document.getElementById("live-clear");
  const liveMerge = document.getElementById("live-merge");
  const liveDeep = document.getElementById("live-deep");
  const liveSubCount = document.getElementById("live-sub-count");
  const liveRelCount = document.getElementById("live-rel-count");
  const liveStatus = document.getElementById("live-status");
  const liveSubList = document.getElementById("live-sub-list");
  const liveRelList = document.getElementById("live-rel-list");

  const SOURCE_IDS = [
    "crtsh", "bufferover", "hackertarget", "alienvault", "urlscan",
    "wayback", "anubis", "threatminer", "certspotter", "sharedDns",
    "otxUrls", "wordlist", "pagejs", "network"
  ];

  let currentController = null;
  let stopped = false;
  let lastResults = [];
  let liveSnapshot = { subdomains: [], related: [], bySource: {} };
  let monitoring = false;

  function sourceCheckbox(id) {
    return document.querySelector(`input[data-source="${id}"]`);
  }

  function getEnabledSources() {
    const enabled = {};
    SOURCE_IDS.forEach((id) => {
      const el = sourceCheckbox(id);
      enabled[id] = Boolean(el?.checked);
    });
    return enabled;
  }

  function setStatus(text, progress) {
    statusEl.textContent = text;
    progressWrap.hidden = false;
    if (typeof progress === "number") {
      progressFill.style.width = `${Math.max(0, Math.min(100, progress))}%`;
    }
  }

  function updateSummary(text) {
    summary.textContent = text;
  }

  function switchTab(name) {
    document.querySelectorAll(".tab").forEach((tab) => {
      const active = tab.dataset.tab === name;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === `panel-${name}`);
    });
  }

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  });

  function setScanningState(scanning) {
    stopBtn.disabled = !scanning;
    document.getElementById("start").disabled = scanning;
    domainInput.disabled = scanning;
    useTabBtn.disabled = scanning;
    document.querySelectorAll("#panel-sources input, #panel-options input").forEach((el) => {
      el.disabled = scanning;
    });
    document.querySelectorAll("#panel-sources .btn.link").forEach((el) => {
      el.disabled = scanning;
    });
    const exportDisabled = scanning || lastResults.length === 0;
    exportJsonBtn.disabled = exportDisabled;
    exportCsvBtn.disabled = exportDisabled;
    exportTxtBtn.disabled = exportDisabled;
    copyBtn.disabled = exportDisabled;
  }

  function renderBadge(value) {
    if (value === true) return '<span class="badge good">OK</span>';
    if (value === false) return '<span class="badge bad">NO</span>';
    if (value === "opaque") return '<span class="badge warn">OPAQUE</span>';
    if (typeof value === "number") return `<span class="badge good">${value}</span>`;
    return '<span class="badge neutral">-</span>';
  }

  function getFilteredResults() {
    const q = (filterText.value || "").trim().toLowerCase();
    const source = filterSource.value;
    return lastResults.filter((row) => {
      if (filterHideRelated.checked && row.related) return false;
      if (filterDns.checked && row.dns !== true) return false;
      if (filterHttp.checked && row.http == null) return false;
      if (q && !row.subdomain.includes(q)) return false;
      if (source && !(row.source || []).includes(source)) return false;
      return true;
    });
  }

  function refreshSourceFilterOptions() {
    const sources = new Set();
    lastResults.forEach((row) => (row.source || []).forEach((s) => sources.add(s)));
    const current = filterSource.value;
    filterSource.innerHTML = '<option value="">All sources</option>';
    Array.from(sources)
      .sort()
      .forEach((s) => {
        const opt = document.createElement("option");
        opt.value = s;
        opt.textContent = s;
        filterSource.appendChild(opt);
      });
    if (current && sources.has(current)) filterSource.value = current;
  }

  function renderResults() {
    const rows = getFilteredResults();
    resultsBody.innerHTML = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      if (row.related) tr.classList.add("related-row");
      const tags = (row.source || [])
        .map((s) => `<span class="source-tag">${s}</span>`)
        .join("");
      tr.innerHTML = `
        <td>${row.subdomain}</td>
        <td>${renderBadge(row.dns)}</td>
        <td>${renderBadge(row.http)}</td>
        <td><div class="source-tags">${tags}</div></td>
      `;
      resultsBody.appendChild(tr);
    });
    updateSummary(
      `${rows.length} shown · ${lastResults.length} total` +
        (lastResults.some((r) => r.related) ? ` · ${lastResults.filter((r) => r.related).length} related` : "")
    );
  }

  async function validateDnsA(subdomain, signal, timeoutMs) {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!data || !Array.isArray(data.Answer)) return false;
    return data.Answer.some((ans) => ans.type === 1);
  }

  async function probeHttp(subdomain, signal, timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const signals = [controller.signal];
    if (signal) signals.push(signal);
    const merged =
      typeof AbortSignal !== "undefined" && AbortSignal.any
        ? AbortSignal.any(signals)
        : controller.signal;
    try {
      const res = await fetch(`https://${subdomain}`, {
        method: "GET",
        mode: "no-cors",
        signal: merged
      });
      return res.type === "opaque" ? "opaque" : res.status;
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function runQueue(items, worker, { concurrency, delay, signal }) {
    let index = 0;
    async function next() {
      if (signal?.aborted) return;
      const current = index++;
      if (current >= items.length) return;
      await worker(items[current], current);
      if (delay > 0) await sleep(delay);
      return next();
    }
    const workers = Array.from(
      { length: Math.min(concurrency, Math.max(items.length, 1)) },
      () => next()
    );
    await Promise.all(workers);
  }

  async function collectFromActiveTab(domain, enabled, timeoutMs) {
    const out = { pagejs: [], network: [], related: [] };
    if (!enabled.pagejs && !enabled.network) return out;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return out;

    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["shared.js", "content.js"]
      });
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["injected.js"],
        world: "MAIN"
      });
    } catch {
      /* restricted page */
    }

    if (enabled.pagejs) {
      try {
        const response = await chrome.tabs.sendMessage(tab.id, {
          type: "extract-page",
          apex: domain
        });
        if (response?.ok && response.result) {
          out.pagejs = response.result.subdomains || [];
          out.related.push(...(response.result.related || []));
          if (response.result.performance) {
            out.network.push(...(response.result.performance.subdomains || []));
            out.related.push(...(response.result.performance.related || []));
          }
        }
      } catch {
        /* no content script */
      }
    }

    if (enabled.network) {
      // Brief monitor to catch in-flight requests, then pull live store
      await chrome.runtime.sendMessage({
        type: "start-monitor",
        tabId: tab.id,
        apex: domain,
        deep: false
      });
      await sleep(Math.min(timeoutMs, 2500));
      const live = await chrome.runtime.sendMessage({ type: "get-live", apex: domain });
      const snap = live?.snapshot;
      if (snap) {
        out.network.push(...(snap.bySource?.network || []), ...(snap.subdomains || []));
        out.related.push(...(snap.related || []));
        if (enabled.pagejs) {
          out.pagejs.push(...(snap.bySource?.pagejs || []), ...(snap.bySource?.performance || []));
        }
      }
      await chrome.runtime.sendMessage({ type: "stop-monitor", tabId: tab.id });
    }

    out.pagejs = Array.from(new Set(out.pagejs.filter((h) => isSubdomainOf(h, domain))));
    out.network = Array.from(new Set(out.network.filter((h) => isSubdomainOf(h, domain))));
    out.related = Array.from(new Set(out.related.filter((h) => isValidDomain(h) && !isSubdomainOf(h, domain))));
    return out;
  }

  function buildExportData() {
    return {
      generatedAt: new Date().toISOString(),
      domain: normalizeDomain(domainInput.value),
      results: getFilteredResults().length ? getFilteredResults() : lastResults
    };
  }

  async function saveSettings() {
    const enabled = getEnabledSources();
    const settings = {
      domain: domainInput.value,
      enabled,
      validateDns: validateDns.checked,
      validateHttp: validateHttp.checked,
      includeRelated: includeRelated.checked,
      concurrency: concurrencyInput.value,
      delay: delayInput.value,
      timeout: timeoutInput.value,
      autoResultsTab: autoResultsTab.checked,
      sortAlpha: sortAlpha.checked,
      liveDeep: liveDeep.checked,
      filterHideRelated: filterHideRelated.checked
    };
    await chrome.storage.local.set({ settings });
  }

  async function loadSettings() {
    const { settings } = await chrome.storage.local.get("settings");
    if (!settings) return;
    domainInput.value = settings.domain || "";
    if (settings.enabled) {
      Object.entries(settings.enabled).forEach(([id, on]) => {
        const el = sourceCheckbox(id);
        if (el) el.checked = Boolean(on);
      });
    }
    validateDns.checked = settings.validateDns ?? true;
    validateHttp.checked = settings.validateHttp ?? false;
    includeRelated.checked = settings.includeRelated ?? true;
    concurrencyInput.value = settings.concurrency ?? 8;
    delayInput.value = settings.delay ?? 100;
    timeoutInput.value = settings.timeout ?? 8000;
    autoResultsTab.checked = settings.autoResultsTab ?? true;
    sortAlpha.checked = settings.sortAlpha ?? true;
    liveDeep.checked = settings.liveDeep ?? false;
    filterHideRelated.checked = settings.filterHideRelated ?? true;
  }

  function renderLive(snapshot) {
    liveSnapshot = snapshot || { subdomains: [], related: [], bySource: {} };
    const subs = liveSnapshot.subdomains || [];
    const rel = liveSnapshot.related || [];
    liveSubCount.textContent = String(subs.length);
    liveRelCount.textContent = String(rel.length);
    liveSubList.innerHTML = subs.map((h) => `<li>${h}</li>`).join("") || "<li>—</li>";
    liveRelList.innerHTML = rel.map((h) => `<li>${h}</li>`).join("") || "<li>—</li>";
  }

  function mergeLiveIntoResults() {
    const domain = normalizeDomain(domainInput.value);
    if (!domain) {
      setStatus("Enter a target domain first.");
      return;
    }
    const map = {};
    lastResults.forEach((row) => {
      map[row.subdomain] = { ...row, source: [...(row.source || [])] };
    });

    const add = (host, source, related) => {
      const h = normalizeDomain(host);
      if (!h) return;
      if (!map[h]) {
        map[h] = { subdomain: h, dns: null, http: null, source: [source], related: Boolean(related) };
      } else if (!map[h].source.includes(source)) {
        map[h].source.push(source);
      }
    };

    (liveSnapshot.subdomains || []).forEach((h) => add(h, "live", false));
    Object.entries(liveSnapshot.bySource || {}).forEach(([source, list]) => {
      (list || []).forEach((h) => add(h, source, false));
    });
    if (includeRelated.checked) {
      (liveSnapshot.related || []).forEach((h) => add(h, "related", true));
    }

    lastResults = Object.values(map);
    if (sortAlpha.checked) {
      lastResults.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    }
    refreshSourceFilterOptions();
    renderResults();
    setScanningState(false);
    switchTab("results");
    setStatus(`Merged live findings. ${lastResults.length} total hosts.`);
  }

  // Source quick toggles
  document.getElementById("sources-all").addEventListener("click", () => {
    SOURCE_IDS.forEach((id) => {
      const el = sourceCheckbox(id);
      if (el) el.checked = true;
    });
  });
  document.getElementById("sources-none").addEventListener("click", () => {
    SOURCE_IDS.forEach((id) => {
      const el = sourceCheckbox(id);
      if (el) el.checked = false;
    });
  });
  document.getElementById("sources-passive").addEventListener("click", () => {
    document.querySelectorAll("input[data-source]").forEach((el) => {
      el.checked = el.dataset.passive === "1";
    });
  });

  useTabBtn.addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    try {
      const host = normalizeDomain(new URL(tab.url).hostname);
      if (isValidDomain(host)) {
        // Prefer apex-ish: drop left labels cautiously — keep full host; user can edit
        const parts = host.split(".");
        domainInput.value = parts.length > 2 ? parts.slice(-2).join(".") : host;
      }
    } catch {
      /* ignore */
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    stopped = false;
    const domain = normalizeDomain(domainInput.value);

    if (!isValidDomain(domain)) {
      setStatus("Enter a valid domain, e.g. example.com");
      updateSummary("Invalid domain.");
      return;
    }

    await saveSettings();
    currentController?.abort();
    currentController = new AbortController();
    const signal = currentController.signal;

    setScanningState(true);
    setStatus("Discovering subdomains…", 5);
    updateSummary("Scanning…");
    resultsBody.innerHTML = "";
    switchTab("sources");

    const timeoutMs = Number(timeoutInput.value) || 8000;
    const enabled = getEnabledSources();

    setStatus("Querying free OSINT sources…", 15);
    const { sourceMap, related, errors } = await runPassiveSources(
      domain,
      enabled,
      signal,
      timeoutMs,
      (key, state, count) => {
        if (state === "done") {
          setStatus(`Source ${key}: ${count ?? 0} hosts`, null);
        }
      }
    );

    if (stopped || signal.aborted) {
      setScanningState(false);
      setStatus("Stopped.");
      return;
    }

    setStatus("Collecting from active tab JS / network…", 45);
    const tabFindings = await collectFromActiveTab(domain, enabled, timeoutMs);
    if (enabled.pagejs) sourceMap.pagejs = tabFindings.pagejs;
    if (enabled.network) sourceMap.network = tabFindings.network;

    let merged = mergeSourceMaps(sourceMap);

    if (includeRelated.checked) {
      const relatedSet = new Set([...(related || []), ...tabFindings.related]);
      relatedSet.forEach((host) => {
        if (!merged.find((r) => r.subdomain === host)) {
          merged.push({
            subdomain: host,
            dns: null,
            http: null,
            source: ["related"],
            related: true
          });
        }
      });
    }

    if (sortAlpha.checked) {
      merged.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    }

    const errKeys = Object.keys(errors || {});
    setStatus(
      `Found ${merged.length} hosts.` +
        (errKeys.length ? ` (${errKeys.length} sources failed)` : "") +
        " Validating…",
      55
    );

    const validateDnsOn = validateDns.checked;
    const validateHttpOn = validateHttp.checked;
    const concurrency = Number(concurrencyInput.value) || 8;
    const delay = Number(delayInput.value) || 0;

    if (validateDnsOn || validateHttpOn) {
      let done = 0;
      await runQueue(
        merged,
        async (row) => {
          if (stopped || signal.aborted) return;
          if (validateDnsOn) row.dns = await validateDnsA(row.subdomain, signal, timeoutMs);
          if (validateHttpOn) row.http = await probeHttp(row.subdomain, signal, timeoutMs);
          done += 1;
          const pct = 55 + Math.round((done / Math.max(merged.length, 1)) * 40);
          setStatus(`Validating ${row.subdomain} (${done}/${merged.length})`, pct);
          lastResults = merged;
          renderResults();
        },
        { concurrency, delay, signal }
      );
    }

    lastResults = merged;
    refreshSourceFilterOptions();
    renderResults();
    setStatus(`Done. ${lastResults.length} results.`, 100);
    setScanningState(false);
    if (autoResultsTab.checked) switchTab("results");
  });

  stopBtn.addEventListener("click", () => {
    stopped = true;
    currentController?.abort();
    setScanningState(false);
    setStatus("Stopped.");
  });

  [filterText, filterDns, filterHttp, filterHideRelated, filterSource].forEach((el) => {
    el.addEventListener("input", renderResults);
    el.addEventListener("change", renderResults);
  });

  exportJsonBtn.addEventListener("click", () => {
    const data = JSON.stringify(buildExportData(), null, 2);
    downloadBlob("subdomains.json", data, "application/json");
  });

  exportCsvBtn.addEventListener("click", () => {
    downloadBlob("subdomains.csv", toCsv(getFilteredResults()), "text/csv");
  });

  exportTxtBtn.addEventListener("click", () => {
    const list = getFilteredResults().map((r) => r.subdomain).join("\n");
    downloadBlob("subdomains.txt", list, "text/plain");
  });

  copyBtn.addEventListener("click", async () => {
    const list = getFilteredResults().map((r) => r.subdomain).join("\n");
    await navigator.clipboard.writeText(list);
    setStatus("Copied filtered hosts to clipboard.");
  });

  liveStart.addEventListener("click", async () => {
    const domain = normalizeDomain(domainInput.value);
    if (!isValidDomain(domain)) {
      liveStatus.textContent = "Set domain";
      return;
    }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      liveStatus.textContent = "No tab";
      return;
    }
    await saveSettings();
    const res = await chrome.runtime.sendMessage({
      type: "start-monitor",
      tabId: tab.id,
      apex: domain,
      deep: liveDeep.checked
    });
    monitoring = true;
    liveStart.disabled = true;
    liveStop.disabled = false;
    liveStatus.textContent = liveDeep.checked ? "Deep" : "On";
    if (res?.snapshot) renderLive(res.snapshot);
  });

  liveStop.addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.runtime.sendMessage({ type: "stop-monitor", tabId: tab?.id });
    monitoring = false;
    liveStart.disabled = false;
    liveStop.disabled = true;
    liveStatus.textContent = "Idle";
  });

  liveClear.addEventListener("click", async () => {
    const domain = normalizeDomain(domainInput.value);
    await chrome.runtime.sendMessage({ type: "clear-live", apex: domain });
    renderLive({ subdomains: [], related: [], bySource: {} });
  });

  liveMerge.addEventListener("click", mergeLiveIntoResults);

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "live-update" && message.payload) {
      const apex = normalizeDomain(domainInput.value);
      if (!apex || message.payload.apex === apex) {
        renderLive(message.payload);
        if (monitoring) liveStatus.textContent = "Capturing";
      }
    }
  });

  loadSettings().then(async () => {
    const domain = normalizeDomain(domainInput.value);
    if (domain) {
      const live = await chrome.runtime.sendMessage({ type: "get-live", apex: domain });
      if (live?.snapshot) renderLive(live.snapshot);
    }
  });
})();
