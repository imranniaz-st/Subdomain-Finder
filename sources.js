/**
 * Free / public OSINT subdomain sources.
 * Depends on globalThis.SF
 */
(function (global) {
  "use strict";

  const {
    normalizeDomain,
    isSubdomainOf,
    isValidDomain,
    fetchJson,
    fetchText,
    extractHostsFromText,
    WORDLIST
  } = global.SF;

  function collectFromNames(names, apex) {
    const out = new Set();
    (names || []).forEach((raw) => {
      String(raw)
        .split(/[\n,\s]+/)
        .forEach((part) => {
          const host = normalizeDomain(part.replace(/^\*\./, ""));
          if (host && isSubdomainOf(host, apex)) out.add(host);
        });
    });
    return Array.from(out);
  }

  async function fetchCrtSh(domain, signal, timeoutMs) {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!Array.isArray(data)) return [];
    const names = new Set();
    data.forEach((entry) => {
      if (!entry.name_value) return;
      entry.name_value.split("\n").forEach((name) => {
        const clean = normalizeDomain(name.replace(/\*\./g, ""));
        if (isSubdomainOf(clean, domain)) names.add(clean);
      });
    });
    return Array.from(names);
  }

  async function fetchBufferOver(domain, signal, timeoutMs) {
    const url = `https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!data) return [];
    const names = new Set();
    const pushLine = (line) => {
      if (!line) return;
      const parts = String(line).split(",");
      const candidate = normalizeDomain(parts[1] || parts[0] || "");
      if (isSubdomainOf(candidate, domain)) names.add(candidate);
    };
    (data.FDNS_A || []).forEach(pushLine);
    (data.RDNS || []).forEach(pushLine);
    return Array.from(names);
  }

  async function fetchHackerTarget(domain, signal, timeoutMs) {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    const text = await fetchText(url, { signal, timeoutMs });
    if (!text || /error|api count|invalid/i.test(text)) return [];
    const names = new Set();
    text.split("\n").forEach((line) => {
      const host = normalizeDomain(line.split(",")[0] || "");
      if (isSubdomainOf(host, domain)) names.add(host);
    });
    return Array.from(names);
  }

  async function fetchAlienVault(domain, signal, timeoutMs) {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!data || !Array.isArray(data.passive_dns)) return [];
    return collectFromNames(
      data.passive_dns.map((row) => row.hostname),
      domain
    );
  }

  async function fetchUrlscan(domain, signal, timeoutMs) {
    const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!data || !Array.isArray(data.results)) return [];
    const names = new Set();
    data.results.forEach((row) => {
      const page = row.page || {};
      [page.domain, page.apexDomain, row.task?.domain].forEach((d) => {
        const host = normalizeDomain(d || "");
        if (isSubdomainOf(host, domain)) names.add(host);
      });
    });
    return Array.from(names);
  }

  async function fetchWayback(domain, signal, timeoutMs) {
    const url =
      `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*` +
      `&output=json&fl=original&collapse=urlkey&limit=2000`;
    const data = await fetchJson(url, { signal, timeoutMs: Math.max(timeoutMs, 12000) });
    if (!Array.isArray(data) || data.length < 2) return [];
    const names = new Set();
    for (let i = 1; i < data.length; i++) {
      const original = data[i]?.[0];
      if (!original) continue;
      try {
        const host = normalizeDomain(new URL(original).hostname);
        if (isSubdomainOf(host, domain)) names.add(host);
      } catch {
        /* ignore */
      }
    }
    return Array.from(names);
  }

  async function fetchAnubis(domain, signal, timeoutMs) {
    const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!Array.isArray(data)) return [];
    return collectFromNames(data, domain);
  }

  async function fetchThreatMiner(domain, signal, timeoutMs) {
    const url = `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!data || !Array.isArray(data.results)) return [];
    return collectFromNames(data.results, domain);
  }

  async function fetchCertSpotter(domain, signal, timeoutMs) {
    const url =
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
      `&include_subdomains=true&expand=dns_names`;
    const data = await fetchJson(url, { signal, timeoutMs });
    if (!Array.isArray(data)) return [];
    const names = new Set();
    data.forEach((row) => {
      (row.dns_names || []).forEach((name) => {
        const host = normalizeDomain(name.replace(/^\*\./, ""));
        if (isSubdomainOf(host, domain)) names.add(host);
      });
    });
    return Array.from(names);
  }

  async function fetchHackertargetShared(domain, signal, timeoutMs) {
    const url = `https://api.hackertarget.com/findshareddns/?q=${encodeURIComponent(domain)}`;
    const text = await fetchText(url, { signal, timeoutMs });
    if (!text || /error|api count|invalid/i.test(text)) return { subdomains: [], related: [] };
    const subdomains = new Set();
    const related = new Set();
    text.split("\n").forEach((line) => {
      const host = normalizeDomain(line.trim());
      if (!isValidDomain(host)) return;
      if (isSubdomainOf(host, domain)) subdomains.add(host);
      else related.add(host);
    });
    return { subdomains: Array.from(subdomains), related: Array.from(related) };
  }

  async function fetchAlienVaultRelated(domain, signal, timeoutMs) {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list?limit=100`;
    const data = await fetchJson(url, { signal, timeoutMs });
    const related = new Set();
    const subdomains = new Set();
    const list = data?.url_list || [];
    list.forEach((item) => {
      const raw = item.url || item.hostname || "";
      try {
        const host = normalizeDomain(raw.includes("://") ? new URL(raw).hostname : raw);
        if (!isValidDomain(host)) return;
        if (isSubdomainOf(host, domain)) subdomains.add(host);
        else related.add(host);
      } catch {
        /* ignore */
      }
    });
    return { subdomains: Array.from(subdomains), related: Array.from(related) };
  }

  function wordlistFor(domain) {
    return WORDLIST.map((word) => `${word}.${domain}`);
  }

  /**
   * Run selected discovery sources in parallel.
   * @returns {{ sourceMap: Object, related: string[], errors: Object }}
   */
  async function runPassiveSources(domain, enabled, signal, timeoutMs, onProgress) {
    const sourceMap = {};
    const related = new Set();
    const errors = {};

    const tasks = [];

    const wrap = (key, fn) => {
      if (!enabled[key]) return;
      tasks.push(
        (async () => {
          try {
            onProgress?.(key, "running");
            const result = await fn();
            if (Array.isArray(result)) {
              sourceMap[key] = result;
            } else if (result && typeof result === "object") {
              sourceMap[key] = result.subdomains || [];
              (result.related || []).forEach((d) => related.add(d));
            }
            onProgress?.(key, "done", (sourceMap[key] || []).length);
          } catch (err) {
            errors[key] = String(err?.message || err);
            sourceMap[key] = [];
            onProgress?.(key, "error");
          }
        })()
      );
    };

    wrap("crtsh", () => fetchCrtSh(domain, signal, timeoutMs));
    wrap("bufferover", () => fetchBufferOver(domain, signal, timeoutMs));
    wrap("hackertarget", () => fetchHackerTarget(domain, signal, timeoutMs));
    wrap("alienvault", () => fetchAlienVault(domain, signal, timeoutMs));
    wrap("urlscan", () => fetchUrlscan(domain, signal, timeoutMs));
    wrap("wayback", () => fetchWayback(domain, signal, timeoutMs));
    wrap("anubis", () => fetchAnubis(domain, signal, timeoutMs));
    wrap("threatminer", () => fetchThreatMiner(domain, signal, timeoutMs));
    wrap("certspotter", () => fetchCertSpotter(domain, signal, timeoutMs));
    wrap("wordlist", async () => wordlistFor(domain));
    wrap("sharedDns", () => fetchHackertargetShared(domain, signal, timeoutMs));
    wrap("otxUrls", () => fetchAlienVaultRelated(domain, signal, timeoutMs));

    await Promise.all(tasks);
    return { sourceMap, related: Array.from(related), errors };
  }

  global.SFSources = {
    fetchCrtSh,
    fetchBufferOver,
    fetchHackerTarget,
    fetchAlienVault,
    fetchUrlscan,
    fetchWayback,
    fetchAnubis,
    fetchThreatMiner,
    fetchCertSpotter,
    fetchHackertargetShared,
    fetchAlienVaultRelated,
    wordlistFor,
    runPassiveSources,
    collectFromNames,
    extractHostsFromText
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
