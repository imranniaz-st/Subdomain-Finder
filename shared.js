/**
 * Shared helpers for Subdomain Finder (popup, background, content).
 * Attaches to globalThis.SF
 */
(function (global) {
  "use strict";

  const DOMAIN_RE =
    /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}/gi;
  const HOST_FROM_URL_RE =
    /(?:https?:\/\/|\/\/|["'`])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})/gi;

  const COMMON_TLDS = new Set([
    "com", "net", "org", "io", "co", "dev", "app", "info", "biz", "me",
    "us", "uk", "de", "fr", "nl", "au", "ca", "in", "jp", "cn", "ru",
    "br", "xyz", "online", "site", "tech", "cloud", "ai", "tv", "cc"
  ]);

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function normalizeDomain(input) {
    if (!input) return "";
    let value = String(input).trim().toLowerCase();
    value = value.replace(/^https?:\/\//, "").replace(/^\/\//, "");
    value = value.split("/")[0].split("?")[0].split("#")[0];
    value = value.replace(/:\d+$/, "").replace(/^\*\./, "").replace(/^\./, "");
    return value;
  }

  function isValidDomain(value) {
    if (!value || value.length > 253) return false;
    if (!/^[a-z0-9.-]+$/.test(value)) return false;
    if (value.startsWith(".") || value.endsWith(".") || value.includes("..")) return false;
    const labels = value.split(".");
    if (labels.length < 2) return false;
    const tld = labels[labels.length - 1];
    if (!/^[a-z]{2,63}$/.test(tld)) return false;
    return labels.every((label) =>
      label.length > 0 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-")
    );
  }

  function isIpLiteral(host) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
  }

  function isSubdomainOf(host, apex) {
    const h = normalizeDomain(host);
    const a = normalizeDomain(apex);
    if (!h || !a || !isValidDomain(h) || !isValidDomain(a)) return false;
    return h === a || h.endsWith(`.${a}`);
  }

  function extractRegistrableHint(host) {
    const parts = normalizeDomain(host).split(".");
    if (parts.length < 2) return host;
    const last = parts[parts.length - 1];
    const second = parts[parts.length - 2];
    if (parts.length >= 3 && COMMON_TLDS.has(last) && second.length <= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function extractHostsFromText(text, { apex = null, includeRelated = true } = {}) {
    const found = new Set();
    const related = new Set();
    if (!text || typeof text !== "string") {
      return { subdomains: found, related };
    }

    const addHost = (raw) => {
      const host = normalizeDomain(raw);
      if (!host || !isValidDomain(host) || isIpLiteral(host)) return;
      if (apex) {
        if (isSubdomainOf(host, apex)) {
          found.add(host);
        } else if (includeRelated) {
          related.add(host);
        }
      } else {
        found.add(host);
      }
    };

    let match;
    const domainRe = new RegExp(DOMAIN_RE.source, DOMAIN_RE.flags);
    while ((match = domainRe.exec(text)) !== null) {
      addHost(match[0]);
    }

    const urlRe = new RegExp(HOST_FROM_URL_RE.source, HOST_FROM_URL_RE.flags);
    while ((match = urlRe.exec(text)) !== null) {
      addHost(match[1]);
    }

    return { subdomains: found, related };
  }

  function hostFromUrl(url) {
    try {
      const u = new URL(url, "https://placeholder.local");
      return normalizeDomain(u.hostname);
    } catch {
      return "";
    }
  }

  async function fetchWithTimeout(url, { signal, timeoutMs = 8000, headers } = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const signals = [controller.signal];
    if (signal) signals.push(signal);
    const merged =
      typeof AbortSignal !== "undefined" && AbortSignal.any
        ? AbortSignal.any(signals)
        : controller.signal;

    try {
      const res = await fetch(url, {
        signal: merged,
        headers: headers || { Accept: "application/json,text/plain,*/*" }
      });
      return res;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function fetchJson(url, opts) {
    try {
      const res = await fetchWithTimeout(url, opts);
      if (!res || !res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  async function fetchText(url, opts) {
    try {
      const res = await fetchWithTimeout(url, opts);
      if (!res || !res.ok) return null;
      return await res.text();
    } catch {
      return null;
    }
  }

  function mergeSourceMaps(sourceMap) {
    const merged = new Map();
    Object.entries(sourceMap).forEach(([source, names]) => {
      (names || []).forEach((name) => {
        const host = normalizeDomain(name);
        if (!host || !isValidDomain(host)) return;
        if (!merged.has(host)) {
          merged.set(host, {
            subdomain: host,
            dns: null,
            http: null,
            source: [source],
            related: false
          });
        } else {
          const entry = merged.get(host);
          if (!entry.source.includes(source)) entry.source.push(source);
        }
      });
    });
    return Array.from(merged.values()).sort((a, b) =>
      a.subdomain.localeCompare(b.subdomain)
    );
  }

  function escapeCsv(value) {
    const text = String(value ?? "");
    if (/[",\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
    return text;
  }

  function toCsv(rows) {
    const header = ["subdomain", "dns", "http", "source", "related"].join(",");
    const lines = rows.map((row) =>
      [
        row.subdomain,
        row.dns === null ? "" : row.dns,
        row.http === null ? "" : row.http,
        (row.source || []).join("|"),
        row.related ? "yes" : "no"
      ]
        .map(escapeCsv)
        .join(",")
    );
    return [header, ...lines].join("\n");
  }

  function downloadBlob(filename, data, mime) {
    const blob = new Blob([data], { type: mime });
    const url = URL.createObjectURL(blob);
    if (global.chrome?.downloads?.download) {
      chrome.downloads.download({ url, filename, saveAs: true }, () => {
        URL.revokeObjectURL(url);
      });
    } else {
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    }
  }

  const WORDLIST = [
    "www", "www2", "api", "api2", "app", "apps", "dev", "development",
    "stage", "staging", "prod", "production", "beta", "test", "testing",
    "qa", "uat", "mail", "smtp", "imap", "pop", "m", "mobile", "cdn",
    "static", "assets", "media", "img", "images", "admin", "portal",
    "secure", "vpn", "remote", "git", "gitlab", "github", "ci", "jenkins",
    "docs", "status", "support", "help", "blog", "shop", "store", "pay",
    "billing", "auth", "sso", "login", "account", "accounts", "dashboard",
    "internal", "intranet", "corp", "office", "ftp", "ns1", "ns2", "dns",
    "monitor", "grafana", "kibana", "elastic", "db", "mysql", "redis",
    "cache", "edge", "proxy", "gateway", "ws", "websocket", "graphql",
    "v1", "v2", "old", "new", "demo", "sandbox", "preview", "cdn1", "cdn2"
  ];

  global.SF = {
    DOMAIN_RE,
    WORDLIST,
    sleep,
    normalizeDomain,
    isValidDomain,
    isIpLiteral,
    isSubdomainOf,
    extractRegistrableHint,
    extractHostsFromText,
    hostFromUrl,
    fetchWithTimeout,
    fetchJson,
    fetchText,
    mergeSourceMaps,
    escapeCsv,
    toCsv,
    downloadBlob
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
