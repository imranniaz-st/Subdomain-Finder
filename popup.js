const form = document.getElementById("scan-form");
const domainInput = document.getElementById("domain");
const stopBtn = document.getElementById("stop");
const summary = document.getElementById("summary");
const resultsBody = document.getElementById("results-body");
const exportJsonBtn = document.getElementById("export-json");
const exportCsvBtn = document.getElementById("export-csv");
const copyBtn = document.getElementById("copy");

const methodCrt = document.getElementById("method-crt");
const methodBuff = document.getElementById("method-buff");
const methodWordlist = document.getElementById("method-wordlist");
const validateDns = document.getElementById("validate-dns");
const validateHttp = document.getElementById("validate-http");
const concurrencyInput = document.getElementById("concurrency");
const delayInput = document.getElementById("delay");
const timeoutInput = document.getElementById("timeout");

let currentController = null;
let stopped = false;
let lastResults = [];

const WORDLIST = [
  "www",
  "api",
  "app",
  "dev",
  "stage",
  "staging",
  "prod",
  "beta",
  "test",
  "mail",
  "m",
  "cdn",
  "static",
  "admin",
  "portal"
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function normalizeDomain(input) {
  const trimmed = input.trim().toLowerCase();
  return trimmed.replace(/^https?:\/\//, "").replace(/\/$/, "");
}

function isValidDomain(value) {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(value);
}

function setButtonsScanning(scanning) {
  stopBtn.disabled = !scanning;
  exportJsonBtn.disabled = scanning || lastResults.length === 0;
  exportCsvBtn.disabled = scanning || lastResults.length === 0;
  copyBtn.disabled = scanning || lastResults.length === 0;
}

async function fetchJson(url, signal, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const mergedSignal = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;

  try {
    const res = await fetch(url, { signal: mergedSignal });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchCrtSh(domain, signal, timeoutMs) {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  const data = await fetchJson(url, signal, timeoutMs);
  if (!Array.isArray(data)) return [];

  const names = new Set();
  data.forEach((entry) => {
    if (!entry.name_value) return;
    entry.name_value.split("\n").forEach((name) => {
      const clean = name.replace(/\*\./g, "").trim().toLowerCase();
      if (clean.endsWith(domain)) names.add(clean);
    });
  });
  return Array.from(names);
}

async function fetchBufferOver(domain, signal, timeoutMs) {
  const url = `https://dns.bufferover.run/dns?q=.${domain}`;
  const data = await fetchJson(url, signal, timeoutMs);
  if (!data || !Array.isArray(data.FDNS_A)) return [];

  const names = new Set();
  data.FDNS_A.forEach((line) => {
    const parts = line.split(",");
    const name = (parts[1] || "").trim().toLowerCase();
    if (name && name.endsWith(domain)) names.add(name);
  });
  return Array.from(names);
}

async function validateDnsA(subdomain, signal, timeoutMs) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`;
  const data = await fetchJson(url, signal, timeoutMs);
  if (!data || !Array.isArray(data.Answer)) return false;
  return data.Answer.some((ans) => ans.type === 1);
}

async function probeHttp(subdomain, signal, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const mergedSignal = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;

  try {
    const res = await fetch(`https://${subdomain}`, { method: "GET", mode: "no-cors", signal: mergedSignal });
    return res.type === "opaque" ? "opaque" : res.status;
  } catch (err) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function updateSummary(text) {
  summary.textContent = text;
}

function renderResults(results) {
  resultsBody.innerHTML = "";
  results.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.subdomain}</td>
      <td>${renderBadge(row.dns)}</td>
      <td>${renderBadge(row.http)}</td>
      <td>${row.source.join(", ")}</td>
    `;
    resultsBody.appendChild(tr);
  });
}

function renderBadge(value) {
  if (value === true) return '<span class="badge good">OK</span>';
  if (value === false) return '<span class="badge bad">NO</span>';
  if (value === "opaque") return '<span class="badge warn">OPAQUE</span>';
  if (typeof value === "number") return `<span class="badge good">${value}</span>`;
  return '<span class="badge warn">-</span>';
}

async function runQueue(items, worker, { concurrency, delay, signal }) {
  const results = [];
  let index = 0;

  async function next() {
    if (signal?.aborted) return;
    const current = index++;
    if (current >= items.length) return;
    const item = items[current];
    const output = await worker(item, current);
    results.push(output);
    if (delay > 0) await sleep(delay);
    return next();
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => next());
  await Promise.all(workers);
  return results;
}

function mergeResults(sourceMap) {
  const merged = new Map();
  Object.entries(sourceMap).forEach(([source, names]) => {
    names.forEach((name) => {
      if (!merged.has(name)) {
        merged.set(name, { subdomain: name, dns: null, http: null, source: [source] });
      } else {
        const entry = merged.get(name);
        if (!entry.source.includes(source)) entry.source.push(source);
      }
    });
  });
  return Array.from(merged.values()).sort((a, b) => a.subdomain.localeCompare(b.subdomain));
}

function buildExportData() {
  return {
    generatedAt: new Date().toISOString(),
    domain: domainInput.value.trim(),
    results: lastResults
  };
}

function downloadFile(filename, data, mime) {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);

  if (chrome?.downloads?.download) {
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

function toCsv(rows) {
  const header = ["subdomain", "dns", "http", "source"].join(",");
  const lines = rows.map((row) => [
    row.subdomain,
    row.dns === null ? "" : row.dns,
    row.http === null ? "" : row.http,
    row.source.join("|")
  ].map(escapeCsv).join(","));
  return [header, ...lines].join("\n");
}

function escapeCsv(value) {
  const text = String(value ?? "");
  if (/[",\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function setScanningState(scanning) {
  setButtonsScanning(scanning);
  form.querySelectorAll("input, button").forEach((el) => {
    if (el.id === "stop") return;
    el.disabled = scanning;
  });
}

async function saveSettings() {
  const settings = {
    domain: domainInput.value,
    methodCrt: methodCrt.checked,
    methodBuff: methodBuff.checked,
    methodWordlist: methodWordlist.checked,
    validateDns: validateDns.checked,
    validateHttp: validateHttp.checked,
    concurrency: concurrencyInput.value,
    delay: delayInput.value,
    timeout: timeoutInput.value
  };
  await chrome.storage.local.set({ settings });
}

async function loadSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings) return;
  domainInput.value = settings.domain || "";
  methodCrt.checked = settings.methodCrt ?? true;
  methodBuff.checked = settings.methodBuff ?? true;
  methodWordlist.checked = settings.methodWordlist ?? false;
  validateDns.checked = settings.validateDns ?? true;
  validateHttp.checked = settings.validateHttp ?? true;
  concurrencyInput.value = settings.concurrency ?? 8;
  delayInput.value = settings.delay ?? 150;
  timeoutInput.value = settings.timeout ?? 4000;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  stopped = false;
  const domain = normalizeDomain(domainInput.value);

  if (!isValidDomain(domain)) {
    updateSummary("Enter a valid domain, e.g. example.com");
    return;
  }

  await saveSettings();

  currentController?.abort();
  currentController = new AbortController();
  const signal = currentController.signal;

  setScanningState(true);
  updateSummary("Discovering subdomains...");
  resultsBody.innerHTML = "";

  const timeoutMs = Number(timeoutInput.value) || 4000;
  const sources = {};

  if (methodCrt.checked) {
    sources.crtsh = await fetchCrtSh(domain, signal, timeoutMs);
  }

  if (methodBuff.checked) {
    sources.bufferover = await fetchBufferOver(domain, signal, timeoutMs);
  }

  if (methodWordlist.checked) {
    sources.wordlist = WORDLIST.map((word) => `${word}.${domain}`);
  }

  let merged = mergeResults(sources);
  updateSummary(`Found ${merged.length} unique subdomains. Validating...`);

  const validateDnsOn = validateDns.checked;
  const validateHttpOn = validateHttp.checked;
  const concurrency = Number(concurrencyInput.value) || 8;
  const delay = Number(delayInput.value) || 0;

  merged = await runQueue(
    merged,
    async (row) => {
      if (stopped || signal.aborted) return row;
      if (validateDnsOn) row.dns = await validateDnsA(row.subdomain, signal, timeoutMs);
      if (validateHttpOn) row.http = await probeHttp(row.subdomain, signal, timeoutMs);
      renderResults(merged);
      updateSummary(`Scanning ${row.subdomain}... (${merged.filter((r) => r.dns !== null || r.http !== null).length}/${merged.length})`);
      return row;
    },
    { concurrency, delay, signal }
  );

  lastResults = merged;
  renderResults(lastResults);
  updateSummary(`Done. ${lastResults.length} results.`);
  setScanningState(false);
  setButtonsScanning(false);
});

stopBtn.addEventListener("click", () => {
  stopped = true;
  currentController?.abort();
  setScanningState(false);
  updateSummary("Stopped.");
});

exportJsonBtn.addEventListener("click", () => {
  const data = JSON.stringify(buildExportData(), null, 2);
  downloadFile("subdomains.json", data, "application/json");
});

exportCsvBtn.addEventListener("click", () => {
  const data = toCsv(lastResults);
  downloadFile("subdomains.csv", data, "text/csv");
});

copyBtn.addEventListener("click", async () => {
  const list = lastResults.map((row) => row.subdomain).join("\n");
  await navigator.clipboard.writeText(list);
  updateSummary("Copied to clipboard.");
});

loadSettings();
