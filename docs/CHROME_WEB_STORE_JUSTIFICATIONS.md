# Chrome Web Store — Permission Justifications

Ready-to-paste text for the **Privacy practices** / permission justification fields.

**Single-purpose (alignment note):** This extension discovers subdomains for a user-specified domain using free OSINT APIs, analysis of the active page’s JavaScript/DOM, and optional observation of that tab’s network traffic. Permissions below exist only to support that discovery workflow when the user starts a scan or live capture.

---

## activeTab

We use activeTab so that when the user opens the extension and starts a scan or live capture on their current page, we can work with that focused tab to collect hostnames from page content and related network activity. Access is tied to the user’s explicit action (toolbar / side panel use), not background browsing of unrelated tabs.

---

## debugger

The optional “Deep capture” feature attaches the Chrome DevTools Protocol to the user-selected monitored tab so we can observe network request and response URLs and, when enabled, parse response bodies for hostname strings that indicate subdomains of the target domain. The debugger is attached only after the user starts live monitoring with Deep capture enabled, and it is detached when monitoring stops or the tab closes. Chrome shows its standard debugger warning bar while attached. We do not use the debugger to change page behavior or control the browser UI.

---

## scripting

We use the scripting permission to inject our content and page scripts into the tab the user is scanning or live-monitoring. Those scripts extract hostname candidates from the DOM, inline and external JavaScript, Performance API entries, and page-initiated fetch/XHR/WebSocket activity so the extension can report subdomains related to the target domain. Injection runs only for tabs the user has chosen to scan or monitor.

---

## sidePanel

We use the sidePanel permission to present the extension’s main UI in Chrome’s side panel. Clicking the toolbar icon opens this panel, where the user enters a target domain, chooses sources, starts/stops scans and live capture, and exports results. The side panel is the primary interface for the extension’s subdomain discovery features.

---

## tabs

We use the tabs permission to identify the user’s active tab (for “This tab” domain fill and for starting/stopping live capture), to send messages to our content scripts in that tab, and to clean up monitoring when a tab is closed. We read the active tab’s URL only to suggest a target domain and to scope live collection to the tab the user selected. We do not sync browsing history or read tabs unrelated to the user’s scan/monitor actions beyond what is needed for that workflow.

---

## webRequest

We use webRequest (observe-only) during user-started live monitoring to see request URLs from the monitored tab and extract hostnames that are subdomains of—or related to—the target domain. We do not block, redirect, or modify network requests; URLs are used solely to discover hostnames for the subdomain finder results the user requested.

---

## Combined single-purpose blurb (optional)

Subdomain Finder Professional helps users discover subdomains of a domain they enter by combining free public OSINT sources with optional, user-initiated analysis of the active tab’s page JavaScript and network traffic (including optional deep capture of response bodies). All listed permissions support that single purpose: finding and exporting hostname findings for authorized security research and asset inventory.
