# Data Sources

This extension uses free / public data sources and local browser capture.

## Passive OSINT

- **crt.sh** — Certificate Transparency
- **dns.bufferover.run** — Passive DNS
- **HackerTarget** — Host search and shared DNS
- **AlienVault OTX** — Passive DNS and URL lists
- **URLScan.io** — Public scan index
- **Wayback Machine CDX** — Historical hosts
- **Anubis DB** — Subdomain aggregation
- **ThreatMiner** — Domain intelligence
- **Cert Spotter** — Certificate issuances

## Browser capture (Manifest V3)

- **Page / JavaScript** — DOM, inline and fetched script bodies, string extraction
- **Network** — `webRequest`, Performance API, MAIN-world fetch/XHR/WebSocket hooks
- **Deep capture** — Optional Chrome Debugger API for response body parsing

## Validation

- **dns.google** — DNS-over-HTTPS A-record checks
- Optional HTTP probe (`no-cors`)
