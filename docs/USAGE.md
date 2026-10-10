# Usage Details

## Scan Settings

- **Concurrency** — how many validation checks run in parallel
- **Delay** — wait time between checks
- **Timeout** — per-request timeout for OSINT and validation

## Sources

Toggle free OSINT providers (crt.sh, BufferOver, HackerTarget, OTX, URLScan, Wayback, Anubis, ThreatMiner, Cert Spotter), shared/similar DNS, wordlist, and active-tab page JS / network capture.

## Live capture

Monitors the active tab. Enable **Deep capture** to attach the Chrome debugger and parse response bodies (browser shows a warning bar).

## Validation

- DNS resolution via Google DoH
- Optional HTTP status probing (`no-cors`)

## Results filters

- Text filter, DNS OK, HTTP seen, hide related domains, filter by source

## Export

- JSON, CSV, TXT, or copy filtered hosts to the clipboard
