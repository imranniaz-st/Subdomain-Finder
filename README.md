# Subdomain Finder Professional

A Manifest V3 Chrome extension for discovering subdomains using free OSINT sources, page JavaScript analysis, and network traffic capture. By BICODEV. Use responsibly.

## Features

- Passive discovery via crt.sh, BufferOver, HackerTarget, AlienVault OTX, URLScan, Wayback CDX, Anubis, ThreatMiner, Cert Spotter
- Similar / related domain discovery (shared DNS, OTX URLs, non-apex hosts seen in page/network)
- Live capture from page JS, DOM, Performance API, webRequest, and optional debugger response bodies
- Optional wordlist expansion and DNS/HTTP validation
- Filters, concurrency controls, export to JSON / CSV / TXT, clipboard copy
- Clean light UI (white / black / blue)

## Install (Developer Mode)

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select this folder.

## Usage

1. Enter a domain (or click **This tab**).
2. Choose sources under **Sources**.
3. Optionally open **Live capture** to monitor the active tab.
4. Start scan, filter results, and export.

## Notes

- Passive sources are free/public and may rate-limit.
- Deep capture attaches the Chrome debugger and shows a browser warning bar.
- HTTP probing uses `no-cors`, so some responses appear as `OPAQUE`.
- Only scan domains you own or are authorized to assess.

## License

MIT
