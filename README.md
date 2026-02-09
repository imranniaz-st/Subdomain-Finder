# Subdomain Finder Professional

A professional Chrome extension for discovering subdomains using open-source methods and export options. By BICODEV. Use responsibly.

## Features

- Passive discovery via certificate transparency (crt.sh)
- Passive DNS discovery via dns.bufferover.run
- Optional active wordlist expansion
- DNS resolution validation over DoH
- Optional HTTP status probing
- Concurrency and rate limiting controls
- Export to JSON/CSV and copy to clipboard

## Install (Developer Mode)

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select this folder.

## Usage

1. Enter a domain like `example.com`.
2. Choose discovery methods and validations.
3. Adjust concurrency, delay, and timeout.
4. Start scan and export results.

## SEO Use Cases

- Discover hidden subdomains that may host content competing with or diluting rankings.
- Find legacy or staging hosts that can create duplicate content or index bloat.
- Identify regional or product subdomains for localization and content mapping.
- Detect subdomains that should be consolidated or redirected for authority.

## SEO Workflow (Quick Start)

1. Run a passive scan first (crt.sh + passive DNS).
2. Export results to CSV.
3. Filter by response and DNS status.
4. Prioritize high value subdomains for audit and redirects.

For deeper guidance, see SEO documentation in [SEO_GUIDE.md](SEO_GUIDE.md).

## Data Sources

- https://crt.sh (Certificate Transparency search)
- https://dns.bufferover.run (Passive DNS)
- https://dns.google (DNS-over-HTTPS for validation)

## Notes

- Passive sources are used by default.
- Active checks (DNS/HTTP) can be disabled.
- HTTP probing uses `no-cors`, so some responses appear as `OPAQUE`.

## Responsible Use

- Only scan domains you own or are authorized to assess.
- Passive methods are safer for SEO research and compliance.
- Keep concurrency conservative to avoid rate limiting.

## License

MIT
