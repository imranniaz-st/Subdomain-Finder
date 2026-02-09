# SEO Guide for Subdomain Finder Professional

This guide shows how to use the extension for SEO research, content governance, and technical audits. It focuses on lawful, passive discovery and safe validation.

## When to Use It

- Site audits and migration prep
- Detecting duplicate or thin content across subdomains
- Mapping local or product subdomains
- Monitoring brand and property sprawl

## Typical SEO Questions Answered

- Which subdomains are live and should be indexed?
- Are there forgotten hosts with legacy content?
- Are staging or dev subdomains exposed to search?
- Which hosts should be consolidated or redirected?

## Recommended Workflow

1. Start with passive sources only.
2. Export CSV and sort by subdomain pattern.
3. Validate DNS and HTTP to confirm live hosts.
4. Audit indexability and content quality per host.
5. Build a consolidation or redirect plan.

## Interpreting Results

- DNS OK + HTTP OK: likely active and reachable.
- DNS OK + HTTP OPAQUE: reachable but response is blocked by browser policy.
- DNS OK + HTTP empty: likely live but not responding on HTTPS.
- DNS NO + HTTP empty: likely inactive or misconfigured.

## Export Formats

### CSV Columns

- subdomain
- dns
- http
- source

### JSON Structure

- generatedAt
- domain
- results (array of rows)

## SEO Use Cases and Actions

### Duplicate Content Control

- Find legacy or promotional subdomains.
- Decide on noindex, redirects, or consolidation.
- Align canonical strategy for overlapping content.

### Crawl Budget Optimization

- Identify low value hosts.
- Reduce accessible but unused subdomains.
- Ensure robots and redirects are consistent.

### Brand and Market Mapping

- Map country or language subdomains.
- Detect off-brand or obsolete subdomains.
- Standardize naming for SEO clarity.

## Best Practices

- Keep concurrency low when validating (8 to 12).
- Use delay to avoid remote rate limits.
- Validate only on domains you are authorized to test.

## Limitations

- HTTP checks use no-cors and may show OPAQUE.
- Passive sources do not guarantee completeness.
- Some live hosts may block or rate limit probes.

## Compliance and Safety

- Only use for authorized domains.
- Respect robots and legal constraints.
- Document findings and decisions for audit trails.

## Example Output Review

1. Export CSV.
2. Filter for prod, api, shop, or region codes.
3. Verify indexability and content relevance.
4. Plan redirects and canonical updates.

## Glossary

- Passive discovery: uses public sources without direct scanning.
- DoH: DNS-over-HTTPS validation for DNS records.
- OPAQUE: response blocked by browser CORS policy.
