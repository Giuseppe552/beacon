# beacon

[![CI](https://github.com/Giuseppe552/beacon/actions/workflows/ci.yml/badge.svg)](https://github.com/Giuseppe552/beacon/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-65_passing-brightgreen)](https://github.com/Giuseppe552/beacon)
[![Breaches](https://img.shields.io/badge/breach_precedents-115-blue)](https://github.com/Giuseppe552/beacon)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

Business security surface scanner. Checks TLS, HTTP headers, DNS email authentication, exposed paths, third-party tracking, form security, and cookie flags. Maps every finding to a real breach where the same weakness was exploited.

## What it does

Point it at a domain. It tells you what's wrong and what happened last time someone had the same problem.

```
$ beacon resinaro.com --industry immigration

  beacon  v0.2.0
  target  resinaro.com
  industry  Immigration Agency

  B   resinaro.com

  Reasonable
  Your site has a solid foundation but there are gaps. The issues found
  are the kind that professional attackers scan for — they're not
  theoretical, they're the first things checked.

  2 medium  ·  1 low  ·  1 info  (4 findings)

  ─── Priority fix ───

  ▸  No DKIM record found
     Configure DKIM signing with your email provider and publish the
     public key in DNS.
```

Every finding includes:
- **What we found** (technical detail)
- **What it means** (business risk in plain English)
- **What happened before** (real breach with the same weakness, cited)
- **How to fix it**

## Install

```
git clone https://github.com/Giuseppe552/beacon.git
cd beacon
npm install
```

## Usage

```bash
# Scan a domain
npx tsx src/cli.ts example.com

# Scan with industry context (adjusts severity and risk text)
npx tsx src/cli.ts example.com --industry immigration

# Other industries: law, accounting, healthcare, general
npx tsx src/cli.ts example.com --industry law

# Verbose (show progress)
npx tsx src/cli.ts example.com -v

# JSON output
npx tsx src/cli.ts example.com --json > report.json
```

## Web app

The `web/` directory contains a Next.js app that wraps the scanning engine with a browser UI. Landing page, scan form, shareable report URLs.

```bash
cd web
npm install
npm run dev
```

Deployed at [beacon.giuseppegiona.com](https://beacon.giuseppegiona.com).

## Scanners

| Scanner | What it checks |
|---------|---------------|
| **TLS/SSL** | Protocol version, cipher suite, certificate validity, HSTS |
| **HTTP Headers** | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, version disclosure |
| **DNS & Email** | SPF, DKIM (18 selectors), DMARC policy, DNSSEC |
| **Exposed Paths** | .env, .git, admin panels, database dumps, phpinfo, debug endpoints (25 paths with false-positive validators) |
| **Third-Party** | 20+ tracker detection (GA, Hotjar, FullStory, Facebook Pixel, Clarity, etc.), SRI validation, external domain mapping |
| **Forms** | Google Forms, WhatsApp links, HTTP form actions, file upload security, sensitive field detection |
| **Cookies** | HttpOnly, Secure, SameSite flags on session and tracking cookies |

## Industry context

The `--industry` flag adjusts severity levels and risk text for specific business types.

| Industry | What changes |
|----------|-------------|
| `immigration` | No DMARC → critical. Session recording → critical. Google Forms → critical. Risk text mentions passport data, GDPR Art 32, £150M invoice fraud. |
| `law` | No DMARC → critical. Risk text references DPP Law, Tuckers Solicitors, wire transfer fraud. |
| `accounting` | No DMARC → critical. Exposed .env → critical. Risk text mentions tax returns, SSNs, client financial data. |
| `healthcare` | Session recording → critical. Google Forms → critical. Risk text mentions patient records. |
| `general` | No adjustments. Default severity levels. |

Without `--industry`, the scan runs with general severity levels.

## Grading

Each category and the overall scan gets a letter grade (A–F). Starts at 100, deducts by severity:

| Severity | Weight |
|----------|--------|
| Critical | −40 |
| High | −20 |
| Medium | −8 |
| Low | −2 |
| Info | 0 |

Thresholds: A (90+), B (75+), C (55+), D (35+), F (<35).

Two hard rules override the score:
- **Any critical finding = automatic F.** A site with one critical and perfect everything else is not a C.
- **Two or more high findings = cap at D.** Multiple serious issues aren't masked by a clean baseline.

With `--industry`, some findings get bumped to higher severity before grading. No DMARC on a general site is high (−20). No DMARC on an immigration agency is critical (automatic F).

## Breach precedents

115 documented incidents across 21 vulnerability categories. Every entry has a source URL (ICO, FTC, FBI IC3, court filings, peer-reviewed research). Examples:

- DPP Law (2022) — 32.4GB client data on dark web, £60k ICO fine
- British Airways (2018) — 380,000 cards stolen, £20M ICO fine
- Orion S.A. (2024) — $60M in fraudulent wire transfers (BEC)
- Tuckers Solicitors (2020) — 972k files encrypted, first ICO ransomware fine
- Twitch (2021) — 125GB source code leaked via exposed config
- UK solicitor invoice fraud (2022–2024) — £150M+ lost across the legal sector
- FBI IC3 BEC report — $55 billion cumulative losses (2013–2023)

Three entries include victim quotes for human-impact context.

## Exit codes

- `0` — no critical or high findings
- `1` — high-severity findings present
- `2` — critical findings present

## Tests

```
npm test
```

65 tests across 8 test files: grading logic (including floor rules), header analysis, form detection, tracker identification, cookie validation, path validators, precedent data integrity, and industry profiles.

## Legal

beacon checks publicly visible information: HTTP headers, DNS records, TLS certificates, and standard HTTP paths. It does not attempt authentication bypass, payload injection, or any form of exploitation. All requests are standard GET/HEAD with an identifying User-Agent.

## Limitations

- This is passive analysis. A clean scan does not mean the site is secure.
- Third-party detection is based on initial HTML only. Scripts loaded via Google Tag Manager are not detected.
- DKIM selector enumeration checks 18 common selectors. Custom selectors will be missed.
- Path checking may produce false negatives on sites with aggressive WAFs that block HEAD requests.
- Cookie analysis only covers cookies set on the initial page load.
- The breach precedent database is manually curated and will always be incomplete.

## License

MIT
