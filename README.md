# beacon

[![CI](https://github.com/Giuseppe552/beacon/actions/workflows/ci.yml/badge.svg)](https://github.com/Giuseppe552/beacon/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-50_passing-brightgreen)](https://github.com/Giuseppe552/beacon)
[![Breaches](https://img.shields.io/badge/breach_precedents-100-blue)](https://github.com/Giuseppe552/beacon)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

Business security surface scanner. Checks TLS, HTTP headers, DNS email authentication, exposed paths, third-party tracking, form security, and cookie flags. Maps every finding to a real breach where the same weakness was exploited.

## What it does

Point it at a domain. It tells you what's wrong and what happened last time someone had the same problem.

```
$ beacon example.com

  D  example.com  2026-03-23T01:24:42Z  2656ms

  2 high  2 medium  1 low  1 info  (6 total)

  HIGH
  ▸ No SPF record
    No v=spf1 TXT record found. Anyone can send email as this domain.
    ⚡ Precedent: UK solicitor invoice fraud (2022–2024) — Multiple UK
    law firms lost client funds when attackers sent invoices from
    spoofed firm email addresses. £150M+ lost across UK legal sector.
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

# Verbose (show progress)
npx tsx src/cli.ts example.com -v

# JSON output
npx tsx src/cli.ts example.com --json > report.json
```

## Scanners

| Scanner | What it checks |
|---------|---------------|
| **TLS/SSL** | Protocol version, cipher suite, certificate validity, HSTS |
| **HTTP Headers** | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **DNS & Email** | SPF, DKIM (18 selectors), DMARC policy, DNSSEC |
| **Exposed Paths** | .env, .git, admin panels, database dumps, phpinfo, debug endpoints (25 paths) |
| **Third-Party** | Tracker detection (GA, Hotjar, Facebook Pixel, etc.), SRI validation, external domain count |
| **Forms** | Google Forms, WhatsApp links, HTTP form actions, file upload security |
| **Cookies** | HttpOnly, Secure, SameSite flags on session and tracking cookies |

## Grading

Each category and the overall scan gets a letter grade (A–F). Grades are computed from finding severity:

| Severity | Weight |
|----------|--------|
| Critical | -40 |
| High | -20 |
| Medium | -8 |
| Low | -2 |
| Info | 0 |

Starting from 100: A (90+), B (75+), C (55+), D (35+), F (<35).

## Breach precedents

Findings are matched to real incidents. 15 documented breaches including:
- Orrick, Herrington & Sutcliffe (2023) — 637,620 records, $8M settlement
- British Airways Magecart (2018) — 380,000 cards, £20M ICO fine
- Fragomen (2020) — I-9 verification files with passport and SSN data
- Retool (2023) — email spoofing led to 27 customer accounts compromised
- Twitch (2021) — exposed configuration led to 125GB source code leak

## Exit codes

- `0` — no critical or high findings
- `1` — high-severity findings present
- `2` — critical findings present

## Tests

```
npm test
```

44 tests covering grading logic, header analysis, form detection, tracker identification, cookie validation, path validators, and precedent data integrity.

## Legal

beacon checks publicly visible information: HTTP headers, DNS records, TLS certificates, and standard HTTP paths. It does not attempt authentication bypass, payload injection, or any form of exploitation. All requests are standard GET/HEAD with an identifying User-Agent.

## Limitations

- Third-party detection is based on HTML source only. Scripts loaded dynamically after page render (e.g., via Google Tag Manager) are not detected.
- DKIM selector enumeration checks 18 common selectors. Custom selectors will be missed.
- Path checking may produce false negatives on sites with aggressive WAFs that block HEAD requests.
- Cookie analysis only covers cookies set on the initial page load.

## License

MIT
