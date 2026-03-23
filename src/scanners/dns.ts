import * as dns from "node:dns/promises";
import { execFile } from "node:child_process";
import type { Finding, Scanner } from "../types.js";
import { getPrecedent } from "../data/precedents.js";

const COMMON_DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2",
  "k1", "k2", "s1", "s2", "dkim", "mail", "smtp",
  "20230601", "20210112", "mandrill", "mailchimp",
  "ses", "protonmail", "pm",
];

/** Check DNS security: SPF, DKIM, DMARC, DNSSEC. */
export const dnsScanner: Scanner = {
  name: "DNS & Email Security",
  category: "dns",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    // SPF, DKIM, DMARC are always on the root domain, not subdomains.
    // Strip www (or any subdomain) to check the right place.
    const parts = ctx.domain.split(".");
    const domain = parts.length > 2 ? parts.slice(-2).join(".") : ctx.domain;
    const resolver = new dns.Resolver();

    // --- SPF ---
    try {
      const txt = await resolver.resolveTxt(domain);
      const spfRecords = txt.flat().filter((r) => r.startsWith("v=spf1"));
      if (spfRecords.length === 0) {
        findings.push({
          id: "dns-no-spf",
          category: "dns",
          severity: "high",
          title: "No SPF record",
          detail: "No v=spf1 TXT record found. Anyone can send email as this domain.",
          risk: "Attackers send invoices, password resets, or document requests that appear to come from this company. Recipients have no way to tell the difference.",
          precedent: getPrecedent("dns-no-spf"),
          remediation: "Add a TXT record: v=spf1 include:<mail-provider> -all",
        });
      } else {
        const spf = spfRecords[0];
        if (spf.endsWith("~all")) {
          findings.push({
            id: "dns-spf-softfail",
            category: "dns",
            severity: "medium",
            title: "SPF uses ~all (softfail)",
            detail: `SPF record ends with ~all instead of -all. Emails from unauthorised senders are flagged but not rejected.`,
            risk: "Spoofed emails still land in inboxes — just with a warning that most users ignore.",
            precedent: getPrecedent("dns-no-spf"),
            remediation: "Change ~all to -all to hard-fail unauthorised senders.",
          });
        } else if (spf.endsWith("?all")) {
          findings.push({
            id: "dns-spf-neutral",
            category: "dns",
            severity: "high",
            title: "SPF uses ?all (neutral)",
            detail: "SPF record ends with ?all, which provides no protection at all.",
            risk: "Identical to having no SPF. Any server can send as this domain.",
            remediation: "Change ?all to -all.",
          });
        }
      }
    } catch {
      // No TXT records at all
      findings.push({
        id: "dns-no-txt",
        category: "dns",
        severity: "high",
        title: "No TXT records found",
        detail: "Could not resolve any TXT records for the domain. No SPF.",
        risk: "No email authentication. Anyone can impersonate this domain.",
      });
    }

    // --- DMARC ---
    try {
      const txt = await resolver.resolveTxt(`_dmarc.${domain}`);
      const dmarcRecords = txt.flat().filter((r) => r.startsWith("v=DMARC1"));
      if (dmarcRecords.length === 0) {
        findings.push({
          id: "dns-no-dmarc",
          category: "dns",
          severity: "high",
          title: "No DMARC record",
          detail: "No _dmarc TXT record found.",
          risk: "Without DMARC, anyone can send emails that look like they come from your domain. Clients receive invoices, password resets, or document requests they can't distinguish from real ones. This is how invoice fraud starts — and it caused $55 billion in global losses between 2013-2023.",
          precedent: getPrecedent("dns-no-dmarc"),
          remediation: "Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com. This tells email servers to reject spoofed messages.",
        });
      } else {
        const dmarc = dmarcRecords[0];
        const policy = dmarc.match(/;\s*p=(\w+)/)?.[1];
        if (policy === "none") {
          findings.push({
            id: "dns-dmarc-none",
            category: "dns",
            severity: "high",
            title: "DMARC policy is p=none",
            detail: "DMARC exists but policy is 'none' — failures are reported but emails are still delivered.",
            risk: "Your DMARC is set to monitor only — spoofed emails still land in your clients' inboxes. This is a common first step but it provides zero protection. Attackers sending fake invoices from your domain succeed just as easily as if DMARC didn't exist.",
            precedent: getPrecedent("dns-dmarc-none"),
            remediation: "Change p=none to p=reject in your _dmarc TXT record. This tells receiving servers to block spoofed emails instead of just logging them.",
          });
        } else if (policy === "quarantine") {
          findings.push({
            id: "dns-dmarc-quarantine",
            category: "dns",
            severity: "low",
            title: "DMARC policy is p=quarantine",
            detail: "Failed emails are sent to spam rather than rejected outright.",
            risk: "Better than none, but some users check spam folders. p=reject is stronger.",
          });
        }
        // p=reject is the ideal — no finding needed
      }
    } catch {
      findings.push({
        id: "dns-no-dmarc-record",
        category: "dns",
        severity: "high",
        title: "No DMARC record",
        detail: "Could not resolve _dmarc TXT record.",
        risk: "Without DMARC, anyone in the world can send emails that appear to come from your domain. Clients, partners, and staff have no way to tell the difference. This is the single most common technique used in invoice fraud — an attacker sends a payment instruction that looks exactly like it came from your company.",
        precedent: getPrecedent("dns-no-dmarc"),
        remediation: "Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com. This tells receiving email servers to reject emails that fail authentication checks.",
      });
    }

    // --- DKIM ---
    let dkimFound = false;
    for (const selector of COMMON_DKIM_SELECTORS) {
      try {
        const txt = await resolver.resolveTxt(`${selector}._domainkey.${domain}`);
        const flat = txt.flat().join("");
        if (flat.includes("v=DKIM1") || flat.includes("p=")) {
          dkimFound = true;
          // Check key strength
          const keyData = flat.match(/p=([A-Za-z0-9+/=]+)/)?.[1];
          if (keyData && keyData.length < 300) {
            findings.push({
              id: "dns-dkim-weak-key",
              category: "dns",
              severity: "medium",
              title: `DKIM key may be weak (selector: ${selector})`,
              detail: "DKIM public key appears to be 1024-bit or shorter. 2048-bit is recommended.",
              risk: "Short DKIM keys can be factored, allowing attackers to sign emails as this domain.",
              remediation: "Regenerate DKIM keys at 2048-bit minimum.",
            });
          }
          break;
        }
      } catch {
        // Selector not found — try next
      }
    }
    if (!dkimFound) {
      findings.push({
        id: "dns-no-dkim",
        category: "dns",
        severity: "medium",
        title: "No DKIM record found",
        detail: `Checked ${COMMON_DKIM_SELECTORS.length} common selectors — none returned a DKIM key.`,
        risk: "Without DKIM, receiving servers can't verify that emails were actually sent by this domain's mail server.",
        remediation: "Configure DKIM signing with your email provider and publish the public key in DNS.",
      });
    }

    // --- DNSSEC ---
    const dnssecValid = await checkDnssec(domain);
    if (!dnssecValid) {
      findings.push({
        id: "dns-no-dnssec",
        category: "dns",
        severity: "low",
        title: "DNSSEC not enabled",
        detail: "DNS responses are not cryptographically signed.",
        risk: "DNS responses can be forged (cache poisoning). An attacker could redirect the domain to a phishing site at the DNS level.",
        remediation: "Enable DNSSEC with your domain registrar.",
      });
    }

    return findings;
  },
};

/** Check DNSSEC by querying a validating resolver for the AD flag. */
function checkDnssec(domain: string): Promise<boolean> {
  return new Promise((resolve) => {
    execFile(
      "dig",
      ["+dnssec", "+noall", "+comments", `@8.8.8.8`, domain, "A"],
      { timeout: 8000 },
      (err, stdout) => {
        if (err) {
          resolve(false);
          return;
        }
        // AD flag = Authenticated Data (DNSSEC validated)
        resolve(/flags:.*\bad\b/.test(stdout));
      },
    );
  });
}
