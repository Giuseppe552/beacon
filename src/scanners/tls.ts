import * as tls from "node:tls";
import type { Finding, Scanner, ScanContext } from "../types.js";
import { getPrecedent } from "../data/precedents.js";

/** Inspect TLS configuration: protocol, cipher, certificate chain. */
export const tlsScanner: Scanner = {
  name: "TLS/SSL",
  category: "tls",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    const host = ctx.domain;

    // Connect and inspect
    const info = await inspectTls(host);
    if (!info) {
      findings.push({
        id: "tls-connection-failed",
        category: "tls",
        severity: "critical",
        title: "TLS connection failed",
        detail: `Could not establish a TLS connection to ${host}:443.`,
        risk: "The site may not support HTTPS at all, or the certificate is invalid. All data transmitted in plaintext.",
      });
      return findings;
    }

    // Protocol version
    if (info.protocol === "TLSv1" || info.protocol === "TLSv1.1") {
      findings.push({
        id: "tls-outdated-protocol",
        category: "tls",
        severity: "high",
        title: `Outdated TLS protocol: ${info.protocol}`,
        detail: `Server negotiated ${info.protocol}, which has known cryptographic weaknesses (BEAST, POODLE).`,
        risk: "Attackers on the same network can decrypt traffic. PCI DSS banned TLS 1.0 in 2018.",
        precedent: getPrecedent("tls-outdated-protocol"),
        remediation: "Configure the server to accept only TLS 1.2 and 1.3.",
      });
    }

    if (info.protocol !== "TLSv1.3") {
      findings.push({
        id: "tls-no-1.3",
        category: "tls",
        severity: "low",
        title: "TLS 1.3 not negotiated",
        detail: `Server negotiated ${info.protocol} instead of TLS 1.3.`,
        risk: "TLS 1.3 is faster and more secure. Missing it isn't critical but indicates the server config hasn't been updated recently.",
      });
    }

    // Certificate validity
    if (!info.authorized) {
      findings.push({
        id: "tls-cert-invalid",
        category: "tls",
        severity: "critical",
        title: "Invalid TLS certificate",
        detail: `Certificate validation failed: ${info.authError ?? "unknown error"}.`,
        risk: "Browsers show a security warning. Users who click through are vulnerable to man-in-the-middle attacks.",
      });
    }

    if (info.certExpiry) {
      const daysLeft = Math.floor(
        (info.certExpiry.getTime() - Date.now()) / 86400000,
      );
      if (daysLeft < 0) {
        findings.push({
          id: "tls-cert-expired",
          category: "tls",
          severity: "critical",
          title: "TLS certificate expired",
          detail: `Certificate expired ${Math.abs(daysLeft)} days ago.`,
          risk: "Browsers block access. Users cannot reach the site securely.",
        });
      } else if (daysLeft < 14) {
        findings.push({
          id: "tls-cert-expiring",
          category: "tls",
          severity: "medium",
          title: `TLS certificate expires in ${daysLeft} days`,
          detail: "Certificate is close to expiry and may not auto-renew.",
          risk: "If renewal fails, the site becomes unreachable.",
          remediation: "Verify auto-renewal is configured (Let's Encrypt, Cloudflare, etc.).",
        });
      }
    }

    // HSTS
    const hsts = ctx.headers["strict-transport-security"];
    if (!hsts) {
      findings.push({
        id: "tls-no-hsts",
        category: "tls",
        severity: "high",
        title: "No HSTS header",
        detail: "Strict-Transport-Security header is missing.",
        risk: "First visit to the site can be intercepted on public WiFi before the HTTPS redirect. Session cookies and form data exposed.",
        precedent: getPrecedent("tls-no-hsts"),
        remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      });
    } else {
      const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] ?? "0", 10);
      if (maxAge < 31536000) {
        findings.push({
          id: "tls-hsts-short",
          category: "tls",
          severity: "low",
          title: "HSTS max-age is short",
          detail: `max-age=${maxAge} (${Math.floor(maxAge / 86400)} days). Recommended: 31536000 (1 year).`,
          risk: "Short HSTS windows leave gaps where downgrade attacks are possible.",
        });
      }
      if (!hsts.includes("includeSubDomains")) {
        findings.push({
          id: "tls-hsts-no-subdomains",
          category: "tls",
          severity: "low",
          title: "HSTS does not include subdomains",
          detail: "includeSubDomains directive is missing from HSTS header.",
          risk: "Subdomains (mail.example.com, admin.example.com) are not protected by HSTS.",
        });
      }
    }

    // HTTP to HTTPS redirect
    if (!ctx.httpsRedirect) {
      findings.push({
        id: "tls-no-http-redirect",
        category: "tls",
        severity: "medium",
        title: "HTTP does not redirect to HTTPS",
        detail: "Port 80 does not redirect to port 443.",
        risk: "Users who type the domain without https:// get an unencrypted connection.",
        remediation: "Add a 301 redirect from HTTP to HTTPS.",
      });
    }

    return findings;
  },
};

type TlsInfo = {
  protocol: string;
  cipher: string;
  authorized: boolean;
  authError?: string;
  certExpiry?: Date;
  certSubject?: string;
};

function inspectTls(host: string): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    const sock = tls.connect(443, host, { servername: host, timeout: 8000 }, () => {
      const info: TlsInfo = {
        protocol: sock.getProtocol() ?? "unknown",
        cipher: sock.getCipher()?.standardName ?? sock.getCipher()?.name ?? "unknown",
        authorized: sock.authorized,
        authError: sock.authorizationError
          ? String(sock.authorizationError)
          : undefined,
      };
      const cert = sock.getPeerCertificate();
      if (cert?.valid_to) {
        info.certExpiry = new Date(cert.valid_to);
      }
      if (cert?.subject?.CN) {
        const cn = cert.subject.CN;
        info.certSubject = Array.isArray(cn) ? cn[0] : cn;
      }
      sock.end();
      resolve(info);
    });
    sock.on("error", () => resolve(null));
    sock.on("timeout", () => {
      sock.destroy();
      resolve(null);
    });
  });
}
