import type { Finding, Scanner } from "../types.js";

/** Analyse cookie security flags from Set-Cookie headers. */
export const cookiesScanner: Scanner = {
  name: "Cookie Security",
  category: "cookies",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    const raw = ctx.headers["set-cookie"];
    if (!raw) return findings;

    // set-cookie may be a single string with multiple cookies joined
    // or the raw header may appear once. We split on common delimiters.
    const cookies = raw.split(/,(?=[^ ])/);

    for (const cookie of cookies) {
      const name = cookie.split("=")[0]?.trim();
      if (!name) continue;

      const lower = cookie.toLowerCase();
      const issues: string[] = [];

      if (!lower.includes("httponly")) {
        issues.push("no HttpOnly flag — any script on the page can read this cookie");
      }
      if (!lower.includes("secure")) {
        issues.push("no Secure flag — cookie transmitted in the clear over unencrypted connections");
      }
      if (!lower.includes("samesite")) {
        issues.push("no SameSite attribute — other websites can trigger requests that carry this cookie");
      }

      if (issues.length > 0) {
        // Session cookies are higher severity
        const isSession =
          /sess|token|auth|login|jwt|sid/i.test(name);
        findings.push({
          id: `cookies-insecure-${name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`,
          category: "cookies",
          severity: isSession ? "high" : "medium",
          title: `Insecure cookie: ${name}`,
          detail: issues.join("; "),
          risk: isSession
            ? "This cookie controls who is logged in. Without these flags, an attacker who gets a script onto your page — or who is on the same WiFi — can copy this cookie and log in as your user. They see everything that user sees: account details, documents, messages."
            : "This cookie is missing standard security flags. It can be read by scripts on the page or transmitted over unencrypted connections, potentially leaking information about your visitors.",
          remediation: "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on all cookies.",
        });
      }
    }

    return findings;
  },
};
