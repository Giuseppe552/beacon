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
        issues.push("no HttpOnly flag — JavaScript can read this cookie (XSS data theft)");
      }
      if (!lower.includes("secure")) {
        issues.push("no Secure flag — cookie sent over unencrypted HTTP");
      }
      if (!lower.includes("samesite")) {
        issues.push("no SameSite attribute — vulnerable to CSRF attacks");
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
            ? "Session cookie without proper flags. An XSS vulnerability or network attacker can steal the user's session."
            : "Cookie missing security flags. May leak data or enable cross-site attacks.",
          remediation: "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on all cookies.",
        });
      }
    }

    return findings;
  },
};
