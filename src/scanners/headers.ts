import type { Finding, Scanner } from "../types.js";
import { getPrecedent } from "../data/precedents.js";

/** Check HTTP security headers. */
export const headersScanner: Scanner = {
  name: "HTTP Security Headers",
  category: "headers",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    const h = ctx.headers;

    // Content-Security-Policy
    if (!h["content-security-policy"]) {
      findings.push({
        id: "headers-no-csp",
        category: "headers",
        severity: "high",
        title: "No Content-Security-Policy",
        detail: "CSP header is missing. The browser has no restrictions on which scripts can execute.",
        risk: "A single injected script (XSS, compromised CDN, malicious ad) can steal every piece of data on the page — form inputs, session tokens, document uploads.",
        precedent: getPrecedent("headers-no-csp"),
        remediation: "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'",
      });
    } else {
      const csp = h["content-security-policy"];
      if (csp.includes("'unsafe-inline'") && csp.includes("script-src")) {
        findings.push({
          id: "headers-csp-unsafe-inline",
          category: "headers",
          severity: "medium",
          title: "CSP allows unsafe-inline scripts",
          detail: "script-src includes 'unsafe-inline', which negates most XSS protection.",
          risk: "If someone injects malicious code into your website, this weakness means they can steal everything your clients type into forms — names, addresses, payment details, uploaded documents. Your site has a security policy but this exception makes it ineffective.",
          precedent: getPrecedent("headers-csp-unsafe-inline"),
          remediation: "Remove 'unsafe-inline' from script-src and use nonces or hashes instead. A web developer can implement this in 1-2 hours.",
        });
      }
      if (csp.includes("'unsafe-eval'")) {
        findings.push({
          id: "headers-csp-unsafe-eval",
          category: "headers",
          severity: "medium",
          title: "CSP allows unsafe-eval",
          detail: "CSP includes 'unsafe-eval', permitting dynamic code execution via string-to-code functions.",
          risk: "An attacker who finds a way to inject code into your site can run any programme they want inside your visitors' browsers. This makes data theft, session hijacking, and keylogging possible.",
          precedent: getPrecedent("headers-csp-unsafe-eval"),
          remediation: "Remove 'unsafe-eval' from your Content-Security-Policy. If your site breaks, ask your developer which scripts depend on it and replace them.",
        });
      }
    }

    // X-Frame-Options
    if (!h["x-frame-options"] && !cspHasFrameAncestors(h["content-security-policy"])) {
      findings.push({
        id: "headers-no-frame-protection",
        category: "headers",
        severity: "medium",
        title: "No clickjacking protection",
        detail: "Neither X-Frame-Options nor CSP frame-ancestors is set.",
        risk: "An attacker can embed your site inside their own page invisibly. Your clients think they're clicking buttons on your site while actually authorising actions on the attacker's page — transferring money, changing passwords, submitting documents.",
        precedent: getPrecedent("headers-no-frame-protection"),
        remediation: "Add X-Frame-Options: DENY or frame-ancestors 'none' to your CSP. This is a one-line server configuration change.",
      });
    }

    // X-Content-Type-Options
    if (h["x-content-type-options"] !== "nosniff") {
      findings.push({
        id: "headers-no-nosniff",
        category: "headers",
        severity: "low",
        title: "Missing X-Content-Type-Options: nosniff",
        detail: "Browser may interpret uploaded files as executable content.",
        risk: "Uploaded files (PDFs, images) could be misinterpreted as executable code by the browser. An attacker who uploads a malicious file could trick the browser into running it as a script.",
        precedent: getPrecedent("headers-no-nosniff"),
        remediation: "Add X-Content-Type-Options: nosniff to your server headers. One-line configuration change.",
      });
    }

    // Referrer-Policy
    if (!h["referrer-policy"]) {
      findings.push({
        id: "headers-no-referrer-policy",
        category: "headers",
        severity: "low",
        title: "No Referrer-Policy",
        detail: "Browser default referrer behaviour sends the full URL (including query params) to external sites.",
        risk: "Every time someone clicks a link on your site that goes to another website, the full page URL they were on is sent to that other site. If your URLs contain client names, reference numbers, or internal paths, those leak to every external link and third-party script on the page.",
        precedent: getPrecedent("headers-no-referrer-policy"),
        remediation: "Add Referrer-Policy: strict-origin-when-cross-origin to your server headers. Stops URLs leaking while keeping basic referrer data for analytics.",
      });
    }

    // Permissions-Policy
    if (!h["permissions-policy"]) {
      findings.push({
        id: "headers-no-permissions-policy",
        category: "headers",
        severity: "low",
        title: "No Permissions-Policy",
        detail: "Browser features (camera, microphone, geolocation) are not explicitly restricted.",
        risk: "Without this header, a compromised page could silently activate a visitor's camera, microphone, or GPS. The browser allows these by default unless you explicitly block them.",
        precedent: getPrecedent("headers-no-permissions-policy"),
        remediation: "Add Permissions-Policy: camera=(), microphone=(), geolocation=() to your server headers. Blocks device access even if the site is compromised.",
      });
    }

    // Server version disclosure
    const server = h["server"];
    if (server && /\d+\.\d+/.test(server)) {
      findings.push({
        id: "headers-server-version",
        category: "information-disclosure",
        severity: "low",
        title: `Server version disclosed: ${server}`,
        detail: "The Server header includes a version number.",
        risk: "Attackers can look up every known vulnerability for this exact software version and attempt them all. It's like leaving your house key brand visible — it tells a burglar exactly which tools to bring.",
        precedent: getPrecedent("headers-server-version"),
        remediation: "Configure your server to hide the version number. Usually one line in the server config.",
      });
    }

    // X-Powered-By
    if (h["x-powered-by"]) {
      findings.push({
        id: "headers-x-powered-by",
        category: "information-disclosure",
        severity: "low",
        title: `Technology disclosed: X-Powered-By: ${h["x-powered-by"]}`,
        detail: "Framework/runtime version exposed via header.",
        risk: "Tells attackers exactly which technology stack your site runs on, letting them search for known exploits specific to that framework. Unnecessary information that only helps an attacker.",
        precedent: getPrecedent("headers-x-powered-by"),
        remediation: "Remove the X-Powered-By header from your server configuration.",
      });
    }

    return findings;
  },
};

function cspHasFrameAncestors(csp?: string): boolean {
  if (!csp) return false;
  return csp.includes("frame-ancestors");
}
