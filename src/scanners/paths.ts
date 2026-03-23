import type { Finding, Scanner } from "../types.js";
import { EXPOSED_PATHS } from "../data/paths.js";
import { getPrecedent } from "../data/precedents.js";

const MAX_CONCURRENT = 5;
const TIMEOUT_MS = 6000;

/** Check for exposed files and paths that shouldn't be public. */
export const pathsScanner: Scanner = {
  name: "Exposed Paths",
  category: "exposed-paths",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    const base = ctx.url;

    // Process in batches to avoid hammering the server
    for (let i = 0; i < EXPOSED_PATHS.length; i += MAX_CONCURRENT) {
      const batch = EXPOSED_PATHS.slice(i, i + MAX_CONCURRENT);
      const results = await Promise.allSettled(
        batch.map((ep) => checkPath(base, ep)),
      );
      for (const r of results) {
        if (r.status === "fulfilled" && r.value) {
          findings.push(r.value);
        }
      }
    }

    // security.txt presence (positive signal)
    const secTxt = findings.find((f) => f.id === "paths-security-txt-present");
    if (!secTxt) {
      const hasSecTxt = findings.some(
        (f) => f.id === "paths-well-known-security-txt",
      );
      if (!hasSecTxt) {
        findings.push({
          id: "paths-no-security-txt",
          category: "exposed-paths",
          severity: "info",
          title: "No security.txt",
          detail: "No /.well-known/security.txt found (RFC 9116).",
          risk: "Security researchers who find vulnerabilities have no way to report them responsibly.",
          remediation: "Create a security.txt with at least a Contact field.",
        });
      }
    }

    return findings;
  },
};

async function checkPath(
  baseUrl: string,
  ep: (typeof EXPOSED_PATHS)[number],
): Promise<Finding | null> {
  try {
    const url = `${baseUrl}${ep.path}`;

    // Use GET for paths that need body validation, HEAD for others
    const needsBody = !!ep.validate;
    const res = await fetch(url, {
      method: needsBody ? "GET" : "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; beacon-scanner/0.1; +https://giuseppegiona.com/projects/beacon)",
      },
    });

    if (res.status !== 200) return null;

    // If we have a validator, check the body to avoid SPA false positives
    if (ep.validate) {
      const body = await res.text();
      const ct = res.headers.get("content-type") ?? "";
      if (!ep.validate(body, ct)) return null;
    }

    // security.txt is a positive finding, not a vulnerability
    if (ep.path === "/.well-known/security.txt") {
      return {
        id: "paths-security-txt-present",
        category: "exposed-paths",
        severity: "info",
        title: "security.txt found",
        detail: "The site has a security contact published at /.well-known/security.txt.",
        risk: "Positive signal — responsible disclosure is possible.",
      };
    }

    const findingId = `paths-${ep.path.replace(/[^a-z0-9]/g, "-").replace(/^-+|-+$/g, "")}`;
    const precedent = getPrecedent(findingId);

    return {
      id: findingId,
      category: "exposed-paths",
      severity: ep.severity,
      title: `Exposed: ${ep.name}`,
      detail: `${ep.path} returned HTTP 200.`,
      risk: ep.risk,
      precedent,
      remediation: `Block access to ${ep.path} via server configuration or .htaccess rules.`,
    };
  } catch {
    return null;
  }
}
