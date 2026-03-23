import { describe, it, expect } from "vitest";
import { headersScanner } from "./headers.js";
import type { ScanContext } from "../types.js";

function ctx(headers: Record<string, string>): ScanContext {
  return {
    domain: "test.com",
    url: "https://test.com",
    html: "<html></html>",
    headers,
    statusCode: 200,
    httpsRedirect: true,
  };
}

describe("headersScanner", () => {
  it("flags missing CSP", async () => {
    const findings = await headersScanner.scan(ctx({}));
    const csp = findings.find((f) => f.id === "headers-no-csp");
    expect(csp).toBeDefined();
    expect(csp!.severity).toBe("high");
    expect(csp!.precedent).toBeDefined();
  });

  it("passes when all headers present", async () => {
    const findings = await headersScanner.scan(
      ctx({
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
      }),
    );
    // Should have no high/medium findings
    const serious = findings.filter(
      (f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium",
    );
    expect(serious).toHaveLength(0);
  });

  it("flags unsafe-inline in CSP", async () => {
    const findings = await headersScanner.scan(
      ctx({
        "content-security-policy": "script-src 'self' 'unsafe-inline'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
      }),
    );
    const ui = findings.find((f) => f.id === "headers-csp-unsafe-inline");
    expect(ui).toBeDefined();
    expect(ui!.severity).toBe("medium");
  });

  it("flags server version disclosure", async () => {
    const findings = await headersScanner.scan(
      ctx({
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        server: "Apache/2.4.51",
      }),
    );
    const sv = findings.find((f) => f.id === "headers-server-version");
    expect(sv).toBeDefined();
    expect(sv!.title).toContain("Apache/2.4.51");
  });

  it("flags X-Powered-By", async () => {
    const findings = await headersScanner.scan(
      ctx({
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-powered-by": "Express",
      }),
    );
    const xp = findings.find((f) => f.id === "headers-x-powered-by");
    expect(xp).toBeDefined();
  });

  it("accepts frame-ancestors CSP as clickjacking protection", async () => {
    const findings = await headersScanner.scan(
      ctx({
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
      }),
    );
    const frame = findings.find((f) => f.id === "headers-no-frame-protection");
    expect(frame).toBeUndefined();
  });
});
