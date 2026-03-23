import { describe, it, expect } from "vitest";
import { cookiesScanner } from "./cookies.js";
import type { ScanContext } from "../types.js";

function ctx(setCookie: string): ScanContext {
  return {
    domain: "test.com",
    url: "https://test.com",
    html: "",
    headers: { "set-cookie": setCookie },
    statusCode: 200,
    httpsRedirect: true,
  };
}

describe("cookiesScanner", () => {
  it("flags session cookie without HttpOnly", async () => {
    const findings = await cookiesScanner.scan(ctx("session_id=abc123; Path=/; Secure; SameSite=Strict"));
    const f = findings.find((f) => f.id.includes("session"));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high");
    expect(f!.detail).toContain("HttpOnly");
  });

  it("flags cookie without Secure flag", async () => {
    const findings = await cookiesScanner.scan(ctx("prefs=dark; Path=/; HttpOnly; SameSite=Lax"));
    const f = findings.find((f) => f.detail.includes("Secure"));
    expect(f).toBeDefined();
  });

  it("flags cookie without SameSite", async () => {
    const findings = await cookiesScanner.scan(ctx("token=xyz; Path=/; HttpOnly; Secure"));
    const f = findings.find((f) => f.detail.includes("SameSite"));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high"); // token is a session cookie
  });

  it("passes for fully secure cookie", async () => {
    const findings = await cookiesScanner.scan(
      ctx("prefs=dark; Path=/; HttpOnly; Secure; SameSite=Strict"),
    );
    expect(findings).toHaveLength(0);
  });

  it("returns nothing when no cookies set", async () => {
    const findings = await cookiesScanner.scan({
      domain: "test.com",
      url: "https://test.com",
      html: "",
      headers: {},
      statusCode: 200,
      httpsRedirect: true,
    });
    expect(findings).toHaveLength(0);
  });
});
