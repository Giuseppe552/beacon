import { describe, it, expect } from "vitest";
import { formsScanner } from "./forms.js";
import type { ScanContext } from "../types.js";

function ctx(html: string): ScanContext {
  return {
    domain: "test.com",
    url: "https://test.com",
    html,
    headers: {},
    statusCode: 200,
    httpsRedirect: true,
  };
}

describe("formsScanner", () => {
  it("detects Google Forms links", async () => {
    const findings = await formsScanner.scan(
      ctx('<a href="https://docs.google.com/forms/d/abc123">Apply here</a>'),
    );
    const gf = findings.find((f) => f.id.includes("google-forms"));
    expect(gf).toBeDefined();
    expect(gf!.severity).toBe("high");
    expect(gf!.precedent).toBeDefined();
  });

  it("detects WhatsApp links", async () => {
    const findings = await formsScanner.scan(
      ctx('<a href="https://wa.me/447123456789">Chat on WhatsApp</a>'),
    );
    const wa = findings.find((f) => f.id.includes("whatsapp"));
    expect(wa).toBeDefined();
    expect(wa!.severity).toBe("high");
  });

  it("detects Typeform embeds", async () => {
    const findings = await formsScanner.scan(
      ctx('<iframe src="https://form.typeform.com/to/abc123"></iframe>'),
    );
    const tf = findings.find((f) => f.id.includes("typeform"));
    expect(tf).toBeDefined();
  });

  it("flags forms submitting over HTTP", async () => {
    const findings = await formsScanner.scan(
      ctx('<form action="http://insecure.com/submit" method="POST"><input name="passport" /></form>'),
    );
    const http = findings.find((f) => f.id === "forms-http-action");
    expect(http).toBeDefined();
    expect(http!.severity).toBe("critical");
  });

  it("flags GET forms with multiple fields", async () => {
    const findings = await formsScanner.scan(
      ctx(`<form method="GET" action="/search">
        <input name="name" />
        <input name="email" />
        <input name="phone" />
      </form>`),
    );
    const get = findings.find((f) => f.id === "forms-get-method");
    expect(get).toBeDefined();
  });

  it("returns no findings for clean HTML", async () => {
    const findings = await formsScanner.scan(
      ctx('<form action="/submit" method="POST"><input name="query" /><button>Submit</button></form>'),
    );
    // No external forms, no WhatsApp, HTTPS action (relative = same origin)
    const serious = findings.filter((f) => f.severity !== "info");
    expect(serious).toHaveLength(0);
  });
});
