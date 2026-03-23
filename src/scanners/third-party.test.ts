import { describe, it, expect } from "vitest";
import { thirdPartyScanner } from "./third-party.js";
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

describe("thirdPartyScanner", () => {
  it("detects Google Analytics", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC"></script>'),
    );
    const ga = findings.find((f) => f.title.includes("Google Analytics"));
    expect(ga).toBeDefined();
  });

  it("detects Hotjar (session recording)", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="https://static.hotjar.com/c/hotjar-123.js"></script>'),
    );
    const hj = findings.find((f) => f.title.includes("Hotjar"));
    expect(hj).toBeDefined();
    expect(hj!.severity).toBe("high");
    expect(hj!.precedent).toBeDefined();
  });

  it("detects Facebook Pixel", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'),
    );
    const fb = findings.find((f) => f.title.includes("Facebook"));
    expect(fb).toBeDefined();
    expect(fb!.severity).toBe("medium");
  });

  it("detects Microsoft Clarity", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="https://www.clarity.ms/tag/abc"></script>'),
    );
    const cl = findings.find((f) => f.title.includes("Clarity"));
    expect(cl).toBeDefined();
    expect(cl!.severity).toBe("high");
  });

  it("flags external scripts without SRI", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="https://cdn.example.com/lib.js"></script>'),
    );
    const sri = findings.find((f) => f.id === "third-party-no-sri");
    expect(sri).toBeDefined();
  });

  it("does not flag scripts with SRI", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123"></script>'),
    );
    const sri = findings.find((f) => f.id === "third-party-no-sri");
    expect(sri).toBeUndefined();
  });

  it("counts external domains", async () => {
    const html = `
      <script src="https://a.com/1.js"></script>
      <script src="https://b.com/2.js"></script>
      <script src="https://c.com/3.js"></script>
      <script src="https://d.com/4.js"></script>
      <script src="https://e.com/5.js"></script>
      <script src="https://f.com/6.js"></script>
    `;
    const findings = await thirdPartyScanner.scan(ctx(html));
    const count = findings.find((f) => f.id === "third-party-count");
    expect(count).toBeDefined();
    expect(count!.title).toContain("6");
  });

  it("ignores same-domain scripts", async () => {
    const findings = await thirdPartyScanner.scan(
      ctx('<script src="/js/app.js"></script><script src="https://test.com/main.js"></script>'),
    );
    expect(findings).toHaveLength(0);
  });
});
