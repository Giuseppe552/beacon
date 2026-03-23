import { describe, it, expect } from "vitest";
import { BREACHES, getPrecedent, getAllPrecedents } from "./precedents.js";

describe("BREACHES", () => {
  it("has at least 100 entries", () => {
    expect(BREACHES.length).toBeGreaterThanOrEqual(100);
  });

  it("all entries have required fields", () => {
    for (const b of BREACHES) {
      expect(b.name.length, `${b.key} missing name`).toBeGreaterThan(0);
      expect(b.summary.length, `${b.key} missing summary`).toBeGreaterThan(0);
      expect(b.category.length, `${b.key} missing category`).toBeGreaterThan(0);
      expect(b.source.length, `${b.key} missing source`).toBeGreaterThan(0);
    }
  });

  it("all sources are HTTPS URLs", () => {
    for (const b of BREACHES) {
      expect(b.source.startsWith("https://"), `${b.key} source not HTTPS: ${b.source}`).toBe(true);
    }
  });

  it("no duplicate keys", () => {
    const keys = BREACHES.map((b) => b.key);
    const unique = new Set(keys);
    expect(keys.length).toBe(unique.size);
  });

  it("has expected high-profile breaches", () => {
    const keys = new Set(BREACHES.map((b) => b.key));
    expect(keys.has("ba-magecart-2018")).toBe(true);
    expect(keys.has("ticketmaster-magecart-2018")).toBe(true);
  });
});

describe("getPrecedent", () => {
  it("returns a precedent for known finding IDs", () => {
    expect(getPrecedent("headers-no-csp")).toBeDefined();
    expect(getPrecedent("dns-no-dmarc")).toBeDefined();
    expect(getPrecedent("tls-no-hsts")).toBeDefined();
  });

  it("returns undefined for unknown finding IDs", () => {
    expect(getPrecedent("totally-unknown-finding")).toBeUndefined();
  });

  it("matches prefix for cookie findings", () => {
    const p = getPrecedent("cookies-insecure-session-id");
    expect(p).toBeDefined();
  });
});

describe("getAllPrecedents", () => {
  it("returns multiple precedents for common categories", () => {
    const all = getAllPrecedents("headers-no-csp");
    expect(all.length).toBeGreaterThan(1);
  });

  it("returns empty for unknown findings", () => {
    expect(getAllPrecedents("unknown")).toHaveLength(0);
  });
});
