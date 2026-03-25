import { describe, it, expect } from "vitest";
import { INDUSTRY_PROFILES, type Industry } from "./industry.js";
import type { Finding } from "./types.js";

describe("INDUSTRY_PROFILES", () => {
  it("has all expected industries", () => {
    const keys = Object.keys(INDUSTRY_PROFILES) as Industry[];
    expect(keys).toContain("immigration");
    expect(keys).toContain("law");
    expect(keys).toContain("accounting");
    expect(keys).toContain("healthcare");
    expect(keys).toContain("general");
  });

  it("general profile has no severity bumps", () => {
    expect(Object.keys(INDUSTRY_PROFILES.general.severityBumps)).toHaveLength(0);
  });

  it("immigration bumps no-dmarc to critical", () => {
    expect(INDUSTRY_PROFILES.immigration.severityBumps["dns-no-dmarc"]).toBe("critical");
  });

  it("immigration bumps session recording to critical", () => {
    expect(INDUSTRY_PROFILES.immigration.severityBumps["third-party-hotjar"]).toBe("critical");
    expect(INDUSTRY_PROFILES.immigration.severityBumps["third-party-fullstory"]).toBe("critical");
  });

  it("immigration has risk suffix for google forms mentioning passports", () => {
    const suffix = INDUSTRY_PROFILES.immigration.riskSuffix["forms-external-google-forms"];
    expect(suffix?.toLowerCase()).toContain("passport");
    expect(suffix?.toLowerCase()).toContain("consumer");
  });

  it("law has risk suffix for no-dmarc mentioning £150 million", () => {
    const suffix = INDUSTRY_PROFILES.law.riskSuffix["dns-no-dmarc"];
    expect(suffix).toContain("£150 million");
    expect(suffix).toContain("DPP Law");
  });

  it("accounting has risk suffix for exposed env mentioning database credentials", () => {
    const suffix = INDUSTRY_PROFILES.accounting.riskSuffix["paths-env"];
    expect(suffix).toContain("database credentials");
  });

  it("all profiles have a data description", () => {
    for (const [key, profile] of Object.entries(INDUSTRY_PROFILES)) {
      expect(profile.dataDescription.length, `${key} missing dataDescription`).toBeGreaterThan(0);
    }
  });
});
