import { describe, it, expect } from "vitest";
import { computeGrade } from "./grade.js";
import type { Finding } from "./types.js";

function finding(severity: Finding["severity"]): Finding {
  return {
    id: `test-${severity}`,
    category: "headers",
    severity,
    title: "test",
    detail: "test",
    risk: "test",
  };
}

describe("computeGrade", () => {
  it("returns A for no findings", () => {
    expect(computeGrade([])).toBe("A");
  });

  it("returns A for info-only findings", () => {
    expect(computeGrade([finding("info"), finding("info")])).toBe("A");
  });

  it("returns A for a few low findings", () => {
    expect(computeGrade([finding("low"), finding("low"), finding("low")])).toBe("A");
  });

  it("returns B for one high finding", () => {
    expect(computeGrade([finding("high")])).toBe("B");
  });

  it("returns C for one critical finding (100 - 40 = 60)", () => {
    expect(computeGrade([finding("critical")])).toBe("C");
  });

  it("returns F for two critical findings", () => {
    expect(computeGrade([finding("critical"), finding("critical")])).toBe("F");
  });

  it("returns C for mixed medium findings", () => {
    const findings = [
      finding("medium"),
      finding("medium"),
      finding("medium"),
      finding("medium"),
      finding("low"),
    ];
    expect(computeGrade(findings)).toBe("C");
  });

  it("accumulates severity weights", () => {
    // 1 high (20) + 2 medium (16) + 3 low (6) = 42 deducted → 58 → C
    const findings = [
      finding("high"),
      finding("medium"),
      finding("medium"),
      finding("low"),
      finding("low"),
      finding("low"),
    ];
    expect(computeGrade(findings)).toBe("C");
  });
});
