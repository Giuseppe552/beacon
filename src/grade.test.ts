import { describe, it, expect } from "vitest";
import { computeGrade, GRADE_EXPLANATIONS, SEVERITY_EXPLANATIONS } from "./grade.js";
import type { Finding, Grade, Severity } from "./types.js";

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

  // Critical floor: any critical = F
  it("returns F for one critical finding", () => {
    expect(computeGrade([finding("critical")])).toBe("F");
  });

  it("returns F for two critical findings", () => {
    expect(computeGrade([finding("critical"), finding("critical")])).toBe("F");
  });

  it("returns F for critical even with clean everything else", () => {
    expect(computeGrade([finding("critical"), finding("info"), finding("info")])).toBe("F");
  });

  // Two high cap: 2+ highs = cap at D
  it("caps at D for two high findings", () => {
    // score = 100 - 40 = 60 → would be C, but 2 highs caps at D
    expect(computeGrade([finding("high"), finding("high")])).toBe("D");
  });

  it("caps at D for three high findings", () => {
    expect(computeGrade([finding("high"), finding("high"), finding("high")])).toBe("D");
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

  it("accumulates severity weights correctly", () => {
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

describe("GRADE_EXPLANATIONS", () => {
  const grades: Grade[] = ["A", "B", "C", "D", "F"];

  it("has an explanation for every grade", () => {
    for (const g of grades) {
      expect(GRADE_EXPLANATIONS[g]).toBeDefined();
      expect(GRADE_EXPLANATIONS[g].label.length).toBeGreaterThan(0);
      expect(GRADE_EXPLANATIONS[g].meaning.length).toBeGreaterThan(20);
      expect(GRADE_EXPLANATIONS[g].action.length).toBeGreaterThan(20);
    }
  });

  it("F explanation mentions immediate action", () => {
    expect(GRADE_EXPLANATIONS.F.action.toLowerCase()).toContain("today");
  });
});

describe("SEVERITY_EXPLANATIONS", () => {
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

  it("has an explanation for every severity", () => {
    for (const s of severities) {
      expect(SEVERITY_EXPLANATIONS[s]).toBeDefined();
      expect(SEVERITY_EXPLANATIONS[s].label.length).toBeGreaterThan(0);
      expect(SEVERITY_EXPLANATIONS[s].meaning.length).toBeGreaterThan(20);
    }
  });
});
