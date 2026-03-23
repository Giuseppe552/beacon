import type { Finding, Grade, Severity } from "./types.js";

/** Weight per severity level. */
const WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 2,
  info: 0,
};

/**
 * Compute a letter grade from a set of findings.
 * Starts at 100 (A) and deducts points per finding.
 */
export function computeGrade(findings: Finding[]): Grade {
  let score = 100;
  for (const f of findings) {
    score -= WEIGHTS[f.severity];
  }
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}
