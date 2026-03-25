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
 *
 * Rules:
 * 1. Start at 100, deduct by severity weight
 * 2. Any critical finding = automatic F (floor)
 * 3. Two or more high findings = cap at D
 * 4. Score thresholds: A (90+), B (75+), C (55+), D (35+), F (<35)
 *
 * The floors exist because a single catastrophic weakness
 * (exposed .env, no DMARC on a firm sending wire instructions)
 * should not be masked by clean results elsewhere. A site with
 * perfect headers and an exposed database backup is not a C.
 */
export function computeGrade(findings: Finding[]): Grade {
  const criticals = findings.filter((f) => f.severity === "critical").length;
  const highs = findings.filter((f) => f.severity === "high").length;

  // Floor: any critical = F
  if (criticals > 0) return "F";

  let score = 100;
  for (const f of findings) {
    score -= WEIGHTS[f.severity];
  }

  // Cap: 2+ highs = cannot be above D
  if (highs >= 2) {
    const raw = scoreToGrade(score);
    return gradeMax(raw, "D");
  }

  return scoreToGrade(score);
}

function scoreToGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}

/** Return the worse of two grades. */
function gradeMax(a: Grade, cap: Grade): Grade {
  const order: Grade[] = ["A", "B", "C", "D", "F"];
  const ai = order.indexOf(a);
  const ci = order.indexOf(cap);
  return ai >= ci ? a : cap;
}

/**
 * Human-readable explanation of what each grade means.
 * Written for a business owner, not a security engineer.
 */
export const GRADE_EXPLANATIONS: Record<Grade, {
  label: string;
  meaning: string;
  action: string;
}> = {
  A: {
    label: "Strong",
    meaning: "No critical or high-severity issues found. Your site follows security best practices that most businesses miss. This doesn't mean you're invulnerable — it means an attacker scanning for easy targets will move on.",
    action: "Keep monitoring. Security isn't a one-time fix. New vulnerabilities are discovered constantly, and configurations drift over time.",
  },
  B: {
    label: "Reasonable",
    meaning: "Your site has a solid foundation but there are gaps. The issues found are the kind that professional attackers scan for — they're not theoretical, they're the first things checked. Most businesses score here or lower.",
    action: "Fix the high-severity findings first. Each one is explained with a real breach where the same weakness was exploited. The fixes are usually straightforward — often a single configuration change.",
  },
  C: {
    label: "Weak",
    meaning: "Significant weaknesses. Every issue listed has caused a real data breach at another company. An attacker who stumbles on this site would flag it for closer inspection. If your site handles personal data, client documents, or payments, this grade demands attention.",
    action: "Start with the priority fix at the top of the report. Work through the high and medium findings in order. Most can be fixed in an afternoon by someone who manages your hosting.",
  },
  D: {
    label: "Poor",
    meaning: "Serious exposure. Multiple weaknesses that are being actively exploited across the internet right now. The breach precedents listed are not warnings — they are documented incidents with named companies, regulatory fines, and real financial losses.",
    action: "This needs immediate attention. If you handle client data, you may already be in breach of your data protection obligations. Share this report with whoever manages your website and your professional indemnity insurer.",
  },
  F: {
    label: "Critical",
    meaning: "At least one finding that, on its own, has caused major data breaches, regulatory enforcement, and business closures. This is not a collection of small issues — there is a specific, exploitable weakness that puts your clients' data at immediate risk.",
    action: "Act today. Not next week. The specific vulnerability is described at the top of this report with the exact steps to fix it. If you don't have someone technical on hand, hire one — the cost of fixing this is a fraction of what a breach will cost.",
  },
};

/**
 * Severity level explanations for the report legend.
 */
export const SEVERITY_EXPLANATIONS: Record<Severity, {
  label: string;
  meaning: string;
}> = {
  critical: {
    label: "Critical",
    meaning: "A single finding at this level means your site has an exploitable weakness that has directly caused major breaches elsewhere. Immediate action required.",
  },
  high: {
    label: "High",
    meaning: "Weaknesses that professional attackers actively scan for. Each one meaningfully increases the chance of a breach. Fix these before anything else.",
  },
  medium: {
    label: "Medium",
    meaning: "Security gaps that weaken your overall posture. Not immediately exploitable on their own, but they make other attacks easier or more damaging.",
  },
  low: {
    label: "Low",
    meaning: "Minor configuration issues or information leaks. Low individual risk, but they signal to an attacker that security isn't a priority — which makes them look harder.",
  },
  info: {
    label: "Info",
    meaning: "Observations that aren't vulnerabilities but are worth knowing about. No action required, but useful context for understanding your security posture.",
  },
};
