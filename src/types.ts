/** Grade for a security category or overall. */
export type Grade = "A" | "B" | "C" | "D" | "F";

/** Severity of an individual finding. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** A single security finding with breach precedent. */
export type Finding = {
  id: string;
  category: ScanCategory;
  severity: Severity;
  title: string;
  /** What we found — technical. */
  detail: string;
  /** What it means — business risk in plain English. */
  risk: string;
  /** Real breach that exploited this exact weakness, if known. */
  precedent?: BreachPrecedent;
  /** How to fix it. */
  remediation?: string;
};

export type BreachPrecedent = {
  /** Short name, e.g. "Fragomen 2020" */
  name: string;
  /** What happened. */
  summary: string;
  /** How many records/people affected. */
  impact?: string;
  /** Source URL (ICO report, news article, CVE). */
  source?: string;
  /** Direct quote from a victim, client, or investigator. The human cost. */
  quote?: string;
};

export type ScanCategory =
  | "tls"
  | "headers"
  | "dns"
  | "exposed-paths"
  | "technology"
  | "forms"
  | "third-party"
  | "cookies"
  | "email"
  | "information-disclosure";

/** Per-category result. */
export type CategoryResult = {
  category: ScanCategory;
  grade: Grade;
  findings: Finding[];
  /** Time taken in ms. */
  durationMs: number;
};

/** Full scan report for a domain. */
export type ScanReport = {
  domain: string;
  url: string;
  timestamp: string;
  durationMs: number;
  overallGrade: Grade;
  categories: CategoryResult[];
  findings: Finding[];
  /** All third-party domains that receive data during a page load. */
  thirdPartyDomains: string[];
  /** Summary counts. */
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
};

/** Scanner interface — each layer implements this. */
export type Scanner = {
  name: string;
  category: ScanCategory;
  scan: (ctx: ScanContext) => Promise<Finding[]>;
};

/** Shared context passed to all scanners. */
export type ScanContext = {
  domain: string;
  url: string;
  /** Raw HTML of the homepage. */
  html: string;
  /** Response headers from the homepage GET. */
  headers: Record<string, string>;
  /** Status code from homepage. */
  statusCode: number;
  /** Whether the site redirects HTTP to HTTPS. */
  httpsRedirect: boolean;
  /** Industry context for risk text and severity adjustment. */
  industry?: string;
};
