import type { BreachPrecedent } from "../types.js";
import breachDb from "./breaches.json" with { type: "json" };

export type BreachEntry = {
  key: string;
  category: string;
  name: string;
  summary: string;
  impact: string;
  source: string;
};

/** Full breach database — 100 verified incidents with cited sources. */
export const BREACHES: BreachEntry[] = breachDb as BreachEntry[];

/**
 * Map from scanner finding categories to breach database categories.
 * A single finding type can match multiple breach categories.
 */
const FINDING_TO_BREACH_CATEGORIES: Record<string, string[]> = {
  // Headers scanner
  "headers-no-csp": ["xss", "supply-chain"],
  "headers-csp-unsafe-inline": ["xss"],
  "headers-csp-unsafe-eval": ["xss"],
  "headers-no-frame-protection": ["clickjacking"],
  "headers-no-nosniff": ["xss"],
  "headers-no-referrer-policy": ["information-disclosure"],
  "headers-no-permissions-policy": ["xss"],
  "headers-server-version": ["information-disclosure"],
  "headers-x-powered-by": ["information-disclosure"],

  // TLS scanner
  "tls-outdated-protocol": ["tls-downgrade"],
  "tls-no-hsts": ["tls-downgrade"],
  "tls-hsts-short": ["tls-downgrade"],
  "tls-cert-invalid": ["certificate-issues"],
  "tls-cert-expired": ["certificate-issues"],
  "tls-cert-expiring": ["certificate-issues"],
  "tls-no-http-redirect": ["tls-downgrade"],

  // DNS scanner
  "dns-no-spf": ["email-spoofing"],
  "dns-spf-softfail": ["email-spoofing"],
  "dns-spf-neutral": ["email-spoofing"],
  "dns-no-dmarc": ["email-spoofing"],
  "dns-dmarc-none": ["email-spoofing"],
  "dns-no-dmarc-record": ["email-spoofing"],
  "dns-no-dkim": ["email-spoofing"],
  "dns-dkim-weak-key": ["email-spoofing"],
  "dns-no-dnssec": ["subdomain-takeover"],

  // Paths scanner
  "paths-env": ["exposed-files"],
  "paths-env-local": ["exposed-files"],
  "paths-env-production": ["exposed-files"],
  "paths-git-head": ["exposed-files"],
  "paths-git-config": ["exposed-files"],
  "paths-package-json": ["exposed-files"],
  "paths-docker-compose-yml": ["exposed-files"],
  "paths-backup-sql": ["exposed-files", "cloud-storage"],
  "paths-dump-sql": ["exposed-files"],
  "paths-phpinfo-php": ["information-disclosure"],
  "paths-wp-admin": ["wordpress-cms", "admin-panel"],
  "paths-wp-login-php": ["wordpress-cms", "credential-stuffing"],
  "paths-admin": ["admin-panel"],
  "paths-phpmyadmin": ["admin-panel"],
  "paths-graphql": ["api-exposure"],
  "paths-swagger-json": ["api-exposure"],
  "paths-api-docs": ["api-exposure"],
  "paths-wp-config-php-bak": ["exposed-files"],

  // Third-party scanner — specific trackers
  "third-party-hotjar": ["session-recording"],
  "third-party-fullstory": ["session-recording"],
  "third-party-mouseflow": ["session-recording"],
  "third-party-microsoft-clarity": ["session-recording"],
  "third-party-smartlook": ["session-recording"],
  "third-party-facebook-pixel": ["session-recording"],
  "third-party-google-analytics": ["session-recording"],
  "third-party-linkedin-insight": ["session-recording"],
  "third-party-tiktok-analytics": ["session-recording"],
  "third-party-intercom": ["session-recording"],
  "third-party-crisp": ["session-recording"],
  "third-party-tawk-to": ["session-recording"],
  "third-party-livechat": ["session-recording"],
  "third-party-zendesk": ["session-recording"],
  "third-party-google-recaptcha": ["session-recording"],
  "third-party-sentry": ["session-recording"],
  "third-party-no-sri": ["supply-chain"],
  "third-party-count": ["session-recording"],

  // Forms scanner
  "forms-external-google-forms": ["cloud-storage", "legal-professional"],
  "forms-whatsapp-communication": ["whatsapp-consumer-tools"],
  "forms-http-action": ["tls-downgrade"],
  "forms-file-upload-insecure": ["file-upload"],
  "forms-external-typeform": ["cloud-storage"],
  "forms-external-jotform": ["cloud-storage"],

  // Cookies scanner — any insecure cookie finding
  "cookies-insecure": ["cookie-session"],
};

/**
 * Get the most relevant breach precedent for a finding ID.
 * Returns a random selection from matching breaches to vary output.
 */
export function getPrecedent(findingId: string): BreachPrecedent | undefined {
  // Try exact match first
  const categories = FINDING_TO_BREACH_CATEGORIES[findingId];
  if (!categories) {
    // Try prefix match (e.g., "cookies-insecure-session-id" → "cookies-insecure")
    const prefix = Object.keys(FINDING_TO_BREACH_CATEGORIES).find((k) =>
      findingId.startsWith(k),
    );
    if (!prefix) return undefined;
    return pickPrecedent(FINDING_TO_BREACH_CATEGORIES[prefix]);
  }
  return pickPrecedent(categories);
}

/**
 * Get ALL matching breach precedents for a finding ID.
 * Used for detailed reports that list multiple examples.
 */
export function getAllPrecedents(findingId: string): BreachPrecedent[] {
  const categories = FINDING_TO_BREACH_CATEGORIES[findingId];
  if (!categories) {
    const prefix = Object.keys(FINDING_TO_BREACH_CATEGORIES).find((k) =>
      findingId.startsWith(k),
    );
    if (!prefix) return [];
    return matchBreaches(FINDING_TO_BREACH_CATEGORIES[prefix]);
  }
  return matchBreaches(categories);
}

function pickPrecedent(categories: string[]): BreachPrecedent | undefined {
  const matches = matchBreaches(categories);
  if (matches.length === 0) return undefined;
  // Pick the one with the highest impact (heuristic: longest impact string)
  return matches.sort((a, b) => (b.impact?.length ?? 0) - (a.impact?.length ?? 0))[0];
}

function matchBreaches(categories: string[]): BreachPrecedent[] {
  return BREACHES.filter((b) => categories.includes(b.category)).map((b) => ({
    name: b.name,
    summary: b.summary,
    impact: b.impact,
    source: b.source,
  }));
}
