import { parse } from "node-html-parser";
import type { Finding, Scanner, ScanContext } from "../types.js";
import { getPrecedent } from "../data/precedents.js";

/** Known trackers and their risk category. */
const TRACKER_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  category: "analytics" | "session-recording" | "advertising" | "social" | "chat" | "other";
  risk: string;
}> = [
  // Analytics
  { pattern: /google-analytics\.com|googletagmanager\.com|gtag/i, name: "Google Analytics / GTM", category: "analytics", risk: "Visitor behaviour, page views, and form interactions sent to Google." },
  { pattern: /plausible\.io/i, name: "Plausible Analytics", category: "analytics", risk: "Privacy-focused analytics. No personal data collected. Low risk." },
  { pattern: /umami\.is|umami\./i, name: "Umami Analytics", category: "analytics", risk: "Privacy-focused analytics. Low risk." },
  { pattern: /analytics\.tiktok\.com/i, name: "TikTok Analytics", category: "analytics", risk: "Browsing data sent to TikTok (ByteDance). Subject to Chinese data laws." },

  // Session recording
  { pattern: /hotjar\.com/i, name: "Hotjar", category: "session-recording", risk: "Records mouse movements, clicks, scrolls, and form interactions. Third-party employees can view recordings." },
  { pattern: /fullstory\.com/i, name: "FullStory", category: "session-recording", risk: "Full session replay including form inputs. Third-party access to user behaviour." },
  { pattern: /mouseflow\.com/i, name: "Mouseflow", category: "session-recording", risk: "Session recording and heatmaps. Form data may be captured." },
  { pattern: /clarity\.ms/i, name: "Microsoft Clarity", category: "session-recording", risk: "Free session recording from Microsoft. Captures form interactions." },
  { pattern: /smartlook\.com/i, name: "Smartlook", category: "session-recording", risk: "Session recording including form inputs." },

  // Advertising
  { pattern: /facebook\.net|facebook\.com\/tr|fbevents/i, name: "Facebook Pixel", category: "advertising", risk: "Browsing data sent to Meta. Used for ad targeting. Tracks users across sites." },
  { pattern: /doubleclick\.net|googlesyndication/i, name: "Google Ads", category: "advertising", risk: "Ad targeting data sent to Google." },
  { pattern: /linkedin\.com\/insight|snap\.licdn/i, name: "LinkedIn Insight", category: "advertising", risk: "Professional profile matching with browsing behaviour." },

  // Social
  { pattern: /platform\.twitter\.com|x\.com\/i\/api/i, name: "Twitter/X embed", category: "social", risk: "Twitter tracks visitors who see embedded tweets." },

  // Chat
  { pattern: /intercom\.io|intercomcdn/i, name: "Intercom", category: "chat", risk: "Chat widget loads external scripts with access to page content." },
  { pattern: /crisp\.chat/i, name: "Crisp", category: "chat", risk: "Chat widget with session tracking." },
  { pattern: /tawk\.to/i, name: "Tawk.to", category: "chat", risk: "Free chat widget. Data stored on Tawk.to servers." },
  { pattern: /livechat\.com|livechatinc/i, name: "LiveChat", category: "chat", risk: "Chat widget with visitor tracking." },
  { pattern: /zendesk\.com/i, name: "Zendesk", category: "chat", risk: "Support widget with visitor identification." },

  // Other
  { pattern: /recaptcha|grecaptcha/i, name: "Google reCAPTCHA", category: "other", risk: "Google tracks user behaviour to detect bots. Sends data to Google on every page load." },
  { pattern: /hcaptcha\.com/i, name: "hCaptcha", category: "other", risk: "Privacy-focused CAPTCHA. Lower tracking risk than reCAPTCHA." },
  { pattern: /sentry\.io|sentry-cdn/i, name: "Sentry", category: "other", risk: "Error tracking. May capture user context and breadcrumbs including URLs and form state." },
];

/** Scan HTML for third-party scripts, pixels, and tracking. */
export const thirdPartyScanner: Scanner = {
  name: "Third-Party Tracking",
  category: "third-party",
  scan: async (ctx) => {
    const findings: Finding[] = [];
    const root = parse(ctx.html);

    // Collect all external resource URLs
    const externalDomains = new Set<string>();
    const scripts = root.querySelectorAll("script[src]");
    const links = root.querySelectorAll("link[href]");
    const iframes = root.querySelectorAll("iframe[src]");
    const imgs = root.querySelectorAll('img[src*="//"]');

    const allSrcs: string[] = [
      ...scripts.map((el) => el.getAttribute("src") ?? ""),
      ...links.map((el) => el.getAttribute("href") ?? ""),
      ...iframes.map((el) => el.getAttribute("src") ?? ""),
      ...imgs.map((el) => el.getAttribute("src") ?? ""),
    ];

    for (const src of allSrcs) {
      try {
        if (!src || src.startsWith("/") || src.startsWith("data:")) continue;
        const url = new URL(src, ctx.url);
        if (url.hostname !== ctx.domain && !url.hostname.endsWith(`.${ctx.domain}`)) {
          externalDomains.add(url.hostname);
        }
      } catch {
        // malformed URL
      }
    }

    // Also check inline scripts for tracking patterns
    const inlineScripts = root
      .querySelectorAll("script:not([src])")
      .map((el) => el.text);
    const allContent = [...allSrcs, ...inlineScripts].join(" ");

    // Match against known trackers
    let hasSessionRecording = false;
    const matchedTrackers: string[] = [];

    for (const tracker of TRACKER_PATTERNS) {
      if (tracker.pattern.test(allContent)) {
        matchedTrackers.push(tracker.name);

        const severity =
          tracker.category === "session-recording"
            ? "high" as const
            : tracker.category === "advertising"
              ? "medium" as const
              : "low" as const;

        if (tracker.category === "session-recording") {
          hasSessionRecording = true;
        }

        const tpId = `third-party-${tracker.name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`;
        findings.push({
          id: tpId,
          category: "third-party",
          severity,
          title: `Third-party: ${tracker.name}`,
          detail: `${tracker.name} detected in page source.`,
          risk: tracker.risk,
          precedent: getPrecedent(tpId),
        });
      }
    }

    // Summary finding if many third parties
    if (externalDomains.size > 5) {
      findings.push({
        id: "third-party-count",
        category: "third-party",
        severity: "medium",
        title: `${externalDomains.size} external domains loaded`,
        detail: `The page loads resources from ${externalDomains.size} external domains: ${[...externalDomains].slice(0, 10).join(", ")}${externalDomains.size > 10 ? "..." : ""}`,
        risk: "Each external domain receives data about your visitors (IP address, browser, page URL at minimum). More domains = more exposure.",
      });
    }

    // Check for SRI on external scripts
    const scriptsWithoutSri = scripts.filter((el) => {
      const src = el.getAttribute("src") ?? "";
      if (src.startsWith("/") || src.startsWith("data:")) return false;
      try {
        const url = new URL(src, ctx.url);
        if (url.hostname === ctx.domain) return false;
      } catch {
        return false;
      }
      return !el.getAttribute("integrity");
    });

    if (scriptsWithoutSri.length > 0) {
      findings.push({
        id: "third-party-no-sri",
        category: "third-party",
        severity: "medium",
        title: `${scriptsWithoutSri.length} external scripts without SRI`,
        detail: "External scripts loaded without Subresource Integrity hashes.",
        risk: "If a CDN or third-party is compromised, modified scripts execute on your site with full page access. SRI prevents this by verifying the file hash before execution.",
        remediation: "Add integrity attributes to external script tags.",
      });
    }

    return findings;
  },
};

/** Extract all third-party domains from scan context (used by report). */
export function extractThirdPartyDomains(ctx: ScanContext): string[] {
  const root = parse(ctx.html);
  const domains = new Set<string>();

  const allSrcs = [
    ...root.querySelectorAll("script[src]").map((el) => el.getAttribute("src")),
    ...root.querySelectorAll("link[href]").map((el) => el.getAttribute("href")),
    ...root.querySelectorAll("iframe[src]").map((el) => el.getAttribute("src")),
    ...root.querySelectorAll('img[src*="//"]').map((el) => el.getAttribute("src")),
  ];

  for (const src of allSrcs) {
    if (!src || src.startsWith("/") || src.startsWith("data:")) continue;
    try {
      const url = new URL(src, `https://${ctx.domain}`);
      if (url.hostname !== ctx.domain && !url.hostname.endsWith(`.${ctx.domain}`)) {
        domains.add(url.hostname);
      }
    } catch {
      // skip
    }
  }

  return [...domains].sort();
}
