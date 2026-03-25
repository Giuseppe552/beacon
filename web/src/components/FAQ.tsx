"use client";

import { useState } from "react";

const QUESTIONS: { q: string; a: string }[] = [
  {
    q: "Is this actually free?",
    a: "Yes. Full scan, full report, no signup, no limits. The scan runs the same code whether you pay or not — because there is no paid tier yet. If we add paid features later (monitoring, alerts, scheduled re-scans), the one-off scan will stay free.",
  },
  {
    q: "Do you store my results?",
    a: "Scan results are stored for 7 days so you can share the report URL. After that, they\u2019re deleted. We don\u2019t build a database of scanned domains or sell any data. The source code is public if you want to verify this.",
  },
  {
    q: "Will this break my website?",
    a: "No. The scan makes standard HTTP requests — the same ones any browser makes when visiting your site. It does not execute JavaScript, submit forms, attempt login, or probe for injection vulnerabilities. Your site won\u2019t know the difference between beacon and a regular visitor.",
  },
  {
    q: "My site got an A. Am I safe?",
    a: "An A means the publicly visible configuration has no obvious weaknesses. It does not mean your site is invulnerable. beacon checks the front door — it doesn\u2019t check whether your admin password is \u201cpassword123\u201d or whether your WordPress plugins are up to date. An A is a good sign, not a guarantee.",
  },
  {
    q: "My site got an F. What do I do?",
    a: "Read the \u201cFix this first\u201d section at the top of your report. It shows the most critical issue with exact steps to fix it. Most critical findings are configuration changes, not code rewrites — your hosting provider or web developer can usually fix them in under an hour. The report also shows what happened to other businesses with the same weakness, so you can judge the urgency for yourself.",
  },
  {
    q: "Why does the grade change when I select an industry?",
    a: "Different businesses handle different types of data. A missing DMARC record on a restaurant\u2019s website is a high-severity issue. The same missing record on an immigration agency — which sends payment instructions and handles passport data by email — is critical, because it enables the exact type of invoice fraud that has cost UK solicitors over \u00a3150 million. The industry selector adjusts severity levels to reflect what actually matters for your type of business.",
  },
  {
    q: "Where do the breach precedents come from?",
    a: "All 115 precedents are manually curated from public sources: ICO enforcement actions, FTC complaints, FBI IC3 reports, court filings, and investigative journalism. Every entry has a source URL you can click to verify. We don\u2019t use AI-generated summaries or unverified claims. If a precedent can\u2019t be traced to a primary source, it\u2019s not in the database.",
  },
  {
    q: "How is this different from SecurityHeaders.com or Mozilla Observatory?",
    a: "Those tools check HTTP headers and give you a letter grade. beacon also checks headers, but it adds six more layers: email authentication, exposed files, third-party tracking, form security, cookie flags, and TLS configuration. More importantly, every finding is connected to a real breach where the same weakness was exploited. SecurityHeaders tells you \u201cyou\u2019re missing X-Frame-Options.\u201d beacon tells you \u201cyou\u2019re missing X-Frame-Options, here\u2019s a company that was attacked because of it, and here\u2019s exactly how to fix it.\u201d",
  },
  {
    q: "Can I use this to scan someone else\u2019s website?",
    a: "beacon checks publicly visible information — the same data any visitor\u2019s browser receives. Scanning a public website is not an attack and does not require permission. That said, we rate-limit scans per domain to prevent abuse, and we identify ourselves in the User-Agent header.",
  },
  {
    q: "Is the source code available?",
    a: "Yes. The scanning engine, breach database, grading algorithm, and industry profiles are all on GitHub under MIT licence. You can read every line of code that runs when you click \u201cScan.\u201d",
  },
];

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <div className="space-y-1">
      {QUESTIONS.map((item, i) => (
        <div key={i} className="border border-[var(--border)] rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={() => setOpen(open === i ? null : i)}
            className="w-full flex items-center justify-between gap-4 px-4 py-3 text-left hover:bg-[var(--surface)] transition-colors"
          >
            <span className="text-sm font-medium text-[var(--fg)]">{item.q}</span>
            <span
              className="text-[var(--fg-dim)] text-xs shrink-0 transition-transform duration-200"
              style={{ transform: open === i ? "rotate(45deg)" : "rotate(0deg)" }}
            >
              +
            </span>
          </button>
          {open === i && (
            <div className="px-4 pb-4">
              <p className="text-sm text-[var(--fg-muted)] leading-relaxed">{item.a}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
