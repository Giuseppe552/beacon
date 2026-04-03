import type { Metadata } from "next";
import ScanTabs from "@/components/ScanTabs";
import FAQ from "@/components/FAQ";

export const metadata: Metadata = {
  title: "beacon — free website security scanner | Check your site for vulnerabilities",
  description:
    "Free security scanner for business websites. Checks encryption, email authentication, exposed files, third-party tracking, and more. Every finding maps to a real documented breach.",
  openGraph: {
    title: "beacon — free website security scanner",
    description:
      "Find out if your website has the same weaknesses that caused real data breaches. Free, no signup, full report.",
    type: "website",
  },
};

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col">
      {/* ── Hero + Scan ────────────────────────────────── */}
      <div className="flex flex-col items-center px-5 pt-16 pb-12 sm:pt-24 sm:pb-16">
        <div className="text-center mb-10">
          <h1 className="ff-mono text-4xl sm:text-5xl font-bold tracking-tight">
            beacon
          </h1>
          <p className="mt-4 max-w-lg text-[var(--fg-secondary)] text-base sm:text-lg leading-relaxed">
            Find out if your website has the same weaknesses
            that caused real data breaches at other businesses.
          </p>
        </div>
        <ScanTabs />
        <p className="mt-6 text-xs text-[var(--fg-dim)] text-center max-w-sm">
          43% of UK businesses experienced a cyber breach last year.
          Most didn&apos;t know until someone else told them.
          <br />
          <span className="text-[var(--fg-dim)]/60">
            Source: UK DSIT Cyber Breaches Survey, 2025
          </span>
        </p>
        <p className="mt-3 text-[10px] text-[var(--fg-dim)]/50 text-center max-w-xs">
          Free tool. No signup. No data stored beyond 7 days.
          Runs on limited infrastructure — be patient with slow scans.
        </p>
      </div>

      {/* ── Content sections ───────────────────────────── */}
      <div className="mx-auto max-w-3xl w-full px-5 space-y-20 pb-20">

        {/* What we check */}
        <section>
          <h2 className="text-xl font-bold text-[var(--fg)] mb-2">
            What the scan checks
          </h2>
          <p className="text-sm text-[var(--fg-muted)] mb-6">
            Seven independent scanners, each checking a different layer
            of your website&apos;s security. The scan takes 3–6 seconds and
            doesn&apos;t install anything on your site.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-2.5 pr-4 text-[var(--fg-muted)] font-medium">Layer</th>
                  <th className="text-left py-2.5 pr-4 text-[var(--fg-muted)] font-medium">What it checks</th>
                  <th className="text-left py-2.5 text-[var(--fg-muted)] font-medium">Why it matters</th>
                </tr>
              </thead>
              <tbody className="text-[var(--fg-secondary)]">
                {[
                  ["Encryption (TLS)", "Protocol version, certificate validity, HSTS enforcement, HTTP→HTTPS redirect", "Without encryption, anyone on the same network can read what your visitors type — passwords, card numbers, personal details"],
                  ["Email authentication", "SPF, DKIM (18 selectors), DMARC policy, DNSSEC", "Without these records, anyone can send emails that appear to come from your domain. This is how invoice fraud works — £150M+ lost across UK law firms since 2022"],
                  ["Exposed files", "25 paths including .env, .git, database backups, admin panels, API documentation", "Misconfigured servers sometimes expose files containing passwords, API keys, or full database dumps. Twitch lost 125GB of source code this way"],
                  ["Security headers", "CSP, X-Frame-Options, referrer policy, permissions policy, version disclosure", "Headers tell browsers what scripts are allowed to run and what data can be shared. Without them, a single injected script can steal everything on the page"],
                  ["Third-party tracking", "20+ known trackers, session recording tools (Hotjar, FullStory, Clarity), SRI validation", "Session recording tools capture every mouse movement and form interaction. If clients enter passport numbers or financial details, those recordings exist on someone else\u2019s servers"],
                  ["Forms & uploads", "Google Forms, WhatsApp links, HTTP form actions, file upload security", "Passport copies submitted through Google Forms are stored on Google\u2019s consumer infrastructure. WhatsApp provides no audit trail and no guaranteed deletion"],
                  ["Cookies", "HttpOnly, Secure, SameSite flags on session and tracking cookies", "An insecure session cookie means an attacker can log in as your user — seeing their account, their documents, their data"],
                ].map(([layer, checks, why]) => (
                  <tr key={layer} className="border-b border-[var(--border)]/50">
                    <td className="py-3 pr-4 font-medium text-[var(--fg)] whitespace-nowrap align-top">{layer}</td>
                    <td className="py-3 pr-4 align-top text-xs leading-relaxed">{checks}</td>
                    <td className="py-3 align-top text-xs leading-relaxed text-[var(--fg-muted)]">{why}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Grading methodology */}
        <section>
          <h2 className="text-xl font-bold text-[var(--fg)] mb-2">
            How the grades work
          </h2>
          <p className="text-sm text-[var(--fg-muted)] mb-6">
            Each finding has a severity level. The overall grade starts at 100
            and deducts points based on what we find. Two hard rules override the
            score: any critical finding = automatic F, and two or more high findings
            cap the grade at D. A site with perfect headers but an exposed database
            backup is not a B.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
            {/* Grade scale */}
            <div>
              <h3 className="ff-mono text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-3">Grade scale</h3>
              <div className="space-y-1.5">
                {[
                  ["A", "var(--grade-a)", "Strong", "No critical or high-severity issues. Better than most."],
                  ["B", "var(--grade-b)", "Reasonable", "Solid foundation, some gaps. The issues found are what attackers check first."],
                  ["C", "var(--grade-c)", "Weak", "Significant weaknesses. Every issue here has caused a real breach elsewhere."],
                  ["D", "var(--grade-d)", "Poor", "Serious exposure. Multiple weaknesses being actively exploited across the internet."],
                  ["F", "var(--grade-f)", "Critical", "At least one finding that has caused major breaches, fines, and business closures."],
                ].map(([grade, color, label, desc]) => (
                  <div key={grade} className="flex gap-3 items-start rounded border border-[var(--border)] bg-[var(--surface)] p-2.5">
                    <span className="ff-mono text-base font-bold w-5 shrink-0" style={{ color: `${color}` }}>{grade}</span>
                    <div>
                      <span className="text-sm font-medium text-[var(--fg)]">{label}</span>
                      <p className="text-xs text-[var(--fg-muted)] mt-0.5">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Severity weights */}
            <div>
              <h3 className="ff-mono text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-3">Severity weights</h3>
              <div className="space-y-1.5">
                {[
                  ["Critical", "var(--sev-critical)", "\u221240 points", "Automatic F regardless of other findings"],
                  ["High", "var(--sev-high)", "\u221220 points", "Two or more = grade capped at D"],
                  ["Medium", "var(--sev-medium)", "\u22128 points", "Weakens posture, makes other attacks easier"],
                  ["Low", "var(--sev-low)", "\u22122 points", "Minor issue, signals low security priority"],
                  ["Info", "var(--sev-info)", "0 points", "Worth knowing, no action required"],
                ].map(([level, color, weight, desc]) => (
                  <div key={level} className="flex gap-3 items-start rounded border border-[var(--border)] bg-[var(--surface)] p-2.5">
                    <span className="ff-mono text-xs font-medium w-16 shrink-0" style={{ color: `${color}` }}>{level}</span>
                    <div>
                      <span className="ff-mono text-xs text-[var(--fg)]">{weight}</span>
                      <p className="text-xs text-[var(--fg-muted)] mt-0.5">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-4 rounded border border-[var(--border)] bg-[var(--surface)] p-3">
                <h4 className="text-xs font-medium text-[var(--fg)] mb-1">Industry context</h4>
                <p className="text-xs text-[var(--fg-muted)] leading-relaxed">
                  If you select an industry, severity levels adjust. For example: no
                  DMARC on an immigration agency is bumped from high to critical
                  because that agency sends payment instructions and case updates
                  by email. The same finding on a restaurant stays high.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Breach precedent database */}
        <section>
          <h2 className="text-xl font-bold text-[var(--fg)] mb-2">
            115 breach precedents, all sourced
          </h2>
          <p className="text-sm text-[var(--fg-muted)] mb-6">
            Every finding in your report is matched to a real incident where the
            same weakness was exploited. Not hypothetical risk — documented
            breaches with named companies, regulatory fines, and cited sources.
          </p>

          {/* Sample precedents */}
          <div className="space-y-3 mb-6">
            {[
              {
                name: "DPP Law, Merseyside (2022)",
                finding: "No MFA on admin account",
                impact: "32.4GB of client data on the dark web. 682 clients affected. £60,000 ICO fine.",
                source: "ICO enforcement",
                url: "https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2025/04/law-firm-fined-60-000-following-cyber-attack/",
                quote: "I\u2019m now a prisoner in my own home again. In fear of my life. My family\u2019s also.",
              },
              {
                name: "British Airways (2018)",
                finding: "No Content-Security-Policy",
                impact: "429,000 payment cards stolen. £20 million ICO fine.",
                source: "ICO / The Register",
                url: "https://www.theregister.com/2020/10/16/british_airways_ico_fine_20m/",
              },
              {
                name: "Orion S.A. (2024)",
                finding: "No email authentication (DMARC)",
                impact: "$60 million in fraudulent wire transfers.",
                source: "TechCrunch / SEC filing",
                url: "https://techcrunch.com/2024/08/14/texas-firm-says-it-lost-60m-in-a-bank-wire-transfer-scam/",
              },
              {
                name: "Tuckers Solicitors, London (2020)",
                finding: "No MFA on remote access, unpatched systems",
                impact: "972,191 files encrypted. 60 court bundles — including rape and murder cases — posted on the dark web. £98,000 ICO fine.",
                source: "ICO / Law Gazette",
                url: "https://www.lawgazette.co.uk/news/firm-fined-almost-100000-over-ransomware-attack-/5111806.article",
              },
              {
                name: "Twitch (2021)",
                finding: "Exposed configuration files",
                impact: "125GB of source code, streamer payment data, and internal tools leaked.",
                source: "The Verge",
                url: "https://www.theverge.com/2021/10/6/22712250/twitch-hack-leak-data-streamer-revenue",
              },
            ].map((b) => (
              <div key={b.name} className="rounded border border-[var(--border)] bg-[var(--surface)] p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-medium text-[var(--fg)]">{b.name}</div>
                    <div className="ff-mono text-xs text-[var(--fg-dim)] mt-0.5">Triggered by: {b.finding}</div>
                  </div>
                  <a
                    href={b.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-[var(--fg-dim)] hover:text-[var(--fg-muted)] transition-colors ff-mono shrink-0"
                  >
                    {b.source} ↗
                  </a>
                </div>
                <p className="mt-2 text-xs text-[var(--fg-secondary)] italic">{b.impact}</p>
                {b.quote && (
                  <p className="mt-2 text-xs text-[var(--sev-high)] italic">
                    &ldquo;{b.quote}&rdquo;
                  </p>
                )}
              </div>
            ))}
          </div>

          <div className="flex flex-wrap gap-3 text-xs text-[var(--fg-dim)]">
            <span className="rounded border border-[var(--border)] px-2.5 py-1">115 total precedents</span>
            <span className="rounded border border-[var(--border)] px-2.5 py-1">21 vulnerability categories</span>
            <span className="rounded border border-[var(--border)] px-2.5 py-1">100% have source URLs</span>
            <span className="rounded border border-[var(--border)] px-2.5 py-1">Sources: ICO, FTC, FBI IC3, court filings, peer-reviewed research</span>
          </div>
        </section>

        {/* What this is not */}
        <section>
          <h2 className="text-xl font-bold text-[var(--fg)] mb-2">
            What this scan does not do
          </h2>
          <p className="text-sm text-[var(--fg-muted)] mb-4">
            Honesty about limitations is more useful than false confidence.
          </p>
          <div className="space-y-2">
            {[
              "This is passive analysis. beacon does not attempt authentication bypass, payload injection, or any form of exploitation. A clean scan does not mean your site is secure — it means the publicly visible configuration has no obvious weaknesses.",
              "Third-party detection works on the initial HTML only. Scripts loaded dynamically after page render (via Google Tag Manager, for example) are not detected.",
              "DKIM selector enumeration checks 18 common selectors. Custom selectors used by some providers won\u2019t be found.",
              "Cookie analysis only covers cookies set on the initial page load. Session cookies that appear after login are not captured.",
              "The breach precedent database is manually curated and will always be incomplete. It covers the most consequential incidents, not every case.",
            ].map((text, i) => (
              <div key={i} className="flex gap-3 text-xs text-[var(--fg-muted)] leading-relaxed">
                <span className="text-amber-400 shrink-0 mt-0.5">▲</span>
                <span>{text}</span>
              </div>
            ))}
          </div>
        </section>

        {/* FAQ */}
        <section>
          <h2 className="text-xl font-bold text-[var(--fg)] mb-6">
            Questions
          </h2>
          <FAQ />
        </section>

        {/* How it works (for SEO — more detail than the quick version) */}
        <section>
          <h2 className="text-xl font-bold text-[var(--fg)] mb-2">
            How the scan works, technically
          </h2>
          <div className="space-y-4 text-sm text-[var(--fg-secondary)] leading-relaxed">
            <p>
              When you enter a domain, beacon makes standard HTTP requests to the site — the same requests any browser makes. It connects over TLS to check the encryption configuration, reads the HTTP response headers, queries DNS records for email authentication, and requests a set of common file paths that are sometimes accidentally left public.
            </p>
            <p>
              The scan sends a standard <code className="ff-mono text-xs bg-[var(--surface)] px-1.5 py-0.5 rounded">User-Agent</code> header identifying itself. It does not execute JavaScript, does not submit forms, does not attempt login, and does not probe for injection vulnerabilities. Everything beacon checks is information your site already serves to every visitor.
            </p>
            <p>
              Each finding is matched against a database of 115 documented breach incidents across 21 vulnerability categories. The matching is deterministic — a missing DMARC record always maps to the email spoofing category, which contains cases like the FBI IC3 report on $55 billion in business email compromise losses and the UK solicitor invoice fraud epidemic.
            </p>
            <p>
              If you select an industry (immigration, law, accounting, healthcare), the scan adjusts severity levels and appends industry-specific risk context to findings. A missing DMARC record on a general business website is high severity. On an immigration agency — which sends payment instructions and handles passport data by email — it becomes critical.
            </p>
          </div>
        </section>
      </div>

      {/* Footer */}
      <footer className="border-t border-[var(--border)] py-8 px-5">
        <div className="mx-auto max-w-3xl flex flex-col sm:flex-row justify-between items-center gap-4 text-xs text-[var(--fg-dim)]">
          <p>
            Built by{" "}
            <a href="https://giuseppegiona.com" className="text-[var(--fg-muted)] hover:text-[var(--fg-secondary)] transition-colors">
              Giuseppe Giona
            </a>
          </p>
          <div className="flex gap-4">
            <a href="https://github.com/Giuseppe552/beacon" className="text-[var(--fg-muted)] hover:text-[var(--fg-secondary)] transition-colors">
              Source code
            </a>
            <span>115 breach precedents</span>
            <span>65 tests</span>
          </div>
        </div>
      </footer>
    </main>
  );
}
