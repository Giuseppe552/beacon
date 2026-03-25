"use client";

import { useState, useRef } from "react";
import { useRouter } from "next/navigation";

const INDUSTRIES = [
  { value: "general", label: "Any business", hint: "General security check" },
  { value: "immigration", label: "Immigration", hint: "Handles passports & visas" },
  { value: "law", label: "Law firm", hint: "Handles case files & court docs" },
  { value: "accounting", label: "Accounting", hint: "Handles tax & financial data" },
  { value: "healthcare", label: "Healthcare", hint: "Handles patient records" },
];

const SCANNER_STEPS = [
  { technical: "TLS/SSL", human: "Checking your site\u2019s encryption" },
  { technical: "Headers", human: "Checking browser security settings" },
  { technical: "DNS", human: "Checking email authentication" },
  { technical: "Paths", human: "Looking for exposed files" },
  { technical: "Third-Party", human: "Mapping third-party data flows" },
  { technical: "Forms", human: "Checking form security" },
  { technical: "Cookies", human: "Checking login security" },
];

export default function ScanForm() {
  const [domain, setDomain] = useState("");
  const [industry, setIndustry] = useState("general");
  const [scanning, setScanning] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const router = useRouter();
  const abortRef = useRef<AbortController | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim() || scanning) return;

    setScanning(true);
    setError("");
    setStep(0);

    let stepIdx = 0;
    const timer = setInterval(() => {
      stepIdx++;
      if (stepIdx < SCANNER_STEPS.length) setStep(stepIdx);
    }, 600);

    abortRef.current = new AbortController();

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim(), industry }),
        signal: abortRef.current.signal,
      });

      clearInterval(timer);

      if (!res.ok) {
        const data = await res.json().catch(() => ({ error: "Scan failed" }));
        setError(data.error ?? `Scan failed (${res.status})`);
        setScanning(false);
        return;
      }

      const { id } = await res.json();
      router.push(`/scan/${id}`);
    } catch (err) {
      clearInterval(timer);
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError("Connection failed. Check your network and try again.");
      setScanning(false);
    }
  }

  return (
    <div className="w-full max-w-xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Domain input */}
        <div className="flex gap-2">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="yourwebsite.com"
            disabled={scanning}
            className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--bg-subtle)] px-4 py-3 text-base text-[var(--fg)] placeholder:text-[var(--fg-dim)] outline-none transition-colors focus:border-[var(--accent)] disabled:opacity-50"
            autoFocus
          />
          <button
            type="submit"
            disabled={scanning || !domain.trim()}
            className="shrink-0 rounded-lg bg-[var(--accent)] px-6 py-3 text-sm font-medium text-white transition-all hover:brightness-110 disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {scanning ? "Scanning\u2026" : "Scan"}
          </button>
        </div>

        {/* Industry — explained for non-tech users */}
        <div>
          <p className="text-xs text-[var(--fg-muted)] mb-2">
            Tell us your industry and we&apos;ll adjust the scan for what matters most to your type of business.
          </p>
          <div className="flex flex-wrap gap-1.5">
            {INDUSTRIES.map((ind) => (
              <button
                key={ind.value}
                type="button"
                onClick={() => setIndustry(ind.value)}
                disabled={scanning}
                title={ind.hint}
                className={`rounded-full border px-3 py-1.5 text-xs transition-all disabled:opacity-50 ${
                  industry === ind.value
                    ? "border-[var(--accent)]/40 bg-[var(--accent)]/10 text-[var(--accent)]"
                    : "border-[var(--border)] text-[var(--fg-muted)] hover:border-[var(--border-hover)] hover:text-[var(--fg-secondary)]"
                }`}
              >
                {ind.label}
              </button>
            ))}
          </div>
        </div>
      </form>

      {/* Scan progress — human-readable steps */}
      {scanning && (
        <div className="mt-6 rounded-lg border border-[var(--accent)]/20 bg-[var(--bg-subtle)] p-5">
          <p className="text-sm text-[var(--fg-secondary)] mb-3">
            Scanning {domain.trim()}\u2026
          </p>
          <div className="space-y-2">
            {SCANNER_STEPS.map(({ human }, i) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <span className="w-5 text-center shrink-0">
                  {i < step ? (
                    <span className="text-[var(--grade-a)]">✓</span>
                  ) : i === step ? (
                    <span className="text-[var(--accent)] inline-block animate-spin">◌</span>
                  ) : (
                    <span className="text-[var(--fg-dim)]">·</span>
                  )}
                </span>
                <span
                  className={
                    i < step
                      ? "text-[var(--fg-muted)]"
                      : i === step
                        ? "text-[var(--fg)]"
                        : "text-[var(--fg-dim)]"
                  }
                >
                  {human}
                </span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-[var(--fg-dim)]">
            This usually takes 3–6 seconds. We&apos;re checking real servers, not running a quick header scan.
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mt-4 rounded-lg border border-[var(--sev-high)]/30 bg-[var(--sev-high)]/5 px-4 py-3 text-sm text-[var(--sev-high)]">
          {error}
        </div>
      )}
    </div>
  );
}
