"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const INDUSTRIES = [
  { value: "general", label: "Any business" },
  { value: "immigration", label: "Immigration" },
  { value: "law", label: "Law firm" },
  { value: "accounting", label: "Accounting" },
  { value: "healthcare", label: "Healthcare" },
];

export default function CompareForm() {
  const [domains, setDomains] = useState(["", "", ""]);
  const [industry, setIndustry] = useState("general");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState("");
  const router = useRouter();

  function updateDomain(index: number, value: string) {
    setDomains((prev) => {
      const next = [...prev];
      next[index] = value;
      return next;
    });
  }

  function addDomain() {
    if (domains.length < 4) {
      setDomains((prev) => [...prev, ""]);
    }
  }

  function removeDomain(index: number) {
    if (domains.length > 2) {
      setDomains((prev) => prev.filter((_, i) => i !== index));
    }
  }

  const filledDomains = domains.filter((d) => d.trim().length > 0);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (filledDomains.length < 2 || scanning) return;

    setScanning(true);
    setError("");
    setProgress(`Scanning ${filledDomains.length} domains\u2026`);

    try {
      const res = await fetch("/api/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: filledDomains, industry }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({ error: "Comparison failed" }));
        setError(data.error ?? `Failed (${res.status})`);
        setScanning(false);
        return;
      }

      const result = await res.json();
      router.push(`/compare/${result.id}`);
    } catch {
      setError("Connection failed. Check your network and try again.");
      setScanning(false);
    }
  }

  return (
    <div className="w-full max-w-xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-3">
        {domains.map((domain, i) => (
          <div key={i} className="flex gap-2 items-center">
            <span className="text-xs text-[var(--fg-dim)] w-5 shrink-0 text-right ff-mono">
              {i + 1}.
            </span>
            <input
              type="text"
              value={domain}
              onChange={(e) => updateDomain(i, e.target.value)}
              placeholder={i === 0 ? "your-site.com" : `competitor-${i}.com`}
              disabled={scanning}
              className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--bg-subtle)] px-4 py-2.5 text-sm text-[var(--fg)] placeholder:text-[var(--fg-dim)] outline-none transition-colors focus:border-[var(--accent)] disabled:opacity-50"
            />
            {domains.length > 2 && (
              <button
                type="button"
                onClick={() => removeDomain(i)}
                disabled={scanning}
                className="text-[var(--fg-dim)] hover:text-[var(--fg-muted)] text-xs disabled:opacity-30"
                title="Remove"
              >
                ✕
              </button>
            )}
          </div>
        ))}

        {domains.length < 4 && (
          <button
            type="button"
            onClick={addDomain}
            disabled={scanning}
            className="text-xs text-[var(--fg-dim)] hover:text-[var(--accent)] transition-colors disabled:opacity-30 ml-7"
          >
            + add domain
          </button>
        )}

        <div className="ml-7">
          <div className="flex flex-wrap gap-1.5">
            {INDUSTRIES.map((ind) => (
              <button
                key={ind.value}
                type="button"
                onClick={() => setIndustry(ind.value)}
                disabled={scanning}
                className={`rounded-full border px-3 py-1 text-xs transition-all disabled:opacity-50 ${
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

        <div className="ml-7">
          <button
            type="submit"
            disabled={scanning || filledDomains.length < 2}
            className="rounded-lg bg-[var(--accent)] px-6 py-2.5 text-sm font-medium text-white transition-all hover:brightness-110 disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {scanning ? "Comparing\u2026" : `Compare ${filledDomains.length} sites`}
          </button>
        </div>
      </form>

      {scanning && (
        <div className="mt-5 ml-7 rounded-lg border border-[var(--accent)]/20 bg-[var(--bg-subtle)] px-4 py-3">
          <p className="text-sm text-[var(--fg-secondary)]">{progress}</p>
          <p className="mt-1 text-xs text-[var(--fg-dim)]">
            This takes 10-20 seconds. Each site is scanned independently.
          </p>
        </div>
      )}

      {error && (
        <div className="mt-4 ml-7 rounded-lg border border-[var(--sev-high)]/30 bg-[var(--sev-high)]/5 px-4 py-3 text-sm text-[var(--sev-high)]">
          {error}
        </div>
      )}
    </div>
  );
}
