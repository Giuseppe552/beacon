"use client";

import { useState } from "react";

export default function ShareActions({ id, domain }: { id: string; domain: string }) {
  const [copied, setCopied] = useState(false);

  const url = `${typeof window !== "undefined" ? window.location.origin : ""}/scan/${id}`;

  async function copyUrl() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback: select a hidden input
    }
  }

  function downloadJson() {
    window.open(`/api/scan/${id}/json`, "_blank");
  }

  return (
    <div className="mb-8 flex flex-wrap gap-2">
      <button
        onClick={copyUrl}
        className="rounded border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 ff-mono text-xs text-[var(--fg-muted)] hover:text-[var(--fg-secondary)] hover:border-[var(--border-hover)] transition-all"
      >
        {copied ? "Copied" : "Copy link"}
      </button>
    </div>
  );
}
