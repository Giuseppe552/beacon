"use client";

import { useState } from "react";
import ScanForm from "./ScanForm";
import CompareForm from "./CompareForm";

export default function ScanTabs() {
  const [mode, setMode] = useState<"scan" | "compare">("scan");

  return (
    <div className="w-full max-w-xl mx-auto">
      <div className="flex justify-center gap-1 mb-6">
        <button
          onClick={() => setMode("scan")}
          className={`px-4 py-1.5 text-sm rounded-full transition-all ${
            mode === "scan"
              ? "bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/30"
              : "text-[var(--fg-dim)] hover:text-[var(--fg-muted)] border border-transparent"
          }`}
        >
          Scan
        </button>
        <button
          onClick={() => setMode("compare")}
          className={`px-4 py-1.5 text-sm rounded-full transition-all ${
            mode === "compare"
              ? "bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/30"
              : "text-[var(--fg-dim)] hover:text-[var(--fg-muted)] border border-transparent"
          }`}
        >
          Compare
        </button>
      </div>
      {mode === "scan" ? <ScanForm /> : <CompareForm />}
    </div>
  );
}
