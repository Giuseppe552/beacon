import Link from "next/link";

export default function ScanNotFound() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center px-5">
      <h1 className="ff-mono text-2xl font-bold text-[var(--fg)]">
        Report not found
      </h1>
      <p className="mt-3 text-sm text-[var(--fg-muted)] text-center max-w-md">
        This scan report has expired or doesn&apos;t exist.
        Reports are kept for 7 days.
      </p>
      <Link
        href="/"
        className="mt-6 rounded border border-[var(--accent)]/30 bg-[var(--accent)]/10 px-5 py-2 ff-mono text-xs font-medium text-[var(--accent)] transition-all hover:bg-[var(--accent)]/20 hover:border-[var(--accent)]/50"
      >
        Scan again
      </Link>
    </main>
  );
}
