import Link from "next/link";

export default function NotFound() {
  return (
    <div className="border border-swiss-border bg-surface p-12 text-center space-y-6 max-w-lg mx-auto mt-16 shadow-swiss-sm">
      <div className="space-y-2">
        <div className="inline-block px-2 py-0.5 border border-swiss-border font-mono text-[11px] uppercase tracking-widest text-accent bg-accent-subtle">
          {"SYS // 404"}
        </div>
        <h1 className="text-xl font-mono font-bold tracking-tight text-ink-primary">
          404 — NOT FOUND
        </h1>
        <p className="text-xs font-mono text-ink-muted leading-relaxed">
          The requested security assessment view, target endpoint, or cryptographic artifact could not be located in the current workspace.
        </p>
      </div>

      <div className="pt-2">
        <Link
          href="/"
          className="inline-flex items-center justify-center font-mono font-medium text-xs uppercase tracking-wider px-4 py-2.5 bg-accent text-white hover:bg-accent-hover transition-colors shadow-swiss-sm"
        >
          Return to Overview
        </Link>
      </div>
    </div>
  );
}
