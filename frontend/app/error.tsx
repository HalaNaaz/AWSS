'use client';

import React from 'react';

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="border border-swiss-border border-l-4 border-l-accent bg-surface p-10 space-y-5 max-w-lg mx-auto mt-16 shadow-swiss-sm">
      <div className="space-y-1">
        <div className="inline-block px-2 py-0.5 border border-swiss-border font-mono text-[10px] uppercase tracking-widest text-accent bg-accent-subtle">
          {"ERR // EXECUTION FAULT"}
        </div>
        <h1 className="text-lg font-mono font-bold text-ink-primary tracking-tight">
          Application Error
        </h1>
      </div>

      <div className="p-3 border border-swiss-border bg-surface-subtle text-xs font-mono text-accent leading-relaxed break-all">
        {error.message || 'An unexpected error occurred in the security dashboard.'}
        {error.digest && (
          <div className="mt-2 pt-2 border-t border-swiss-border text-[10px] text-ink-muted">
            Digest: {error.digest}
          </div>
        )}
      </div>

      <button
        onClick={() => reset()}
        className="inline-flex items-center justify-center font-mono font-medium text-xs uppercase tracking-wider px-4 py-2 bg-accent text-white hover:bg-accent-hover transition-colors shadow-swiss-sm"
      >
        Retry Action
      </button>
    </div>
  );
}
