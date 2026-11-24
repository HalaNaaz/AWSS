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
    <div className="border border-red-900/60 rounded-xl bg-red-950/20 p-8 text-center space-y-4 max-w-lg mx-auto mt-12">
      <h2 className="text-xl font-bold text-red-400">Application Error</h2>
      <p className="text-sm text-slate-300">
        {error.message || 'An unexpected error occurred in the security dashboard.'}
      </p>
      <button
        onClick={() => reset()}
        className="px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white font-medium text-sm transition-colors"
      >
        Retry Action
      </button>
    </div>
  );
}
