import Link from "next/link";

export default function NotFound() {
  return (
    <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-12 text-center space-y-4 max-w-lg mx-auto mt-12">
      <h2 className="text-2xl font-bold text-white">404 — Not Found</h2>
      <p className="text-sm text-slate-400">
        The requested asset or security view could not be located.
      </p>
      <Link
        href="/"
        className="inline-block px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors"
      >
        Return to Overview
      </Link>
    </div>
  );
}
