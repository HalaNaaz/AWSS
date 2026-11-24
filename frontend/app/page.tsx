import React from "react";

export default function OverviewDashboard() {
  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="border border-slate-800 rounded-xl bg-gradient-to-r from-slate-900/80 via-slate-900/40 to-slate-900/80 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Security Assessment Overview</h1>
          <p className="text-sm text-slate-400 mt-1">
            Ashlynx WebSec Scanner — Continuous Dynamic Application Security Testing (DAST)
          </p>
        </div>
        <div className="flex gap-3">
          <button className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors shadow-lg shadow-cyan-600/20">
            + New Scan
          </button>
          <button className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-sm transition-colors border border-slate-700">
            Register Target
          </button>
        </div>
      </div>

      {/* Severity Counters Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="p-4 rounded-xl border border-red-950/60 bg-red-950/10 backdrop-blur">
          <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">Critical</span>
          <p className="text-3xl font-extrabold text-red-500 mt-2">0</p>
          <span className="text-xs text-slate-400 mt-1 block">Immediate action</span>
        </div>
        <div className="p-4 rounded-xl border border-orange-950/60 bg-orange-950/10 backdrop-blur">
          <span className="text-xs font-semibold text-orange-400 uppercase tracking-wider">High</span>
          <p className="text-3xl font-extrabold text-orange-500 mt-2">0</p>
          <span className="text-xs text-slate-400 mt-1 block">Injection / BOLA</span>
        </div>
        <div className="p-4 rounded-xl border border-amber-950/60 bg-amber-950/10 backdrop-blur">
          <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Medium</span>
          <p className="text-3xl font-extrabold text-amber-500 mt-2">0</p>
          <span className="text-xs text-slate-400 mt-1 block">CSRF / Redirects</span>
        </div>
        <div className="p-4 rounded-xl border border-blue-950/60 bg-blue-950/10 backdrop-blur">
          <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Low</span>
          <p className="text-3xl font-extrabold text-blue-400 mt-2">0</p>
          <span className="text-xs text-slate-400 mt-1 block">Cookie flags</span>
        </div>
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/30 backdrop-blur">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Info</span>
          <p className="text-3xl font-extrabold text-slate-300 mt-2">0</p>
          <span className="text-xs text-slate-400 mt-1 block">Endpoints found</span>
        </div>
      </div>

      {/* Main Panels Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Scans Console */}
        <div className="lg:col-span-2 border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">Active Scans</h2>
            <span className="text-xs text-slate-400">Real-time Orchestrator</span>
          </div>
          <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-8 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-800/60 flex items-center justify-center mx-auto text-slate-400">
              ⚡
            </div>
            <p className="text-sm font-medium text-slate-300">No active scans running</p>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Launch a scan via the dashboard or trigger one via the headless CLI:
            </p>
            <code className="text-xs text-cyan-400 bg-slate-900 px-3 py-1.5 rounded-md border border-slate-800 inline-block font-mono">
              ashlynx scan https://example.com --profile QUICK_ASSESSMENT
            </code>
          </div>
        </div>

        {/* Security Engine Status */}
        <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
          <h2 className="text-lg font-semibold text-white">Engine Guardrails</h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span className="text-slate-400">ScopeGate Anti-SSRF</span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">ENFORCED</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span className="text-slate-400">Two-Phase Verifier</span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">ACTIVE</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span className="text-slate-400">Evidence SHA-256 Seal</span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">ENABLED</span>
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-slate-400">Rate Limiter</span>
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">10 req/s</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
