"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { fetchApi } from "../../services/api-client";

interface ScanJob {
  id: string;
  target_url: string;
  profile: string;
  status: string;
  duration_seconds: number;
  urls_crawled: number;
  findings_count: number;
  created_at: string;
}

export default function ScansPage() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(false);

  const loadScans = async () => {
    try {
      setLoading(true);
      const res = await fetchApi<ScanJob[]>("/scans/");
      if (Array.isArray(res)) {
        setScans(res);
      }
    } catch {
      // Ignored
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-6 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan Execution Registry</h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time multi-phase DAST orchestrator jobs, crawl metrics, and live execution status
          </p>
        </div>
        <Link
          href="/"
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors"
        >
          + New Scan
        </Link>
      </div>

      <div className="border border-slate-800 rounded-xl bg-slate-900/40 overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
            <tr>
              <th className="p-3">Status</th>
              <th className="p-3">Scan Job ID</th>
              <th className="p-3">Target URL</th>
              <th className="p-3">Profile</th>
              <th className="p-3">Duration</th>
              <th className="p-3">URLs Crawled</th>
              <th className="p-3">Findings</th>
              <th className="p-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {scans.map((s) => (
              <tr key={s.id} className="hover:bg-slate-800/30 transition-colors">
                <td className="p-3">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${
                      s.status === "COMPLETED"
                        ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                        : s.status === "RUNNING"
                        ? "bg-cyan-950 text-cyan-400 border border-cyan-800/60 animate-pulse"
                        : s.status === "CANCELLED"
                        ? "bg-slate-800 text-slate-400 border border-slate-700"
                        : "bg-yellow-950 text-yellow-400 border border-yellow-800/60"
                    }`}
                  >
                    {s.status}
                  </span>
                </td>
                <td className="p-3 font-mono text-xs text-slate-400">{s.id.slice(0, 8)}...</td>
                <td className="p-3 font-mono text-xs text-slate-200">{s.target_url}</td>
                <td className="p-3 font-mono text-xs text-slate-300">{s.profile}</td>
                <td className="p-3 font-mono text-xs text-slate-400">{s.duration_seconds || 0}s</td>
                <td className="p-3 font-mono text-xs text-slate-300">{s.urls_crawled || 0}</td>
                <td className="p-3 font-mono font-bold text-cyan-400">{s.findings_count || 0}</td>
                <td className="p-3 text-right space-x-2">
                  <Link
                    href={`/attack-surface?scan_id=${s.id}`}
                    className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-xs text-cyan-400 border border-cyan-800/60"
                  >
                    Attack Surface
                  </Link>
                  <Link
                    href={`/reports?scan_id=${s.id}`}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
                  >
                    Report
                  </Link>
                </td>
              </tr>
            ))}
            {scans.length === 0 && !loading && (
              <tr>
                <td colSpan={8} className="p-8 text-center text-slate-500">
                  No scan jobs currently registered.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
