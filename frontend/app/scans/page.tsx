"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { fetchApi } from "../../services/api-client";
import {
  PanelHeader,
  StatusBadge,
  Button,
} from "../../components/ui/swiss-components";
import { Crosshair, Plus, RefreshCw, Layers } from "lucide-react";

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
      {/* Editorial Header */}
      <PanelHeader
        tag="OPS // REGISTRY"
        title="Scan Execution Registry"
        subtitle="Real-time multi-phase DAST orchestrator jobs, crawl metrics, and live execution status"
        actions={
          <div className="flex items-center gap-2">
            <Button
              onClick={loadScans}
              variant="outline"
              size="md"
              title="Refresh Registry"
            >
              <RefreshCw size={12} className={`mr-1 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Link
              href="/"
              className="inline-flex items-center px-3 py-1.5 text-xs font-mono font-semibold tracking-wider uppercase border border-accent bg-accent text-white hover:bg-accent-hover transition-colors"
            >
              + New Scan
            </Link>
          </div>
        }
      />

      {/* Scans Registry Table */}
      <div className="border border-swiss-border bg-surface overflow-hidden">
        <div className="px-4 py-2.5 border-b border-swiss-border bg-surface-subtle flex justify-between items-center text-xs font-mono text-ink-muted">
          <span>ORCHESTRATOR JOBS ({scans.length})</span>
          <span>POLLING CADENCE: 3000MS</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
              <tr>
                <th className="p-3 font-semibold">Status</th>
                <th className="p-3 font-semibold">Scan Job ID</th>
                <th className="p-3 font-semibold">Target URL</th>
                <th className="p-3 font-semibold">Profile</th>
                <th className="p-3 font-semibold">Duration</th>
                <th className="p-3 font-semibold">URLs Crawled</th>
                <th className="p-3 font-semibold">Findings</th>
                <th className="p-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-swiss-border-subtle font-mono text-xs">
              {scans.map((s) => (
                <tr key={s.id} className="hover:bg-surface-subtle/80 transition-colors">
                  <td className="p-3">
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="p-3 text-ink-muted">{s.id.slice(0, 8)}...</td>
                  <td className="p-3 font-semibold text-ink-primary">{s.target_url}</td>
                  <td className="p-3 text-ink-secondary">{s.profile}</td>
                  <td className="p-3 text-ink-muted tabular-nums">{s.duration_seconds || 0}s</td>
                  <td className="p-3 text-ink-secondary tabular-nums">{s.urls_crawled || 0}</td>
                  <td className="p-3 font-bold text-accent tabular-nums">{s.findings_count || 0}</td>
                  <td className="p-3 text-right space-x-1.5 whitespace-nowrap">
                    <Link
                      href={`/attack-surface?scan_id=${s.id}`}
                      className="inline-flex items-center px-2 py-1 text-[11px] font-mono font-semibold uppercase tracking-wider border border-swiss-border bg-surface-subtle hover:bg-surface text-ink-primary transition-colors"
                    >
                      Surface
                    </Link>
                    <Link
                      href={`/findings?scan_id=${s.id}`}
                      className="inline-flex items-center px-2 py-1 text-[11px] font-mono font-semibold uppercase tracking-wider border border-swiss-border bg-surface hover:bg-surface-subtle text-ink-primary transition-colors"
                    >
                      Findings
                    </Link>
                  </td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-ink-muted font-mono text-xs">
                    No scan jobs registered. Launch an assessment from the Overview dashboard.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
