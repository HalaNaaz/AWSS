"use client";

import React, { useState, useEffect } from "react";
import { fetchApi } from "../../services/api-client";
import { PanelHeader, Button } from "../../components/ui/swiss-components";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

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

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [reportFormat, setReportFormat] = useState<string>("html");
  const [reportContent, setReportContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const queryId = params.get("scan_id");
      if (queryId) {
        setSelectedScanId(queryId);
      }
    }

    fetchApi<ScanJob[]>("/scans/")
      .then((res) => {
        if (Array.isArray(res) && res.length > 0) {
          setScans(res);
          setSelectedScanId((prev) => {
            if (prev) return prev;
            const first = res.find((s) => s.status === "COMPLETED") || res[0];
            return first?.id || "";
          });
        }
      })
      .catch(() => {});
  }, []);

  const handlePreview = async () => {
    if (!selectedScanId) return;
    setLoading(true);
    try {
      const resp = await fetch(
        `${API_BASE}/reports/${selectedScanId}?format=${reportFormat}&download=false`
      );
      if (resp.ok) {
        const text = await resp.text();
        setReportContent(text);
      } else {
        setReportContent(`Report unavailable: ${resp.statusText}`);
      }
    } catch (err: any) {
      setReportContent(`Failed to load report: ${err?.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <PanelHeader
        tag="06 // REPORTS"
        title="Security Assessment Reports"
        subtitle="Export structured JSON, executive HTML, Markdown, and SARIF 2.1.0 security documentation"
        actions={
          scans.length > 0 ? (
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider whitespace-nowrap">
                Scan Target:
              </span>
              <select
                aria-label="Select Scan Target for Report"
                value={selectedScanId}
                onChange={(e) => {
                  setSelectedScanId(e.target.value);
                  setReportContent(null);
                }}
                className="px-3 py-2 bg-surface-subtle border border-swiss-border text-xs text-ink-primary focus:outline-none focus:border-accent font-mono w-full sm:w-auto"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target_url} ({s.status})
                  </option>
                ))}
              </select>
            </div>
          ) : null
        }
      />

      {selectedScanId && (
        <div className="border border-swiss-border bg-surface p-6 space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-swiss-border">
            <div className="space-y-1">
              <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider">
                Selected Scan Job
              </span>
              <p className="font-mono text-sm font-semibold text-ink-primary break-all">
                {selectedScanId}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <select
                aria-label="Report Format"
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value)}
                className="px-3 py-2 bg-surface-subtle border border-swiss-border text-xs text-ink-primary focus:outline-none focus:border-accent font-mono"
              >
                <option value="html">HTML Executive Report</option>
                <option value="json">JSON Structured Data</option>
                <option value="markdown">Markdown Documentation</option>
                <option value="sarif">SARIF 2.1.0 (CI Security)</option>
              </select>

              <Button
                variant="outline"
                size="sm"
                onClick={handlePreview}
                disabled={loading}
              >
                {loading ? "Generating..." : "Preview Report"}
              </Button>

              <a
                href={`${API_BASE}/reports/${selectedScanId}?format=${reportFormat}&download=true`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center font-mono font-medium text-xs uppercase tracking-wider px-3 py-2 bg-accent text-white hover:bg-accent-hover transition-colors shadow-swiss-sm"
              >
                Download {reportFormat.toUpperCase()}
              </a>
            </div>
          </div>

          {reportContent && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-[11px] font-mono text-ink-muted uppercase tracking-wider">
                <span>Output Format: {reportFormat.toUpperCase()}</span>
                <span>Render Engine: Swiss Technical Workstation</span>
              </div>
              <div className="border border-swiss-border bg-canvas overflow-hidden">
                {reportFormat === "html" ? (
                  <iframe
                    srcDoc={reportContent}
                    sandbox=""
                    title="HTML Report Preview"
                    className="w-full h-[650px] border-0 bg-white"
                  />
                ) : (
                  <pre className="p-4 text-xs font-mono text-ink-primary max-h-[550px] overflow-auto whitespace-pre-wrap leading-relaxed">
                    {reportContent}
                  </pre>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {!selectedScanId && (
        <div className="p-12 text-center text-ink-muted border border-dashed border-swiss-border bg-surface">
          <p className="font-mono text-xs uppercase tracking-wider">
            No scan selected. Run a scan from the dashboard to generate assessment reports.
          </p>
        </div>
      )}
    </div>
  );
}
