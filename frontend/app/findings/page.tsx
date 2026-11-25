"use client";

import React, { useState, useEffect } from "react";
import { fetchApi } from "../../services/api-client";

interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description?: string;
  cwe_id: string;
  owasp_category?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  cvss_score: number;
  confidence: number;
  remediation?: string;
  endpoint?: { url: string; method: string; parameter?: string };
  evidence?: { request_raw?: string; response_raw?: string; sha256_hash?: string };
}

export default function FindingsPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    fetchApi<any[]>("/scans/")
      .then((res) => {
        if (Array.isArray(res) && res.length > 0) {
          setScans(res);
          const first = res.find((s) => s.findings_count > 0) || res[0];
          setSelectedScanId(first.id);
          loadFindings(first.id);
        }
      })
      .catch(() => {});
  }, []);

  const loadFindings = async (scanId: string) => {
    if (!scanId) return;
    try {
      const res = await fetchApi<Finding[]>(`/scans/${scanId}/findings`);
      setFindings(res || []);
    } catch {
      setFindings([]);
    }
  };

  const filtered = findings.filter((f) => {
    const matchesSev = severityFilter === "ALL" || f.severity === severityFilter;
    const matchesSearch =
      !searchQuery ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.cwe_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.endpoint && f.endpoint.url.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSev && matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Vulnerability Findings & Evidence</h1>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic vulnerability verifications, passive anomalies, and cryptographic evidence
          </p>
        </div>

        {scans.length > 0 && (
          <select
            value={selectedScanId}
            onChange={(e) => {
              setSelectedScanId(e.target.value);
              loadFindings(e.target.value);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_url} ({s.findings_count || 0} findings)
              </option>
            ))}
          </select>
        )}
      </div>

      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex gap-2">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                severityFilter === sev
                  ? "bg-cyan-600 text-white font-semibold"
                  : "bg-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <input
          type="text"
          placeholder="Search findings by title, CWE, or URL..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 w-full sm:w-72"
        />
      </div>

      <div className="space-y-4">
        {filtered.map((f) => {
          const isExpanded = expandedId === f.id;
          return (
            <div key={f.id} className="border border-slate-800 rounded-xl bg-slate-900/40 p-5 space-y-3">
              <div className="flex justify-between items-start gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        f.severity === "CRITICAL"
                          ? "bg-red-950 text-red-400 border border-red-800"
                          : f.severity === "HIGH"
                          ? "bg-orange-950 text-orange-400 border border-orange-800"
                          : f.severity === "MEDIUM"
                          ? "bg-amber-950 text-amber-400 border border-amber-800"
                          : "bg-blue-950 text-blue-400 border border-blue-800"
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{f.cwe_id}</span>
                    <span className="text-xs text-slate-500">CVSS {f.cvss_score}</span>
                    <span className="text-xs text-slate-500">Confidence {Math.round(f.confidence * 100)}%</span>
                  </div>
                  <h3 className="text-base font-semibold text-white">{f.title}</h3>
                </div>
                <button
                  onClick={() => setExpandedId(isExpanded ? null : f.id)}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 border border-slate-700"
                >
                  {isExpanded ? "Collapse" : "View Details"}
                </button>
              </div>

              {f.endpoint && (
                <p className="text-xs font-mono text-slate-300 bg-slate-950/80 px-2.5 py-1.5 rounded border border-slate-800 break-all">
                  {f.endpoint.method} {f.endpoint.url}
                </p>
              )}

              {isExpanded && (
                <div className="pt-3 border-t border-slate-800/80 space-y-3 text-xs">
                  {f.description && (
                    <div>
                      <span className="font-semibold text-slate-400 block mb-1">Description</span>
                      <p className="text-slate-300 leading-relaxed">{f.description}</p>
                    </div>
                  )}

                  {f.remediation && (
                    <div className="p-3 rounded bg-cyan-950/20 border border-cyan-800/40">
                      <span className="font-semibold text-cyan-400 block mb-1">Remediation Guidance</span>
                      <p className="text-slate-300">{f.remediation}</p>
                    </div>
                  )}

                  {f.evidence && (
                    <div className="space-y-2">
                      <span className="font-semibold text-slate-400 block">Cryptographic Evidence</span>
                      {f.evidence.sha256_hash && (
                        <p className="text-[10px] font-mono text-slate-500 truncate">
                          SHA-256 Seal: {f.evidence.sha256_hash}
                        </p>
                      )}
                      {f.evidence.response_raw && (
                        <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap">
                          {f.evidence.response_raw}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {filtered.length === 0 && (
          <div className="p-12 text-center text-slate-500 border border-slate-800 rounded-xl bg-slate-900/20">
            No findings matching the selected filters.
          </div>
        )}
      </div>
    </div>
  );
}
