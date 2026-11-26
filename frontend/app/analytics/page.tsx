"use client";

import React, { useState, useEffect, useCallback } from "react";
import { fetchApi } from "../../services/api-client";
import type {
  ContextAssessmentReport,
  EvidenceIntelligenceSummary,
  ExecutionReliabilityMetrics,
  ScanAnalytics,
  ScanComparison,
  ScanPlan,
  SecurityCoverageReport,
} from "../../types/models";

interface ScanOption {
  id: string;
  target_url: string;
  status: string;
  findings_count?: number;
}

export default function AnalyticsPage() {
  const [analytics, setAnalytics] = useState<ScanAnalytics | null>(null);
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");

  const [scanPlan, setScanPlan] = useState<ScanPlan | null>(null);
  const [coverage, setCoverage] = useState<SecurityCoverageReport | null>(null);
  const [contextReport, setContextReport] = useState<ContextAssessmentReport | null>(null);
  const [reliability, setReliability] = useState<ExecutionReliabilityMetrics | null>(null);
  const [evidenceIntel, setEvidenceIntel] = useState<EvidenceIntelligenceSummary | null>(null);

  const [baselineId, setBaselineId] = useState<string>("");
  const [currentId, setCurrentId] = useState<string>("");
  const [comparison, setComparison] = useState<ScanComparison | null>(null);

  const [activeTab, setActiveTab] = useState<"overview" | "planner" | "coverage" | "reliability" | "compare">("overview");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadOverviewAndScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [overviewRes, scansRes] = await Promise.all([
        fetchApi<ScanAnalytics>("/analytics/overview"),
        fetchApi<ScanOption[]>("/scans/"),
      ]);
      setAnalytics(overviewRes);
      if (Array.isArray(scansRes)) {
        setScans(scansRes);
        const completed = scansRes.filter((s) => s.status === "COMPLETED");
        if (completed.length > 0 && !selectedScanId) {
          setSelectedScanId(completed[0].id);
          setCurrentId(completed[0].id);
          setBaselineId(completed[1]?.id || completed[0].id);
        }
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load security analytics.");
    } finally {
      setLoading(false);
    }
  }, [selectedScanId]);

  const loadScanDetails = useCallback(async (scanId: string) => {
    if (!scanId) return;
    try {
      const [planRes, covRes, ctxRes, relRes, evRes] = await Promise.all([
        fetchApi<ScanPlan>(`/scans/${scanId}/plan`).catch(() => null),
        fetchApi<SecurityCoverageReport>(`/scans/${scanId}/coverage`).catch(() => null),
        fetchApi<ContextAssessmentReport>(`/scans/${scanId}/context-assessment`).catch(() => null),
        fetchApi<ExecutionReliabilityMetrics>(`/scans/${scanId}/reliability`).catch(() => null),
        fetchApi<EvidenceIntelligenceSummary>(`/scans/${scanId}/evidence-intelligence`).catch(() => null),
      ]);
      setScanPlan(planRes);
      setCoverage(covRes);
      setContextReport(ctxRes);
      setReliability(relRes);
      setEvidenceIntel(evRes);
    } catch {
      // Handled gracefully per-card
    }
  }, []);

  useEffect(() => {
    loadOverviewAndScans();
  }, [loadOverviewAndScans]);

  useEffect(() => {
    if (selectedScanId) {
      loadScanDetails(selectedScanId);
    }
  }, [selectedScanId, loadScanDetails]);

  const handleCompare = async () => {
    if (!baselineId || !currentId) return;
    setError(null);
    try {
      const res = await fetchApi<ScanComparison>(
        `/analytics/compare?baseline_scan_id=${baselineId}&current_scan_id=${currentId}`
      );
      setComparison(res);
    } catch (err: any) {
      setError(err?.message || "Scan comparison failed.");
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border border-slate-800 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/60 to-slate-900 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
              PHASE 6
            </span>
            <h1 className="text-2xl font-bold text-white">Security Scanning Intelligence & Analytics</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Explainable scan planning, OWASP Top 10:2021 coverage intelligence, execution reliability, evidence quality, and scan comparison
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            aria-label="Select Scan for Telemetry"
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 font-mono"
          >
            <option value="">Select Completed Scan...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_url} ({s.status})
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg border border-red-900/60 bg-red-950/30 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="border-b border-slate-800 flex flex-wrap gap-4 text-sm font-medium">
        {[
          { id: "overview", label: "Analytics Overview" },
          { id: "planner", label: "Scan Plan & Context" },
          { id: "coverage", label: "OWASP Coverage" },
          { id: "reliability", label: "Reliability & Evidence" },
          { id: "compare", label: "Scan Comparison" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`pb-3 px-1 border-b-2 transition-colors ${
              activeTab === tab.id
                ? "border-cyan-500 text-cyan-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading && !analytics ? (
        <div className="p-12 text-center text-slate-400 border border-slate-800 rounded-xl">
          Loading real-time security analytics...
        </div>
      ) : (
        <>
          {/* Tab 1: Overview */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                  <span className="text-xs text-slate-400 uppercase font-semibold">Scans Analyzed</span>
                  <p className="text-2xl font-bold text-white mt-1">{analytics?.total_scans_analyzed || 0}</p>
                </div>
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                  <span className="text-xs text-slate-400 uppercase font-semibold">Total Findings</span>
                  <p className="text-2xl font-bold text-cyan-400 mt-1">{analytics?.total_findings_across_scans || 0}</p>
                </div>
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                  <span className="text-xs text-slate-400 uppercase font-semibold">Avg DAST Coverage</span>
                  <p className="text-2xl font-bold text-emerald-400 mt-1">{analytics?.average_dast_coverage_percent || 0}%</p>
                </div>
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                  <span className="text-xs text-slate-400 uppercase font-semibold">Tech Patterns</span>
                  <p className="text-2xl font-bold text-purple-400 mt-1">
                    {Object.keys(analytics?.technology_risk_patterns || {}).length}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
                  <h3 className="text-sm font-semibold text-white">Top Vulnerable Categories</h3>
                  {Object.entries(analytics?.top_vulnerable_categories || {}).map(([cat, count]) => (
                    <div key={cat} className="flex justify-between text-xs py-1 border-b border-slate-800/60">
                      <span className="font-mono text-slate-300">{cat}</span>
                      <span className="font-bold text-cyan-400">{count}</span>
                    </div>
                  ))}
                  {Object.keys(analytics?.top_vulnerable_categories || {}).length === 0 && (
                    <p className="text-xs text-slate-500">No scan findings recorded yet.</p>
                  )}
                </div>

                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
                  <h3 className="text-sm font-semibold text-white">Endpoint Exposure Breakdown</h3>
                  {Object.entries(analytics?.endpoint_exposure_breakdown || {}).map(([exp, count]) => (
                    <div key={exp} className="flex justify-between text-xs py-1 border-b border-slate-800/60">
                      <span className="font-mono text-slate-300">{exp}</span>
                      <span className="font-bold text-amber-400">{count}</span>
                    </div>
                  ))}
                  {Object.keys(analytics?.endpoint_exposure_breakdown || {}).length === 0 && (
                    <p className="text-xs text-slate-500">No exposure telemetry yet.</p>
                  )}
                </div>

                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
                  <h3 className="text-sm font-semibold text-white">Technology Risk Patterns</h3>
                  {Object.entries(analytics?.technology_risk_patterns || {}).map(([tech, count]) => (
                    <div key={tech} className="flex justify-between text-xs py-1 border-b border-slate-800/60">
                      <span className="font-mono text-slate-300">{tech}</span>
                      <span className="font-bold text-purple-400">{count}</span>
                    </div>
                  ))}
                  {Object.keys(analytics?.technology_risk_patterns || {}).length === 0 && (
                    <p className="text-xs text-slate-500">No technology patterns observed yet.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Scan Plan & Context */}
          {activeTab === "planner" && (
            <div className="space-y-6">
              {scanPlan ? (
                <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-base font-semibold text-white">Explainable Scan Plan</h3>
                    <span className="text-xs font-mono text-cyan-400">
                      Budget: {scanPlan.estimated_total_probes}/{scanPlan.allocated_probe_budget} probes
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{scanPlan.planner_summary}</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-emerald-400">
                        Planned Active Targets ({scanPlan.planned_targets_count})
                      </span>
                      {scanPlan.planned_checks.slice(0, 12).map((p, idx) => (
                        <div key={idx} className="p-2.5 rounded border border-slate-800 bg-slate-950/60 text-xs space-y-1">
                          <div className="font-mono text-cyan-300 break-all">{p.method} {p.url}</div>
                          <div className="text-[11px] text-slate-400">Analyzers: {p.selected_analyzers.join(", ")}</div>
                          <div className="text-[11px] text-slate-500">{p.rationale}</div>
                        </div>
                      ))}
                    </div>
                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-amber-400">
                        Pruned / Skipped Checks ({scanPlan.skipped_targets_count})
                      </span>
                      {scanPlan.skipped_checks.slice(0, 12).map((s, idx) => (
                        <div key={idx} className="p-2.5 rounded border border-slate-800 bg-slate-950/60 text-xs space-y-1">
                          <div className="font-mono text-slate-300 break-all">{s.url}</div>
                          <div className="text-[11px] text-amber-300">{s.reason}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-xl">
                  Select a completed scan above to inspect its generated scan plan.
                </div>
              )}

              {contextReport && contextReport.suggestions.length > 0 && (
                <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-3">
                  <h3 className="text-base font-semibold text-white">Context-Aware Assessment Suggestions</h3>
                  <p className="text-xs text-slate-400">{contextReport.summary}</p>
                  <div className="space-y-2">
                    {contextReport.suggestions.map((sg) => (
                      <div key={sg.suggestion_id} className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 text-xs space-y-1">
                        <div className="flex justify-between">
                          <span className="font-mono font-semibold text-cyan-400">{sg.category}</span>
                          <span className="font-mono text-amber-400">{sg.priority}</span>
                        </div>
                        <div className="font-mono text-slate-300 break-all">{sg.target_url}</div>
                        <p className="text-slate-300">{sg.recommended_safe_check}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 3: OWASP Coverage */}
          {activeTab === "coverage" && (
            <div className="space-y-4">
              {coverage ? (
                <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
                  <div className="flex flex-wrap justify-between items-center gap-2">
                    <div>
                      <h3 className="text-base font-semibold text-white">OWASP Top 10:2021 Security Coverage Matrix</h3>
                      <p className="text-xs text-slate-400 mt-1">{coverage.honesty_disclaimer}</p>
                    </div>
                    <span className="px-3 py-1 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-sm font-bold">
                      {coverage.overall_dast_coverage_percent}% DAST Coverage
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase">
                        <tr>
                          <th className="p-3">Category</th>
                          <th className="p-3">Status</th>
                          <th className="p-3">Findings</th>
                          <th className="p-3">Explanation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {coverage.owasp_categories.map((c) => (
                          <tr key={c.owasp_id}>
                            <td className="p-3 font-semibold text-white">{c.owasp_id} {c.owasp_name}</td>
                            <td className="p-3 font-mono text-cyan-400">{c.status}</td>
                            <td className="p-3 font-mono text-slate-200">{c.findings_detected}</td>
                            <td className="p-3 text-slate-400">{c.explanation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-xl">
                  Select a completed scan to inspect OWASP coverage telemetry.
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Reliability & Evidence */}
          {activeTab === "reliability" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-3">
                <h3 className="text-base font-semibold text-white">Execution Reliability & Timings</h3>
                {reliability ? (
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Reliability Status</span>
                      <span className="font-mono text-emerald-400">{reliability.reliability_status}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Requests Attempted / Succeeded</span>
                      <span className="font-mono text-slate-200">{reliability.total_requests_attempted} / {reliability.successful_requests}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Retries / Timeouts / 429s</span>
                      <span className="font-mono text-slate-200">{reliability.retried_requests} / {reliability.timed_out_requests} / {reliability.rate_limited_429_count}</span>
                    </div>
                    <div className="pt-2">
                      <span className="text-slate-400 font-semibold block mb-1">Stage Timings (seconds)</span>
                      {Object.entries(reliability.stage_timings_seconds).map(([st, sec]) => (
                        <div key={st} className="flex justify-between py-0.5 font-mono text-slate-300">
                          <span>{st}</span>
                          <span>{sec}s</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Select a completed scan to inspect reliability metrics.</p>
                )}
              </div>

              <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-3">
                <h3 className="text-base font-semibold text-white">Evidence Quality & Chain of Custody</h3>
                {evidenceIntel ? (
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Total Sealed SHA-256 Records</span>
                      <span className="font-mono text-emerald-400">{evidenceIntel.sealed_sha256_count} / {evidenceIntel.total_evidence_records}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Redaction Verified Clean</span>
                      <span className="font-mono text-emerald-400">{evidenceIntel.redacted_secrets_confirmed ? "YES" : "REVIEW"}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Average Confidence Score</span>
                      <span className="font-mono text-cyan-400">{Math.round(evidenceIntel.average_confidence_score * 100)}%</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Contradictory Evidence Signals</span>
                      <span className="font-mono text-amber-400">{evidenceIntel.contradictory_evidence_count}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Select a completed scan to inspect evidence intelligence.</p>
                )}
              </div>
            </div>
          )}

          {/* Tab 5: Scan Comparison */}
          {activeTab === "compare" && (
            <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
              <h3 className="text-base font-semibold text-white">Baseline vs Current Scan Comparison</h3>
              <div className="flex flex-wrap items-center gap-3">
                <select
                  aria-label="Baseline Scan"
                  value={baselineId}
                  onChange={(e) => setBaselineId(e.target.value)}
                  className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 font-mono"
                >
                  <option value="">Baseline Scan...</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>{s.target_url} ({s.id.slice(0, 8)})</option>
                  ))}
                </select>
                <select
                  aria-label="Current Scan"
                  value={currentId}
                  onChange={(e) => setCurrentId(e.target.value)}
                  className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 font-mono"
                >
                  <option value="">Current Scan...</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>{s.target_url} ({s.id.slice(0, 8)})</option>
                  ))}
                </select>
                <button
                  onClick={handleCompare}
                  disabled={!baselineId || !currentId}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-medium"
                >
                  Compare Scans
                </button>
              </div>

              {comparison && (
                <div className="p-4 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2 text-xs">
                  <p className="text-cyan-300 font-medium">{comparison.summary}</p>
                  <div className="grid grid-cols-3 gap-4 pt-2">
                    <div>
                      <span className="text-slate-400 block">New Findings</span>
                      <span className="text-lg font-bold text-rose-400">{comparison.new_findings_count}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Resolved Findings</span>
                      <span className="text-lg font-bold text-emerald-400">{comparison.resolved_findings_count}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Persisting Findings</span>
                      <span className="text-lg font-bold text-amber-400">{comparison.persisting_findings_count}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
