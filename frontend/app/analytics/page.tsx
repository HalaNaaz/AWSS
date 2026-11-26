"use client";

import React, { useState, useEffect, useCallback } from "react";
import { fetchApi } from "../../services/api-client";
import { PanelHeader, MetricCell, Button } from "../../components/ui/swiss-components";
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
      <PanelHeader
        tag="07 // PHASE 6"
        title="Security Scanning Intelligence & Analytics"
        subtitle="Explainable scan planning, OWASP Top 10:2021 coverage intelligence, execution reliability, evidence quality, and scan comparison"
        actions={
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider whitespace-nowrap">
              Scope Telemetry:
            </span>
            <select
              aria-label="Select Scan for Telemetry"
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="px-3 py-2 bg-surface-subtle border border-swiss-border text-xs text-ink-primary font-mono focus:outline-none focus:border-accent w-full sm:w-auto"
            >
              <option value="">Select Completed Scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_url} ({s.status})
                </option>
              ))}
            </select>
          </div>
        }
      />

      {error && (
        <div className="p-3 border-l-2 border-l-accent border border-swiss-border bg-surface text-xs font-mono text-accent">
          {error}
        </div>
      )}

      {/* Modular Swiss Navigation Tabs */}
      <div className="border border-swiss-border bg-surface flex flex-wrap text-xs font-mono uppercase tracking-wider">
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
            className={`py-3 px-4 sm:px-5 border-r border-b md:border-b-0 border-swiss-border transition-colors ${
              activeTab === tab.id
                ? "bg-surface-subtle text-accent font-bold border-t-2 border-t-accent"
                : "text-ink-muted hover:text-ink-primary hover:bg-surface-subtle"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading && !analytics ? (
        <div className="p-12 text-center text-ink-muted border border-dashed border-swiss-border bg-surface font-mono text-xs uppercase tracking-wider">
          Loading real-time security analytics...
        </div>
      ) : (
        <>
          {/* Tab 1: Overview */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <MetricCell
                  index="01"
                  label="Scans Analyzed"
                  value={analytics?.total_scans_analyzed || 0}
                  trend="Lifetime scans"
                />
                <MetricCell
                  index="02"
                  label="Total Findings"
                  value={analytics?.total_findings_across_scans || 0}
                  trend="Detections across runs"
                />
                <MetricCell
                  index="03"
                  label="Avg DAST Coverage"
                  value={`${analytics?.average_dast_coverage_percent || 0}%`}
                  trend="OWASP Top 10 coverage"
                />
                <MetricCell
                  index="04"
                  label="Tech Patterns"
                  value={Object.keys(analytics?.technology_risk_patterns || {}).length}
                  trend="Identified frameworks"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="border border-swiss-border bg-surface p-5 space-y-4">
                  <div className="border-b border-swiss-border pb-2">
                    <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                      DISTRIBUTION
                    </span>
                    <h3 className="font-sans font-bold text-sm text-ink-primary">
                      Top Vulnerable Categories
                    </h3>
                  </div>
                  <div className="space-y-1">
                    {Object.entries(analytics?.top_vulnerable_categories || {}).map(([cat, count]) => (
                      <div key={cat} className="flex justify-between items-center text-xs py-2 border-b border-swiss-border-subtle">
                        <span className="font-mono text-ink-primary">{cat}</span>
                        <span className="font-mono font-bold text-accent">{count}</span>
                      </div>
                    ))}
                    {Object.keys(analytics?.top_vulnerable_categories || {}).length === 0 && (
                      <p className="text-xs font-mono text-ink-muted py-2">No scan findings recorded yet.</p>
                    )}
                  </div>
                </div>

                <div className="border border-swiss-border bg-surface p-5 space-y-4">
                  <div className="border-b border-swiss-border pb-2">
                    <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                      SURFACE
                    </span>
                    <h3 className="font-sans font-bold text-sm text-ink-primary">
                      Endpoint Exposure Breakdown
                    </h3>
                  </div>
                  <div className="space-y-1">
                    {Object.entries(analytics?.endpoint_exposure_breakdown || {}).map(([exp, count]) => (
                      <div key={exp} className="flex justify-between items-center text-xs py-2 border-b border-swiss-border-subtle">
                        <span className="font-mono text-ink-primary">{exp}</span>
                        <span className="font-mono font-bold text-ink-primary">{count}</span>
                      </div>
                    ))}
                    {Object.keys(analytics?.endpoint_exposure_breakdown || {}).length === 0 && (
                      <p className="text-xs font-mono text-ink-muted py-2">No exposure telemetry yet.</p>
                    )}
                  </div>
                </div>

                <div className="border border-swiss-border bg-surface p-5 space-y-4">
                  <div className="border-b border-swiss-border pb-2">
                    <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                      PATTERNS
                    </span>
                    <h3 className="font-sans font-bold text-sm text-ink-primary">
                      Technology Risk Patterns
                    </h3>
                  </div>
                  <div className="space-y-1">
                    {Object.entries(analytics?.technology_risk_patterns || {}).map(([tech, count]) => (
                      <div key={tech} className="flex justify-between items-center text-xs py-2 border-b border-swiss-border-subtle">
                        <span className="font-mono text-ink-primary">{tech}</span>
                        <span className="font-mono font-bold text-accent">{count}</span>
                      </div>
                    ))}
                    {Object.keys(analytics?.technology_risk_patterns || {}).length === 0 && (
                      <p className="text-xs font-mono text-ink-muted py-2">No technology patterns observed yet.</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Scan Plan & Context */}
          {activeTab === "planner" && (
            <div className="space-y-6">
              {scanPlan ? (
                <div className="border border-swiss-border bg-surface p-6 space-y-6">
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-swiss-border pb-4">
                    <div>
                      <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                        DETERMINISTIC PLANNER
                      </span>
                      <h3 className="font-sans font-bold text-base text-ink-primary">
                        Explainable Scan Plan
                      </h3>
                    </div>
                    <span className="font-mono text-xs px-2.5 py-1 bg-surface-subtle border border-swiss-border text-accent font-semibold">
                      Budget: {scanPlan.estimated_total_probes} / {scanPlan.allocated_probe_budget} probes
                    </span>
                  </div>
                  <p className="font-mono text-xs text-ink-secondary leading-relaxed">
                    {scanPlan.planner_summary}
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <div className="flex justify-between items-center border-b border-swiss-border pb-2">
                        <span className="font-mono text-xs font-bold uppercase text-ink-primary tracking-wider">
                          Planned Active Targets ({scanPlan.planned_targets_count})
                        </span>
                      </div>
                      <div className="space-y-2 max-h-[500px] overflow-auto pr-1">
                        {scanPlan.planned_checks.slice(0, 16).map((p, idx) => (
                          <div key={idx} className="p-3 border border-swiss-border bg-surface-subtle text-xs space-y-1">
                            <div className="font-mono text-accent font-bold break-all">
                              {p.method} {p.url}
                            </div>
                            <div className="font-mono text-[11px] text-ink-muted">
                              Analyzers: {p.selected_analyzers.join(", ")}
                            </div>
                            <div className="text-[11px] text-ink-primary">
                              {p.rationale}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div className="flex justify-between items-center border-b border-swiss-border pb-2">
                        <span className="font-mono text-xs font-bold uppercase text-ink-muted tracking-wider">
                          Pruned / Skipped Checks ({scanPlan.skipped_targets_count})
                        </span>
                      </div>
                      <div className="space-y-2 max-h-[500px] overflow-auto pr-1">
                        {scanPlan.skipped_checks.slice(0, 16).map((s, idx) => (
                          <div key={idx} className="p-3 border border-dashed border-swiss-border bg-surface-subtle text-xs space-y-1">
                            <div className="font-mono text-ink-primary break-all">
                              {s.url}
                            </div>
                            <div className="font-mono text-[11px] text-ink-muted">
                              {s.reason}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-12 text-center text-ink-muted border border-dashed border-swiss-border bg-surface font-mono text-xs uppercase tracking-wider">
                  Select a completed scan above to inspect its generated scan plan.
                </div>
              )}

              {contextReport && contextReport.suggestions.length > 0 && (
                <div className="border border-swiss-border bg-surface p-6 space-y-4">
                  <div className="border-b border-swiss-border pb-2">
                    <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                      ASSESSMENT INTEL
                    </span>
                    <h3 className="font-sans font-bold text-base text-ink-primary">
                      Context-Aware Assessment Suggestions
                    </h3>
                  </div>
                  <p className="font-mono text-xs text-ink-muted">{contextReport.summary}</p>
                  <div className="space-y-2">
                    {contextReport.suggestions.map((sg) => (
                      <div key={sg.suggestion_id} className="p-3 border border-swiss-border bg-surface-subtle text-xs space-y-1.5">
                        <div className="flex justify-between items-center">
                          <span className="font-mono font-bold text-accent">{sg.category}</span>
                          <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 bg-surface border border-swiss-border text-ink-primary">
                            {sg.priority}
                          </span>
                        </div>
                        <div className="font-mono text-ink-primary break-all">{sg.target_url}</div>
                        <p className="text-ink-secondary leading-relaxed">{sg.recommended_safe_check}</p>
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
                <div className="border border-swiss-border bg-surface p-6 space-y-6">
                  <div className="flex flex-wrap justify-between items-start gap-4 border-b border-swiss-border pb-4">
                    <div>
                      <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                        BENCHMARK COMPLIANCE
                      </span>
                      <h3 className="font-sans font-bold text-base text-ink-primary">
                        OWASP Top 10:2021 Security Coverage Matrix
                      </h3>
                      <p className="font-mono text-xs text-ink-muted mt-1">{coverage.honesty_disclaimer}</p>
                    </div>
                    <span className="px-3 py-1.5 bg-surface-subtle border border-swiss-border text-accent font-mono text-sm font-bold">
                      {coverage.overall_dast_coverage_percent}% DAST Coverage
                    </span>
                  </div>
                  <div className="overflow-x-auto border border-swiss-border">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-surface-subtle border-b border-swiss-border font-mono text-[10px] text-ink-muted uppercase tracking-wider">
                        <tr>
                          <th className="p-3 font-medium">Category</th>
                          <th className="p-3 font-medium">Status</th>
                          <th className="p-3 font-medium">Findings</th>
                          <th className="p-3 font-medium">Explanation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-swiss-border-subtle">
                        {coverage.owasp_categories.map((c) => (
                          <tr key={c.owasp_id} className="hover:bg-surface-subtle/50">
                            <td className="p-3 font-mono font-semibold text-ink-primary">{c.owasp_id} {c.owasp_name}</td>
                            <td className="p-3 font-mono text-accent font-semibold">{c.status}</td>
                            <td className="p-3 font-mono text-ink-primary">{c.findings_detected}</td>
                            <td className="p-3 font-sans text-ink-secondary text-[11px] leading-relaxed">{c.explanation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="p-12 text-center text-ink-muted border border-dashed border-swiss-border bg-surface font-mono text-xs uppercase tracking-wider">
                  Select a completed scan to inspect OWASP coverage telemetry.
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Reliability & Evidence */}
          {activeTab === "reliability" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="border border-swiss-border bg-surface p-6 space-y-4">
                <div className="border-b border-swiss-border pb-2">
                  <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                    TELEMETRY
                  </span>
                  <h3 className="font-sans font-bold text-base text-ink-primary">
                    Execution Reliability & Timings
                  </h3>
                </div>
                {reliability ? (
                  <div className="space-y-3 text-xs">
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Reliability Status</span>
                      <span className="font-mono text-accent font-bold">{reliability.reliability_status}</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Requests Attempted / Succeeded</span>
                      <span className="font-mono text-ink-primary">{reliability.total_requests_attempted} / {reliability.successful_requests}</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Retries / Timeouts / 429s</span>
                      <span className="font-mono text-ink-primary">{reliability.retried_requests} / {reliability.timed_out_requests} / {reliability.rate_limited_429_count}</span>
                    </div>
                    <div className="pt-2">
                      <span className="font-mono uppercase text-[10px] text-ink-muted tracking-wider block mb-2">Stage Timings (seconds)</span>
                      <div className="space-y-1">
                        {Object.entries(reliability.stage_timings_seconds).map(([st, sec]) => (
                          <div key={st} className="flex justify-between py-1 border-b border-swiss-border-subtle font-mono text-[11px] text-ink-primary">
                            <span>{st}</span>
                            <span className="font-bold">{sec}s</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs font-mono text-ink-muted py-4">Select a completed scan to inspect reliability metrics.</p>
                )}
              </div>

              <div className="border border-swiss-border bg-surface p-6 space-y-4">
                <div className="border-b border-swiss-border pb-2">
                  <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                    CRYPTOGRAPHIC CUSTODY
                  </span>
                  <h3 className="font-sans font-bold text-base text-ink-primary">
                    Evidence Quality & Chain of Custody
                  </h3>
                </div>
                {evidenceIntel ? (
                  <div className="space-y-3 text-xs">
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Total Sealed SHA-256 Records</span>
                      <span className="font-mono text-accent font-bold">{evidenceIntel.sealed_sha256_count} / {evidenceIntel.total_evidence_records}</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Redaction Verified Clean</span>
                      <span className="font-mono text-ink-primary font-bold">{evidenceIntel.redacted_secrets_confirmed ? "YES" : "REVIEW"}</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Average Confidence Score</span>
                      <span className="font-mono text-accent font-bold">{Math.round(evidenceIntel.average_confidence_score * 100)}%</span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-swiss-border-subtle">
                      <span className="text-ink-muted font-mono uppercase text-[11px]">Contradictory Evidence Signals</span>
                      <span className="font-mono text-ink-primary">{evidenceIntel.contradictory_evidence_count}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs font-mono text-ink-muted py-4">Select a completed scan to inspect evidence intelligence.</p>
                )}
              </div>
            </div>
          )}

          {/* Tab 5: Scan Comparison */}
          {activeTab === "compare" && (
            <div className="border border-swiss-border bg-surface p-6 space-y-6">
              <div className="border-b border-swiss-border pb-2">
                <span className="font-mono text-[10px] text-ink-muted uppercase tracking-widest block">
                  REGRESSION ANALYSIS
                </span>
                <h3 className="font-sans font-bold text-base text-ink-primary">
                  Baseline vs Current Scan Comparison
                </h3>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <select
                  aria-label="Baseline Scan"
                  value={baselineId}
                  onChange={(e) => setBaselineId(e.target.value)}
                  className="px-3 py-2 bg-surface-subtle border border-swiss-border text-xs text-ink-primary font-mono focus:outline-none focus:border-accent"
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
                  className="px-3 py-2 bg-surface-subtle border border-swiss-border text-xs text-ink-primary font-mono focus:outline-none focus:border-accent"
                >
                  <option value="">Current Scan...</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>{s.target_url} ({s.id.slice(0, 8)})</option>
                  ))}
                </select>
                <Button
                  onClick={handleCompare}
                  disabled={!baselineId || !currentId}
                  variant="primary"
                  size="sm"
                >
                  Compare Scans
                </Button>
              </div>

              {comparison && (
                <div className="p-4 border border-swiss-border bg-surface-subtle space-y-4">
                  <p className="font-mono text-xs text-accent font-semibold">{comparison.summary}</p>
                  <div className="grid grid-cols-3 gap-4 pt-2 border-t border-swiss-border">
                    <div className="border-r border-swiss-border pr-2">
                      <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider block">New Findings</span>
                      <span className="font-mono text-xl font-bold text-accent">{comparison.new_findings_count}</span>
                    </div>
                    <div className="border-r border-swiss-border pr-2">
                      <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider block">Resolved Findings</span>
                      <span className="font-mono text-xl font-bold text-ink-primary">{comparison.resolved_findings_count}</span>
                    </div>
                    <div>
                      <span className="font-mono text-[10px] uppercase text-ink-muted tracking-wider block">Persisting Findings</span>
                      <span className="font-mono text-xl font-bold text-ink-muted">{comparison.persisting_findings_count}</span>
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
