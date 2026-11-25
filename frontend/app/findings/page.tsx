"use client";

import React, { useState, useEffect, useCallback } from "react";
import { fetchApi } from "../../services/api-client";
import type {
  Finding,
  ScanIntelligenceSummary,
  PaginatedResponse,
  ValidationState,
  RemediationStatus,
} from "../../types/models";

interface ScanOption {
  id: string;
  target_url: string;
  findings_count?: number;
  status?: string;
}

export default function FindingsPage() {
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [intelSummary, setIntelSummary] = useState<ScanIntelligenceSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalFindings, setTotalFindings] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const pageSize = 20;

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [confidenceFilter, setConfidenceFilter] = useState<string>("ALL");
  const [validationFilter, setValidationFilter] = useState<string>("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [assetFilter, setAssetFilter] = useState<string>("");
  const [correlationGroupFilter, setCorrelationGroupFilter] = useState<string>("ALL");
  const [remediationFilter, setRemediationFilter] = useState<string>("ALL");
  const [hideDuplicates, setHideDuplicates] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>("");

  // UI state
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [transitionNotes, setTransitionNotes] = useState<string>("");
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    try {
      const res = await fetchApi<ScanOption[]>("/scans/");
      if (Array.isArray(res) && res.length > 0) {
        setScans(res);
        const preferred = res.find((s) => (s.findings_count || 0) > 0) || res[0];
        setSelectedScanId(preferred.id);
      }
    } catch {
      // Scans list optional if querying global findings
    }
  }, []);

  const loadIntelligenceAndFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (selectedScanId) params.set("scan_id", selectedScanId);
      if (severityFilter !== "ALL") params.set("severity", severityFilter);
      if (confidenceFilter !== "ALL") params.set("confidence_level", confidenceFilter);
      if (validationFilter !== "ALL") params.set("validation_state", validationFilter);
      if (categoryFilter !== "ALL") params.set("category", categoryFilter);
      if (assetFilter.trim()) params.set("asset", assetFilter.trim());
      if (correlationGroupFilter !== "ALL") params.set("correlation_group_id", correlationGroupFilter);
      if (remediationFilter !== "ALL") params.set("remediation_status", remediationFilter);
      if (hideDuplicates) params.set("include_duplicates", "false");
      if (searchQuery.trim()) params.set("search", searchQuery.trim());
      params.set("page", String(page));
      params.set("page_size", String(pageSize));

      const paginated = await fetchApi<PaginatedResponse<Finding>>(`/findings/?${params.toString()}`);
      setFindings(paginated.items || []);
      setTotalFindings(paginated.total || 0);
      setTotalPages(paginated.total_pages || 1);

      if (selectedScanId) {
        try {
          const summary = await fetchApi<ScanIntelligenceSummary>(`/scans/${selectedScanId}/intelligence`);
          setIntelSummary(summary);
        } catch {
          setIntelSummary(null);
        }
      } else {
        setIntelSummary(null);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load AVIVE findings intelligence.");
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, [
    selectedScanId,
    severityFilter,
    confidenceFilter,
    validationFilter,
    categoryFilter,
    assetFilter,
    correlationGroupFilter,
    remediationFilter,
    hideDuplicates,
    searchQuery,
    page,
  ]);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  useEffect(() => {
    loadIntelligenceAndFindings();
  }, [loadIntelligenceAndFindings]);

  const handleValidationTransition = async (findingId: string, targetState: ValidationState) => {
    setUpdatingId(findingId);
    setActionMessage(null);
    try {
      await fetchApi<Finding>(`/findings/${findingId}/validate`, {
        method: "POST",
        body: JSON.stringify({
          target_state: targetState,
          actor: "web_analyst",
          validation_method: "dashboard_triage",
          notes: transitionNotes.trim() || `Transitioned via Findings Intelligence UI to ${targetState}`,
          scan_id: selectedScanId || undefined,
        }),
      });
      setTransitionNotes("");
      setActionMessage(`Validation status updated to ${targetState}.`);
      await loadIntelligenceAndFindings();
    } catch (err: any) {
      setError(err?.message || "Failed to update validation state.");
    } finally {
      setUpdatingId(null);
    }
  };

  const handleRemediationUpdate = async (findingId: string, statusVal: RemediationStatus) => {
    setUpdatingId(findingId);
    setActionMessage(null);
    try {
      const qs = selectedScanId ? `?scan_id=${selectedScanId}` : "";
      await fetchApi<Finding>(`/findings/${findingId}/remediation${qs}`, {
        method: "POST",
        body: JSON.stringify({
          remediation_status: statusVal,
          actor: "web_analyst",
        }),
      });
      setActionMessage(`Remediation status updated to ${statusVal}.`);
      await loadIntelligenceAndFindings();
    } catch (err: any) {
      setError(err?.message || "Failed to update remediation status.");
    } finally {
      setUpdatingId(null);
    }
  };

  const priorityBadgeStyle = (prio?: string) => {
    if (prio === "CRITICAL") return "bg-red-950 text-red-300 border-red-700";
    if (prio === "HIGH") return "bg-orange-950 text-orange-300 border-orange-700";
    if (prio === "MEDIUM") return "bg-amber-950 text-amber-300 border-amber-700";
    if (prio === "LOW") return "bg-blue-950 text-blue-300 border-blue-700";
    return "bg-slate-800 text-slate-300 border-slate-700";
  };

  const confidenceBadgeStyle = (lvl?: string) => {
    if (lvl === "HIGH") return "bg-emerald-950 text-emerald-300 border-emerald-700";
    if (lvl === "MEDIUM") return "bg-cyan-950 text-cyan-300 border-cyan-700";
    return "bg-rose-950 text-rose-300 border-rose-700";
  };

  const findingTitleById = (id: string) => {
    const match = findings.find((item) => item.id === id);
    return match ? `${match.title} (${match.cwe_id})` : id;
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
              PHASE 5 · AVIVE
            </span>
            <h1 className="text-2xl font-bold text-white">Vulnerability Findings & Evidence</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Normalized correlation groups, explainable evidence confidence, controlled validation lifecycle, and contextual risk prioritization
          </p>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <label htmlFor="scan-selector" className="text-xs text-slate-400 whitespace-nowrap">
            Scan Scope:
          </label>
          <select
            id="scan-selector"
            value={selectedScanId}
            onChange={(e) => {
              setSelectedScanId(e.target.value);
              setCorrelationGroupFilter("ALL");
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono w-full md:w-72"
          >
            <option value="">All Registered Scans</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_url} ({s.findings_count || 0} findings)
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* AVIVE Intelligence Summary Strip */}
      {intelSummary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Normalized</span>
            <p className="text-2xl font-bold text-white mt-1">{intelSummary.total_raw_findings}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Unique Primary</span>
            <p className="text-2xl font-bold text-cyan-400 mt-1">{intelSummary.unique_primary_findings}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Duplicates Linked</span>
            <p className="text-2xl font-bold text-slate-300 mt-1">{intelSummary.duplicate_findings_count}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Correlation Groups</span>
            <p className="text-2xl font-bold text-purple-400 mt-1">{intelSummary.correlation_groups_count}</p>
          </div>
          <div className="p-4 rounded-xl border border-amber-950/60 bg-amber-950/10">
            <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">Manual Review Needed</span>
            <p className="text-2xl font-bold text-amber-400 mt-1">{intelSummary.manual_review_required_count}</p>
          </div>
        </div>
      )}

      {/* Alerts */}
      {error && (
        <div className="p-3 rounded-lg border border-red-900/60 bg-red-950/30 text-xs text-red-300 flex justify-between items-center">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-white">✕</button>
        </div>
      )}
      {actionMessage && (
        <div className="p-3 rounded-lg border border-emerald-900/60 bg-emerald-950/30 text-xs text-emerald-300 flex justify-between items-center">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Filter Bar */}
      <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-4 space-y-3">
        <div className="flex flex-wrap gap-2 items-center justify-between">
          <div className="flex flex-wrap gap-1.5">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((sev) => (
              <button
                key={sev}
                onClick={() => {
                  setSeverityFilter(sev);
                  setPage(1);
                }}
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
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(1);
            }}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 w-full sm:w-72"
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2 pt-2 border-t border-slate-800/70">
          <select
            aria-label="Confidence Filter"
            value={confidenceFilter}
            onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200"
          >
            <option value="ALL">Confidence: All</option>
            <option value="HIGH">HIGH Confidence</option>
            <option value="MEDIUM">MEDIUM Confidence</option>
            <option value="LOW">LOW Confidence</option>
          </select>

          <select
            aria-label="Validation Status Filter"
            value={validationFilter}
            onChange={(e) => { setValidationFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200"
          >
            <option value="ALL">Validation: All</option>
            <option value="DETECTED">DETECTED</option>
            <option value="NEEDS_REVIEW">NEEDS_REVIEW</option>
            <option value="VALIDATION_PENDING">VALIDATION_PENDING</option>
            <option value="VALIDATED">VALIDATED</option>
            <option value="INCONCLUSIVE">INCONCLUSIVE</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>

          <select
            aria-label="Vulnerability Category Filter"
            value={categoryFilter}
            onChange={(e) => { setCategoryFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200"
          >
            <option value="ALL">Type: All Categories</option>
            <option value="SQL_INJECTION">SQL Injection</option>
            <option value="XSS">XSS</option>
            <option value="SSTI">SSTI</option>
            <option value="SSRF">SSRF</option>
            <option value="XXE">XXE</option>
            <option value="OPEN_REDIRECT">Open Redirect</option>
            <option value="SECURITY_HEADERS">Security Headers</option>
            <option value="COOKIE_SECURITY">Cookie Security</option>
            <option value="CORS_MISCONFIGURATION">CORS Misconfiguration</option>
            <option value="INFORMATION_DISCLOSURE">Info Disclosure</option>
            <option value="TRANSPORT_SECURITY">Transport Security</option>
          </select>

          <select
            aria-label="Correlation Group Filter"
            value={correlationGroupFilter}
            onChange={(e) => { setCorrelationGroupFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 font-mono"
          >
            <option value="ALL">Correlation: All Groups</option>
            {(intelSummary?.correlation_groups || []).map((grp) => (
              <option key={grp.group_id} value={grp.group_id}>
                {grp.group_id} ({grp.relationship_type})
              </option>
            ))}
          </select>

          <select
            aria-label="Remediation Status Filter"
            value={remediationFilter}
            onChange={(e) => { setRemediationFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200"
          >
            <option value="ALL">Remediation: All</option>
            <option value="OPEN">OPEN</option>
            <option value="IN_PROGRESS">IN_PROGRESS</option>
            <option value="FIXED">FIXED</option>
            <option value="VERIFIED_FIXED">VERIFIED_FIXED</option>
            <option value="WONT_FIX">WONT_FIX</option>
          </select>

          <input
            type="text"
            aria-label="Asset Filter"
            placeholder="Filter by host/asset..."
            value={assetFilter}
            onChange={(e) => { setAssetFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500"
          />
        </div>

        <div className="flex items-center justify-between pt-1 text-xs text-slate-400">
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={hideDuplicates}
              onChange={(e) => { setHideDuplicates(e.target.checked); setPage(1); }}
              className="rounded border-slate-700 bg-slate-950"
            />
            <span>Hide Correlated Duplicates (Show Primary Queue Only)</span>
          </label>
          <span>Showing {findings.length} of {totalFindings} findings</span>
        </div>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="p-12 text-center text-slate-400 border border-slate-800 rounded-xl bg-slate-900/20 text-sm">
          Loading normalized findings & AVIVE intelligence...
        </div>
      ) : (
        <div className="space-y-4">
          {findings.map((f) => {
            const isExpanded = expandedId === f.id;
            const intel = f.intelligence;
            const conf = intel?.confidence_assessment;
            const risk = intel?.contextual_risk;
            const rem = intel?.remediation_intelligence;

            return (
              <div
                key={f.id}
                className={`border rounded-xl p-5 space-y-3 transition-colors ${
                  intel?.is_duplicate
                    ? "border-slate-800/60 bg-slate-900/20 opacity-85"
                    : "border-slate-800 bg-slate-900/40"
                }`}
              >
                <div className="flex flex-col sm:flex-row justify-between items-start gap-3">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
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

                      {risk && (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${priorityBadgeStyle(risk.contextual_priority)}`}>
                          CONTEXT PRIO: {risk.contextual_priority} ({risk.contextual_score})
                        </span>
                      )}

                      {conf && (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${confidenceBadgeStyle(conf.level)}`}>
                          {conf.level} CONF ({Math.round(conf.score * 100)}%)
                        </span>
                      )}

                      {intel && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-200 border border-slate-700">
                          {intel.validation_state}
                        </span>
                      )}

                      {intel?.is_duplicate ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-amber-300 border border-amber-800/50">
                          DUPLICATE ({intel.correlation_group_id})
                        </span>
                      ) : intel?.correlation_group_id ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950/60 text-purple-300 border border-purple-800/60">
                          {intel.correlation_relationship}: {intel.correlation_group_id}
                        </span>
                      ) : null}

                      <span className="text-xs font-mono text-slate-400">{f.cwe_id}</span>
                      <span className="text-xs text-slate-500">CVSS {f.cvss_score}</span>
                    </div>

                    <h3 className="text-base font-semibold text-white">{f.title}</h3>
                  </div>

                  <button
                    onClick={() => setExpandedId(isExpanded ? null : f.id)}
                    className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 border border-slate-700 whitespace-nowrap"
                  >
                    {isExpanded ? "Collapse" : "View Details"}
                  </button>
                </div>

                {f.endpoint && (
                  <p className="text-xs font-mono text-slate-300 bg-slate-950/80 px-2.5 py-1.5 rounded border border-slate-800 break-all">
                    {f.endpoint.method} {f.endpoint.url}
                    {f.endpoint.parameter ? ` · param: ${f.endpoint.parameter}` : ""}
                  </p>
                )}

                {isExpanded && (
                  <div className="pt-4 border-t border-slate-800/80 space-y-4 text-xs">
                    {f.description && (
                      <div>
                        <span className="font-semibold text-slate-400 block mb-1">Technical Description</span>
                        <p className="text-slate-300 leading-relaxed">{f.description}</p>
                      </div>
                    )}

                    {/* Phase 5D: Confidence & Evidence Quality */}
                    {conf && (
                      <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="font-semibold text-cyan-400">
                            Explainable Confidence Assessment ({conf.level} · {Math.round(conf.score * 100)}%)
                          </span>
                          {conf.needs_manual_review && (
                            <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 text-[10px] font-mono">
                              MANUAL REVIEW REQUIRED
                            </span>
                          )}
                        </div>
                        <p className="text-slate-300">{conf.explanation}</p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                          <div>
                            <span className="text-[11px] font-semibold text-emerald-400 block mb-1">Contributing Evidence</span>
                            <ul className="list-disc list-inside text-slate-400 space-y-0.5">
                              {conf.contributing_evidence.map((c, i) => <li key={i}>{c}</li>)}
                              {conf.contributing_evidence.length === 0 && <li>None recorded</li>}
                            </ul>
                          </div>
                          <div>
                            <span className="text-[11px] font-semibold text-amber-400 block mb-1">Missing / Contradictory Signals</span>
                            <ul className="list-disc list-inside text-slate-400 space-y-0.5">
                              {conf.missing_evidence.map((m, i) => <li key={`m-${i}`}>{m}</li>)}
                              {conf.contradictory_signals.map((cs, i) => <li key={`c-${i}`} className="text-rose-400">{cs}</li>)}
                              {conf.missing_evidence.length === 0 && conf.contradictory_signals.length === 0 && (
                                <li className="text-emerald-400">No missing or contradictory evidence</li>
                              )}
                            </ul>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Phase 5F: Contextual Risk Assessment & Relationships */}
                    {risk && intel && (
                      <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2">
                        <span className="font-semibold text-purple-400 block">
                          Contextual Risk Rationale & Attack Surface Relationships
                        </span>
                        <p className="text-slate-300">{risk.priority_rationale}</p>
                        <div className="flex flex-wrap gap-2 text-[11px] text-slate-400">
                          <span>Assets: <strong className="text-slate-200">{intel.asset_relationships.join(", ") || "N/A"}</strong></span>
                          <span>· Technologies: <strong className="text-slate-200">{intel.technology_relationships.join(", ") || "None observed"}</strong></span>
                          <span>· Fingerprint: <code className="text-cyan-400">{intel.fingerprint}</code></span>
                        </div>
                        {risk.data_limitations.length > 0 && (
                          <p className="text-[11px] text-amber-300/90">
                            Data Limitations: {risk.data_limitations.join(" | ")}
                          </p>
                        )}
                        {intel.related_finding_ids.length > 0 && (
                          <div className="pt-1">
                            <span className="text-[11px] font-semibold text-slate-400 block mb-1">
                              Correlated / Related Findings ({intel.related_finding_ids.length}):
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {intel.related_finding_ids.slice(0, 6).map((rid) => (
                                <span key={rid} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 font-mono text-[10px] text-slate-300">
                                  {findingTitleById(rid)}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Phase 5G: Remediation Intelligence */}
                    {rem ? (
                      <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 space-y-2">
                        <div className="flex flex-wrap justify-between items-center gap-2">
                          <span className="font-semibold text-cyan-400">
                            Remediation Intelligence ({rem.remediation_priority} · Status: {rem.remediation_status})
                          </span>
                          <div className="flex items-center gap-1.5">
                            {(["OPEN", "IN_PROGRESS", "FIXED", "VERIFIED_FIXED"] as RemediationStatus[]).map((st) => (
                              <button
                                key={st}
                                disabled={updatingId === f.id}
                                onClick={() => handleRemediationUpdate(f.id, st)}
                                className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors ${
                                  rem.remediation_status === st
                                    ? "bg-cyan-600 text-white border-cyan-500"
                                    : "bg-slate-900 text-slate-400 border-slate-700 hover:text-white"
                                }`}
                              >
                                {st}
                              </button>
                            ))}
                          </div>
                        </div>
                        <p className="text-slate-300"><strong>Root Cause:</strong> {rem.root_cause}</p>
                        <p className="text-slate-300"><strong>Why It Matters:</strong> {rem.why_it_matters}</p>
                        <p className="text-slate-300"><strong>Affected Component:</strong> <code className="text-cyan-300">{rem.affected_component}</code></p>
                        <p className="text-slate-200"><strong>Recommended Fix:</strong> {rem.recommended_remediation}</p>
                        <p className="text-slate-300"><strong>Secure Implementation:</strong> {rem.secure_implementation_guidance}</p>
                        <p className="text-slate-300"><strong>Verification Guidance:</strong> {rem.verification_guidance}</p>
                      </div>
                    ) : f.remediation ? (
                      <div className="p-3 rounded bg-cyan-950/20 border border-cyan-800/40">
                        <span className="font-semibold text-cyan-400 block mb-1">Remediation Guidance</span>
                        <p className="text-slate-300">{f.remediation}</p>
                      </div>
                    ) : null}

                    {/* Phase 5E: Validation Lifecycle & History */}
                    {intel && (
                      <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2.5">
                        <span className="font-semibold text-emerald-400 block">
                          Safe Validation Workflow & Audit History
                        </span>
                        <div className="flex flex-wrap items-center gap-2">
                          <input
                            type="text"
                            placeholder="Optional analyst review notes..."
                            value={transitionNotes}
                            onChange={(e) => setTransitionNotes(e.target.value)}
                            className="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 flex-1 min-w-[200px]"
                          />
                          {(["VALIDATED", "NEEDS_REVIEW", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"] as ValidationState[]).map((st) => (
                            <button
                              key={st}
                              disabled={updatingId === f.id || intel.validation_state === st}
                              onClick={() => handleValidationTransition(f.id, st)}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-[10px] font-mono text-slate-200 border border-slate-700"
                            >
                              Mark {st}
                            </button>
                          ))}
                        </div>
                        <div className="space-y-1 max-h-36 overflow-y-auto pt-1">
                          {intel.validation_history.map((h, idx) => (
                            <div key={idx} className="text-[11px] font-mono text-slate-400 border-l-2 border-slate-700 pl-2">
                              [{new Date(h.timestamp).toLocaleString()}]{" "}
                              <span className="text-slate-200">{h.from_state || "INIT"} → {h.to_state}</span>{" "}
                              by <span className="text-cyan-400">{h.actor}</span> ({h.validation_method})
                              {h.notes ? ` — ${h.notes}` : ""}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Cryptographic Evidence */}
                    {f.evidence && (
                      <div className="space-y-2">
                        <span className="font-semibold text-slate-400 block">Cryptographic Evidence (Redacted)</span>
                        {f.evidence.sha256_hash && (
                          <p className="text-[10px] font-mono text-slate-500 truncate">
                            SHA-256 Seal: {f.evidence.sha256_hash}
                          </p>
                        )}
                        {f.evidence.request && (
                          <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-cyan-300/90 max-h-32 overflow-y-auto whitespace-pre-wrap">
                            {f.evidence.request}
                          </pre>
                        )}
                        {f.evidence.response && (
                          <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap">
                            {f.evidence.response}
                          </pre>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {findings.length === 0 && (
            <div className="p-12 text-center text-slate-500 border border-slate-800 rounded-xl bg-slate-900/20">
              No findings matching the selected filters.
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-between items-center pt-2 text-xs text-slate-400">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700"
              >
                Previous
              </button>
              <span>Page {page} of {totalPages}</span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700"
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
