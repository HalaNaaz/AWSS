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
import {
  PanelHeader,
  SeverityBadge,
  StatusBadge,
  Button,
  MetricCell,
  EvidenceViewer,
} from "../../components/ui/swiss-components";
import { ShieldAlert, Filter, Search, CheckCircle2, AlertTriangle, Layers, ArrowRight } from "lucide-react";

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
    if (prio === "CRITICAL") return "bg-[#FEE2E2] dark:bg-[#2B0F10] text-[#C62828] dark:text-[#FF5252] border-[#F87171] dark:border-[#5C1D1E]";
    if (prio === "HIGH") return "bg-[#FFEBEE] dark:bg-[#2A1313] text-[#E53935] dark:text-[#FF6E6A] border-[#FCA5A5] dark:border-[#5A2020]";
    if (prio === "MEDIUM") return "bg-[#FEF3C7] dark:bg-[#291B07] text-[#D97706] dark:text-[#FBBF24] border-[#FCD34D] dark:border-[#52380E]";
    if (prio === "LOW") return "bg-[#EFF6FF] dark:bg-[#0C1A30] text-[#2563EB] dark:text-[#60A5FA] border-[#93C5FD] dark:border-[#1E3A8A]";
    return "bg-surface-subtle text-ink-secondary border-swiss-border";
  };

  const confidenceBadgeStyle = (lvl?: string) => {
    if (lvl === "HIGH") return "bg-[#ECFDF5] dark:bg-[#092015] text-[#15803D] dark:text-[#4ADE80] border-[#6EE7B7] dark:border-[#065F46]";
    if (lvl === "MEDIUM") return "bg-[#EFF6FF] dark:bg-[#0C1A30] text-[#2563EB] dark:text-[#60A5FA] border-[#93C5FD] dark:border-[#1E3A8A]";
    return "bg-[#FEE2E2] dark:bg-[#2B0F10] text-[#C62828] dark:text-[#FF5252] border-[#F87171] dark:border-[#5C1D1E]";
  };

  const findingTitleById = (id: string) => {
    const match = findings.find((item) => item.id === id);
    return match ? `${match.title} (${match.cwe_id})` : id;
  };

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <PanelHeader
        tag="PHASE 5 · AVIVE"
        title="Vulnerability Findings & Evidence"
        subtitle="Normalized correlation groups, explainable evidence confidence, controlled validation lifecycle, and contextual risk prioritization"
        actions={
          <div className="flex items-center gap-2 w-full sm:w-auto font-mono text-xs">
            <label htmlFor="scan-selector" className="text-ink-muted whitespace-nowrap text-[11px] uppercase">
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
              className="px-3 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary focus:outline-none focus:border-accent font-mono w-full sm:w-72 rounded-none"
            >
              <option value="">All Registered Scans</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_url} ({s.findings_count || 0} findings)
                </option>
              ))}
            </select>
          </div>
        }
      />

      {/* AVIVE Intelligence Summary Strip (Swiss Technical Grid) */}
      {intelSummary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 border border-swiss-border bg-surface divide-x divide-y sm:divide-y-0 divide-swiss-border font-mono">
          <MetricCell
            index="01"
            label="Total Normalized"
            value={<span className="text-ink-primary">{intelSummary.total_raw_findings}</span>}
            sublabel="Raw records processed"
          />
          <MetricCell
            index="02"
            label="Unique Primary"
            value={<span className="text-accent">{intelSummary.unique_primary_findings}</span>}
            sublabel="Deduplicated vectors"
          />
          <MetricCell
            index="03"
            label="Duplicates Linked"
            value={<span className="text-ink-secondary">{intelSummary.duplicate_findings_count}</span>}
            sublabel="Correlated instances"
          />
          <MetricCell
            index="04"
            label="Correlation Groups"
            value={<span className="text-[#2563EB] dark:text-[#60A5FA]">{intelSummary.correlation_groups_count}</span>}
            sublabel="Co-located clusters"
          />
          <MetricCell
            index="05"
            label="Manual Review Needed"
            value={<span className="text-[#D97706] dark:text-[#FBBF24]">{intelSummary.manual_review_required_count}</span>}
            sublabel="Requires analyst triage"
            indicatorColor="#D97706"
          />
        </div>
      )}

      {/* Action and Error Feedback */}
      {error && (
        <div className="p-3 border border-[#F87171] bg-[#FEE2E2] dark:bg-[#2B0F10] text-xs font-mono text-[#C62828] dark:text-[#FF5252] flex justify-between items-center">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-current hover:underline font-bold">✕</button>
        </div>
      )}
      {actionMessage && (
        <div className="p-3 border border-[#6EE7B7] bg-[#ECFDF5] dark:bg-[#092015] text-xs font-mono text-[#15803D] dark:text-[#4ADE80] flex justify-between items-center">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-current hover:underline font-bold">✕</button>
        </div>
      )}

      {/* Filter Matrix (Swiss Technical Grid) */}
      <div className="border border-swiss-border bg-surface p-4 space-y-3 font-mono text-xs">
        <div className="flex flex-wrap gap-2 items-center justify-between">
          <div className="flex flex-wrap gap-1">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((sev) => (
              <button
                key={sev}
                onClick={() => {
                  setSeverityFilter(sev);
                  setPage(1);
                }}
                className={`px-2.5 py-1 text-xs uppercase font-semibold border transition-colors ${
                  severityFilter === sev
                    ? "bg-accent text-white border-accent"
                    : "bg-surface-subtle text-ink-muted border-swiss-border hover:bg-surface hover:text-ink-primary"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="w-full sm:w-auto">
            <input
              type="text"
              placeholder="Search findings by title, CWE, or URL..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              className="px-3 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary placeholder-ink-muted focus:outline-none focus:border-accent w-full sm:w-80 rounded-none font-mono"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2 pt-2 border-t border-swiss-border-subtle">
          <select
            aria-label="Confidence Filter"
            value={confidenceFilter}
            onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary rounded-none font-mono"
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
            className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary rounded-none font-mono"
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
            className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary rounded-none font-mono"
          >
            <option value="ALL">Type: All Categories</option>
            <option value="SQL_INJECTION">SQL Injection</option>
            <option value="XSS">XSS</option>
            <option value="SSTI">SSTI</option>
            <option value="SSRF">SSRF</option>
            <option value="XXE">XXE</option>
            <option value="PATH_TRAVERSAL">Path Traversal</option>
            <option value="API_SECURITY">API Security</option>
            <option value="OPEN_REDIRECT">Open Redirect</option>
            <option value="SECURITY_HEADERS">Security Headers</option>
            <option value="COOKIE_SECURITY">Cookie Security</option>
            <option value="TOKEN_SECURITY">Token Security</option>
            <option value="CACHE_SECURITY">Cache Security</option>
            <option value="CLIENT_SIDE_SECURITY">Client-Side Security</option>
            <option value="CORS_MISCONFIGURATION">CORS Misconfiguration</option>
            <option value="INFORMATION_DISCLOSURE">Info Disclosure</option>
            <option value="TRANSPORT_SECURITY">Transport Security</option>
          </select>

          <select
            aria-label="Correlation Group Filter"
            value={correlationGroupFilter}
            onChange={(e) => { setCorrelationGroupFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary rounded-none font-mono"
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
            className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary rounded-none font-mono"
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
            className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary placeholder-ink-muted rounded-none font-mono"
          />
        </div>

        <div className="flex items-center justify-between pt-1 text-xs text-ink-muted border-t border-swiss-border-subtle">
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={hideDuplicates}
              onChange={(e) => { setHideDuplicates(e.target.checked); setPage(1); }}
              className="accent-accent"
            />
            <span>Hide Correlated Duplicates (Show Primary Queue Only)</span>
          </label>
          <span className="tabular-nums">Showing {findings.length} of {totalFindings} findings</span>
        </div>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="p-12 text-center text-ink-muted border border-swiss-border bg-surface text-xs font-mono">
          Loading normalized findings & AVIVE intelligence...
        </div>
      ) : (
        <div className="space-y-3 font-mono">
          {findings.map((f) => {
            const isExpanded = expandedId === f.id;
            const intel = f.intelligence;
            const conf = intel?.confidence_assessment;
            const risk = intel?.contextual_risk;
            const rem = intel?.remediation_intelligence;

            return (
              <div
                key={f.id}
                className={`border bg-surface p-4 space-y-3 transition-colors ${
                  intel?.is_duplicate
                    ? "border-swiss-border-subtle opacity-80"
                    : "border-swiss-border hover:border-swiss-border-strong"
                }`}
              >
                <div className="flex flex-col sm:flex-row justify-between items-start gap-3">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-1.5 text-xs">
                      <SeverityBadge severity={f.severity} />

                      {risk && (
                        <span className={`px-2 py-0.5 text-[10px] font-mono font-bold border rounded-none ${priorityBadgeStyle(risk.contextual_priority)}`}>
                          CONTEXT PRIO: {risk.contextual_priority} ({risk.contextual_score})
                        </span>
                      )}

                      {conf && (
                        <span className={`px-2 py-0.5 text-[10px] font-mono font-bold border rounded-none ${confidenceBadgeStyle(conf.level)}`}>
                          CONF ({conf.level} · {Math.round(conf.score * 100)}%)
                        </span>
                      )}

                      {intel && (
                        <span className="px-2 py-0.5 text-[10px] font-mono bg-surface-subtle text-ink-secondary border border-swiss-border">
                          {intel.validation_state}
                        </span>
                      )}

                      {intel?.is_duplicate ? (
                        <span className="px-2 py-0.5 text-[10px] font-mono bg-surface-subtle text-[#D97706] dark:text-[#FBBF24] border border-[#FCD34D] dark:border-[#52380E]">
                          DUPLICATE ({intel.correlation_group_id})
                        </span>
                      ) : intel?.correlation_group_id ? (
                        <span className="px-2 py-0.5 text-[10px] font-mono bg-accent-subtle text-accent border border-accent/20">
                          {intel.correlation_relationship}: {intel.correlation_group_id}
                        </span>
                      ) : null}

                      <span className="text-xs text-ink-muted">{f.cwe_id}</span>
                      <span className="text-xs text-ink-muted">CVSS {f.cvss_score}</span>
                    </div>

                    <h3 className="text-sm font-display font-bold text-ink-primary">{f.title}</h3>
                  </div>

                  <Button
                    onClick={() => setExpandedId(isExpanded ? null : f.id)}
                    variant="outline"
                    size="sm"
                    className="whitespace-nowrap"
                  >
                    {isExpanded ? "Collapse" : "View Details"}
                  </Button>
                </div>

                {f.endpoint && (
                  <p className="text-xs font-mono text-ink-secondary bg-surface-subtle px-2 py-1 border border-swiss-border break-all">
                    {f.endpoint.method} {f.endpoint.url}
                    {f.endpoint.parameter ? ` · param: ${f.endpoint.parameter}` : ""}
                  </p>
                )}

                {isExpanded && (
                  <div className="pt-3 border-t border-swiss-border space-y-4 text-xs font-mono">
                    {f.description && (
                      <div>
                        <span className="font-bold text-ink-muted uppercase block mb-1">Technical Description</span>
                        <p className="text-ink-secondary font-sans leading-relaxed">{f.description}</p>
                      </div>
                    )}

                    {/* Phase 5D: Confidence & Evidence Quality */}
                    {conf && (
                      <div className="p-3.5 border border-swiss-border bg-surface-subtle space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="font-bold text-accent uppercase">
                            Explainable Confidence Assessment ({conf.level} · {Math.round(conf.score * 100)}%)
                          </span>
                          {conf.needs_manual_review && (
                            <span className="px-1.5 py-0.5 border border-[#FCD34D] dark:border-[#52380E] bg-[#FEF3C7] dark:bg-[#291B07] text-[#D97706] dark:text-[#FBBF24] text-[10px] font-mono font-bold">
                              MANUAL REVIEW REQUIRED
                            </span>
                          )}
                        </div>
                        <p className="text-ink-secondary font-sans leading-relaxed">{conf.explanation}</p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-[11px]">
                          <div>
                            <span className="font-bold text-[#15803D] dark:text-[#4ADE80] uppercase block mb-1">
                              Contributing Evidence
                            </span>
                            <ul className="list-disc list-inside text-ink-muted space-y-0.5">
                              {conf.contributing_evidence.map((c, i) => <li key={i}>{c}</li>)}
                              {conf.contributing_evidence.length === 0 && <li>None recorded</li>}
                            </ul>
                          </div>
                          <div>
                            <span className="font-bold text-[#D97706] dark:text-[#FBBF24] uppercase block mb-1">
                              Missing / Contradictory Signals
                            </span>
                            <ul className="list-disc list-inside text-ink-muted space-y-0.5">
                              {conf.missing_evidence.map((m, i) => <li key={`m-${i}`}>{m}</li>)}
                              {conf.contradictory_signals.map((cs, i) => <li key={`c-${i}`} className="text-[#C62828] dark:text-[#FF5252]">{cs}</li>)}
                              {conf.missing_evidence.length === 0 && conf.contradictory_signals.length === 0 && (
                                <li className="text-[#15803D] dark:text-[#4ADE80]">No missing or contradictory evidence</li>
                              )}
                            </ul>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Phase 5F: Contextual Risk Assessment & Relationships */}
                    {risk && intel && (
                      <div className="p-3.5 border border-swiss-border bg-surface-subtle space-y-2">
                        <span className="font-bold text-[#2563EB] dark:text-[#60A5FA] uppercase block">
                          Contextual Risk Rationale & Attack Surface Relationships
                        </span>
                        <p className="text-ink-secondary font-sans leading-relaxed">{risk.priority_rationale}</p>
                        <div className="flex flex-wrap gap-2 text-[11px] text-ink-muted pt-1">
                          <span>Assets: <strong className="text-ink-primary">{intel.asset_relationships.join(", ") || "N/A"}</strong></span>
                          <span>· Technologies: <strong className="text-ink-primary">{intel.technology_relationships.join(", ") || "None observed"}</strong></span>
                          <span>· Fingerprint: <code className="text-accent">{intel.fingerprint}</code></span>
                        </div>
                        {risk.data_limitations.length > 0 && (
                          <p className="text-[11px] text-[#D97706] dark:text-[#FBBF24]">
                            Data Limitations: {risk.data_limitations.join(" | ")}
                          </p>
                        )}
                        {intel.related_finding_ids.length > 0 && (
                          <div className="pt-1">
                            <span className="text-[11px] font-bold text-ink-muted uppercase block mb-1">
                              Correlated / Related Findings ({intel.related_finding_ids.length}):
                            </span>
                            <div className="flex flex-wrap gap-1">
                              {intel.related_finding_ids.slice(0, 6).map((rid) => (
                                <span key={rid} className="px-2 py-0.5 bg-surface border border-swiss-border text-[10px] text-ink-secondary">
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
                      <div className="p-3.5 border border-swiss-border bg-surface-subtle space-y-2">
                        <div className="flex flex-wrap justify-between items-center gap-2">
                          <span className="font-bold text-accent uppercase">
                            Remediation Intelligence ({rem.remediation_priority} · Status: {rem.remediation_status})
                          </span>
                          <div className="flex items-center gap-1">
                            {(["OPEN", "IN_PROGRESS", "FIXED", "VERIFIED_FIXED"] as RemediationStatus[]).map((st) => (
                              <button
                                key={st}
                                disabled={updatingId === f.id}
                                onClick={() => handleRemediationUpdate(f.id, st)}
                                className={`px-2 py-0.5 text-[10px] font-mono border uppercase tracking-wider transition-colors ${
                                  rem.remediation_status === st
                                    ? "bg-accent text-white border-accent font-bold"
                                    : "bg-surface text-ink-secondary border-swiss-border hover:text-ink-primary"
                                }`}
                              >
                                {st}
                              </button>
                            ))}
                          </div>
                        </div>
                        <p className="text-ink-secondary font-sans leading-relaxed"><strong>Root Cause:</strong> {rem.root_cause}</p>
                        <p className="text-ink-secondary font-sans leading-relaxed"><strong>Why It Matters:</strong> {rem.why_it_matters}</p>
                        <p className="text-ink-secondary font-sans leading-relaxed"><strong>Affected Component:</strong> <code className="text-accent">{rem.affected_component}</code></p>
                        <p className="text-ink-primary font-sans leading-relaxed font-semibold"><strong>Recommended Fix:</strong> {rem.recommended_remediation}</p>
                        <p className="text-ink-secondary font-sans leading-relaxed"><strong>Secure Implementation:</strong> {rem.secure_implementation_guidance}</p>
                        <p className="text-ink-secondary font-sans leading-relaxed"><strong>Verification Guidance:</strong> {rem.verification_guidance}</p>
                      </div>
                    ) : f.remediation ? (
                      <div className="p-3 bg-surface-subtle border border-swiss-border">
                        <span className="font-bold text-accent uppercase block mb-1">Remediation Guidance</span>
                        <p className="text-ink-secondary font-sans leading-relaxed">{f.remediation}</p>
                      </div>
                    ) : null}

                    {/* Phase 5E: Validation Lifecycle & History */}
                    {intel && (
                      <div className="p-3.5 border border-swiss-border bg-surface-subtle space-y-2.5">
                        <span className="font-bold text-[#15803D] dark:text-[#4ADE80] uppercase block">
                          Safe Validation Workflow & Audit History
                        </span>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <input
                            type="text"
                            placeholder="Optional analyst review notes..."
                            value={transitionNotes}
                            onChange={(e) => setTransitionNotes(e.target.value)}
                            className="px-2.5 py-1 bg-surface border border-swiss-border text-xs text-ink-primary flex-1 min-w-[200px] rounded-none font-mono"
                          />
                          {(["VALIDATED", "NEEDS_REVIEW", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"] as ValidationState[]).map((st) => (
                            <button
                              key={st}
                              disabled={updatingId === f.id || intel.validation_state === st}
                              onClick={() => handleValidationTransition(f.id, st)}
                              className="px-2 py-1 bg-surface hover:bg-surface-subtle disabled:opacity-40 text-[10px] font-mono text-ink-primary border border-swiss-border uppercase tracking-wider"
                            >
                              Mark {st}
                            </button>
                          ))}
                        </div>
                        <div className="space-y-1 max-h-36 overflow-y-auto pt-1">
                          {intel.validation_history.map((h, idx) => (
                            <div key={idx} className="text-[11px] font-mono text-ink-muted border-l-2 border-accent pl-2">
                              [{new Date(h.timestamp).toLocaleString()}]{" "}
                              <span className="text-ink-primary font-semibold">{h.from_state || "INIT"} → {h.to_state}</span>{" "}
                              by <span className="text-accent">{h.actor}</span> ({h.validation_method})
                              {h.notes ? ` — ${h.notes}` : ""}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Cryptographic Evidence */}
                    {f.evidence && (
                      <div className="space-y-2">
                        <span className="font-bold text-ink-muted uppercase block">Cryptographic Evidence (Redacted)</span>
                        {f.evidence.sha256_hash && (
                          <p className="text-[10px] font-mono text-ink-muted truncate">
                            SHA-256 Seal: {f.evidence.sha256_hash}
                          </p>
                        )}
                        {f.evidence.request && (
                          <pre className="p-2.5 bg-surface border border-swiss-border text-[10px] font-mono text-accent max-h-32 overflow-y-auto whitespace-pre-wrap">
                            {f.evidence.request}
                          </pre>
                        )}
                        {f.evidence.response && (
                          <pre className="p-2.5 bg-surface border border-swiss-border text-[10px] font-mono text-ink-primary max-h-48 overflow-y-auto whitespace-pre-wrap">
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
            <div className="p-12 text-center text-ink-muted border border-swiss-border bg-surface text-xs font-mono">
              No findings matching the selected filters.
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-between items-center pt-2 text-xs font-mono text-ink-muted">
              <Button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                variant="outline"
                size="sm"
              >
                Previous
              </Button>
              <span className="tabular-nums">Page {page} of {totalPages}</span>
              <Button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                variant="outline"
                size="sm"
              >
                Next
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
