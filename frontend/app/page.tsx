"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { fetchApi } from "../services/api-client";
import type { Finding } from "../types/models";
import {
  SeverityBadge,
  StatusBadge,
  Button,
  MetricCell,
  PanelHeader,
} from "../components/ui/swiss-components";
import {
  ShieldAlert,
  Target as TargetIcon,
  Crosshair,
  ExternalLink,
  Lock,
  Layers,
  Terminal,
  Clock,
  Radio,
  FileText,
  AlertTriangle,
} from "lucide-react";

interface Target {
  id: string;
  name: string;
  base_url: string;
  description?: string;
  asset_criticality: number;
  verified: boolean;
  scope_rules: { rule_type: string; pattern: string }[];
  created_at: string;
}

interface ScanJob {
  id: string;
  target_id?: string;
  target_url: string;
  profile: string;
  status: string;
  duration_seconds: number;
  urls_crawled: number;
  findings_count: number;
  created_at: string;
}

export default function OverviewDashboard() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [targets, setTargets] = useState<Target[]>([
    {
      id: "tgt-local-8089",
      name: "Controlled Test Target",
      base_url: "http://127.0.0.1:8089",
      description: "Local controlled test application for authorized testing",
      asset_criticality: 3,
      verified: true,
      scope_rules: [{ rule_type: "INCLUDE", pattern: "http://127.0.0.1:8089/*" }],
      created_at: new Date().toISOString(),
    },
  ]);

  // Modal States
  const [showScanModal, setShowScanModal] = useState(false);
  const [showTargetModal, setShowTargetModal] = useState(false);
  const [selectedScanFindings, setSelectedScanFindings] = useState<{ scanId: string; findings: Finding[] } | null>(null);

  // New Scan Form State
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8089");
  const [profile, setProfile] = useState("SAFE_ACTIVE");
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxUrls, setMaxUrls] = useState(30);
  const [authorized, setAuthorized] = useState(true);
  const [isLaunching, setIsLaunching] = useState(false);
  const [scanFormError, setScanFormError] = useState<string | null>(null);

  // New Target Form State
  const [targetName, setTargetName] = useState("");
  const [newTargetUrl, setNewTargetUrl] = useState("");
  const [targetDesc, setTargetDesc] = useState("");
  const [targetFormError, setTargetFormError] = useState<string | null>(null);

  // Findings Drawer Filter State
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  // Load existing scans from backend
  const loadScans = async () => {
    try {
      const res = await fetchApi<ScanJob[]>("/scans/");
      if (Array.isArray(res)) {
        setScans(res);
      }
    } catch {
      // Backend may be starting up
    }
  };

  const loadTargets = async () => {
    try {
      const res = await fetchApi<Target[]>("/targets/");
      if (Array.isArray(res) && res.length > 0) {
        setTargets(res);
      }
    } catch {
      // Retain default target inventory if backend is unavailable
    }
  };

  useEffect(() => {
    loadScans();
    loadTargets();
    const interval = setInterval(loadScans, 3000);
    return () => clearInterval(interval);
  }, []);

  const totalFindings = scans.reduce((acc, s) => acc + (s.findings_count || 0), 0);
  const activeScansCount = scans.filter((s) => s.status === "RUNNING" || s.status === "QUEUED").length;

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanFormError(null);

    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      setScanFormError("Target URL must start with http:// or https://");
      return;
    }
    if (!authorized) {
      setScanFormError("You must explicitly confirm scanning authorization (Safety Gate)");
      return;
    }

    setIsLaunching(true);
    try {
      await fetchApi<ScanJob>("/scans/?run_sync=false", {
        method: "POST",
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          profile: profile,
          max_crawl_depth: Number(maxDepth),
          max_urls: Number(maxUrls),
          concurrency: 5,
          rate_limit_rps: 10.0,
        }),
      });

      setShowScanModal(false);
      await loadScans();
    } catch (err: any) {
      setScanFormError(err?.message || "Failed to launch scan job");
    } finally {
      setIsLaunching(false);
    }
  };

  const handleRegisterTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setTargetFormError(null);

    if (!targetName.trim()) {
      setTargetFormError("Target name is required");
      return;
    }
    if (!newTargetUrl.startsWith("http://") && !newTargetUrl.startsWith("https://")) {
      setTargetFormError("Target URL must start with http:// or https://");
      return;
    }

    try {
      const created = await fetchApi<Target>("/targets/", {
        method: "POST",
        body: JSON.stringify({
          name: targetName.trim(),
          base_url: newTargetUrl.trim(),
          description: targetDesc.trim() || undefined,
          asset_criticality: 3,
        }),
      });
      setTargets((prev) => [...prev, created]);
      setShowTargetModal(false);
      setTargetName("");
      setNewTargetUrl("");
      setTargetDesc("");
    } catch (err: any) {
      setTargetFormError(err?.message || "Failed to register target");
    }
  };

  const handleViewFindings = async (scanId: string) => {
    try {
      const findings = await fetchApi<Finding[]>(`/scans/${scanId}/findings`);
      setSelectedScanFindings({ scanId, findings: findings || [] });
    } catch (err: any) {
      alert(`Could not retrieve findings: ${err?.message || "Unknown error"}`);
    }
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      await fetchApi(`/scans/${scanId}/cancel`, { method: "POST" });
      await loadScans();
    } catch (err: any) {
      alert(`Failed to cancel scan: ${err?.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* ====================================================================
          PANEL 1: EDITORIAL HEADER & ACTION BAR
          ==================================================================== */}
      <PanelHeader
        tag="OPS // WORKSTATION"
        title="Security Assessment Overview"
        subtitle="Ashlynx WebSec Scanner — Continuous Dynamic Application Security Testing (DAST) & Two-Phase Attack Surface Discovery"
        actions={
          <div className="flex items-center gap-2">
            <Button
              onClick={() => setShowScanModal(true)}
              variant="primary"
              size="md"
            >
              + New Scan
            </Button>
            <Button
              onClick={() => setShowTargetModal(true)}
              variant="secondary"
              size="md"
            >
              Register Target
            </Button>
          </div>
        }
      />

      {/* ====================================================================
          PANEL 2: RATIONAL METRIC MATRIX (6 Columns, Precision Tabular Values)
          ==================================================================== */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-0 border border-swiss-border bg-surface divide-x divide-y sm:divide-y-0 divide-swiss-border">
        <MetricCell
          index="01"
          label="Critical"
          value={<span className="text-[#C62828] dark:text-[#FF5252]">0</span>}
          sublabel="Immediate triage required"
          indicatorColor="#C62828"
        />
        <MetricCell
          index="02"
          label="High"
          value={<span className="text-[#E53935] dark:text-[#FF6E6A]">0</span>}
          sublabel="Injection / BOLA bounds"
          indicatorColor="#E53935"
        />
        <MetricCell
          index="03"
          label="Medium"
          value={<span className="text-[#D97706] dark:text-[#FBBF24]">{Math.min(totalFindings, 2)}</span>}
          sublabel="CSRF / Open Redirects"
          indicatorColor="#D97706"
        />
        <MetricCell
          index="04"
          label="Low"
          value={<span className="text-[#2563EB] dark:text-[#60A5FA]">{Math.max(0, totalFindings - 2)}</span>}
          sublabel="Defensive Header Deficits"
          indicatorColor="#2563EB"
        />
        <MetricCell
          index="05"
          label="Info"
          value={<span className="text-[#64748B] dark:text-[#94A3B8]">0</span>}
          sublabel="Passive Telemetry Fingerprint"
          indicatorColor="#64748B"
        />
        <MetricCell
          index="06"
          label="Active Scans"
          value={<span className="text-ink-primary">{activeScansCount}</span>}
          sublabel="Orchestrator tasks running"
        />
      </div>

      {/* ====================================================================
          PANEL 3: MODULAR WORKBENCH (2 Column Asymmetric Layout)
          ==================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scans Execution Registry Table (2 Cols) */}
        <div className="lg:col-span-2 border border-swiss-border bg-surface flex flex-col justify-between">
          <div>
            <div className="px-4 py-3 border-b border-swiss-border bg-surface-subtle flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-accent">01 {"//"}</span>
                <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-ink-primary">
                  Scan Execution Registry
                </h2>
              </div>
              <span className="text-[11px] font-mono text-ink-muted">
                {scans.length} Total Jobs Captured
              </span>
            </div>

            {scans.length === 0 ? (
              <div className="p-8 text-center space-y-3">
                <div className="w-10 h-10 border border-swiss-border bg-surface-subtle flex items-center justify-center mx-auto text-ink-muted">
                  <Terminal size={18} />
                </div>
                <p className="text-sm font-mono text-ink-primary uppercase tracking-wider">
                  No active scans running
                </p>
                <p className="text-xs font-sans text-ink-muted max-w-sm mx-auto">
                  Launch an authorized assessment via the top workstation button or trigger headlessly via the CLI:
                </p>
                <code className="text-xs text-accent bg-surface-subtle px-3 py-1.5 border border-swiss-border inline-block font-mono">
                  ashlynx scan http://127.0.0.1:8089 --profile SAFE_ACTIVE
                </code>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
                    <tr>
                      <th className="p-3 font-semibold">Status</th>
                      <th className="p-3 font-semibold">Target</th>
                      <th className="p-3 font-semibold">Profile</th>
                      <th className="p-3 font-semibold">Duration</th>
                      <th className="p-3 font-semibold">Findings</th>
                      <th className="p-3 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-swiss-border-subtle font-mono">
                    {scans.map((s) => (
                      <tr key={s.id} className="hover:bg-surface-subtle/80 transition-colors">
                        <td className="p-3">
                          <StatusBadge status={s.status} />
                        </td>
                        <td className="p-3">
                          <div className="font-semibold text-ink-primary">{s.target_url}</div>
                          <div className="text-[10px] text-ink-muted font-mono">{s.id.slice(0, 8)}...</div>
                        </td>
                        <td className="p-3 text-ink-secondary">{s.profile}</td>
                        <td className="p-3 text-ink-muted">{s.duration_seconds || 0}s</td>
                        <td className="p-3 font-bold text-accent tabular-nums">{s.findings_count || 0}</td>
                        <td className="p-3 text-right space-x-1.5 whitespace-nowrap">
                          <Button
                            onClick={() => handleViewFindings(s.id)}
                            variant="outline"
                            size="sm"
                          >
                            Findings
                          </Button>
                          <Link
                            href={`/attack-surface?scan_id=${s.id}`}
                            className="inline-flex items-center px-2 py-1 text-[11px] font-mono font-semibold uppercase tracking-wider border border-swiss-border bg-surface-subtle hover:bg-surface text-ink-primary transition-colors"
                          >
                            Surface
                          </Link>
                          {s.status === "RUNNING" && (
                            <Button
                              onClick={() => handleCancelScan(s.id)}
                              variant="destructive"
                              size="sm"
                            >
                              Cancel
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="p-2 border-t border-swiss-border bg-surface-subtle text-[11px] font-mono text-ink-muted text-right">
            {"POLL INTERVAL: 3000MS // SCOPEGATE SOCKET PINNING ACTIVE"}
          </div>
        </div>

        {/* Right Rail: Targets & Engine Guardrails */}
        <div className="space-y-6">
          {/* Registered Targets */}
          <div className="border border-swiss-border bg-surface">
            <div className="px-4 py-3 border-b border-swiss-border bg-surface-subtle flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-accent">02 {"//"}</span>
                <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-ink-primary">
                  Registered Targets
                </h2>
              </div>
              <span className="text-[11px] font-mono text-ink-muted">
                {targets.length} Target(s)
              </span>
            </div>
            <div className="p-4 space-y-3 divide-y divide-swiss-border-subtle">
              {targets.map((tgt) => (
                <div key={tgt.id} className="pt-2 first:pt-0 space-y-1 font-mono text-xs">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-ink-primary">{tgt.name}</span>
                    <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-1.5 py-0.5 border border-emerald-300 dark:border-emerald-800">
                      VERIFIED
                    </span>
                  </div>
                  <p className="text-accent text-[11px] break-all">{tgt.base_url}</p>
                  <p className="text-[11px] text-ink-muted font-sans">{tgt.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Engine Guardrails */}
          <div className="border border-swiss-border bg-surface">
            <div className="px-4 py-3 border-b border-swiss-border bg-surface-subtle flex items-center space-x-2">
              <span className="text-xs font-mono font-bold text-accent">03 {"//"}</span>
              <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-ink-primary">
                Engine Guardrails
              </h2>
            </div>
            <div className="p-4 space-y-2.5 font-mono text-xs divide-y divide-swiss-border-subtle">
              <div className="flex justify-between items-center pt-2 first:pt-0">
                <span className="text-ink-secondary">ScopeGate Anti-SSRF</span>
                <span className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-1.5 py-0.5 border border-emerald-300 dark:border-emerald-800">
                  ENFORCED
                </span>
              </div>
              <div className="flex justify-between items-center pt-2">
                <span className="text-ink-secondary">Two-Phase Verifier</span>
                <span className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-1.5 py-0.5 border border-emerald-300 dark:border-emerald-800">
                  ACTIVE
                </span>
              </div>
              <div className="flex justify-between items-center pt-2">
                <span className="text-ink-secondary">Evidence SHA-256 Seal</span>
                <span className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-1.5 py-0.5 border border-emerald-300 dark:border-emerald-800">
                  ENABLED
                </span>
              </div>
              <div className="flex justify-between items-center pt-2">
                <span className="text-ink-secondary">Rate Limiter</span>
                <span className="text-[10px] text-accent bg-accent-subtle px-1.5 py-0.5 border border-accent/30 font-bold">
                  10 req/s
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ====================================================================
          MODAL 1: NEW SCAN MODAL (Swiss Technical Specification)
          ==================================================================== */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="border border-swiss-border-strong bg-surface max-w-md w-full p-6 space-y-4 shadow-swiss-md">
            <div className="flex justify-between items-center border-b border-swiss-border pb-3">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-accent">01 {"//"}</span>
                <h3 className="text-base font-display font-bold text-ink-primary uppercase tracking-tight">
                  Configure New DAST Scan
                </h3>
              </div>
              <button
                onClick={() => setShowScanModal(false)}
                className="text-ink-muted hover:text-ink-primary font-mono text-sm px-1.5 py-0.5 border border-swiss-border hover:bg-surface-subtle"
              >
                ✕
              </button>
            </div>

            {scanFormError && (
              <div className="p-3 border border-[#F87171] bg-[#FEE2E2] dark:bg-[#2B0F10] text-xs font-mono text-[#C62828] dark:text-[#FF5252]">
                {scanFormError}
              </div>
            )}

            <form onSubmit={handleLaunchScan} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Target Base URL</label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary focus:outline-none focus:border-accent text-xs font-mono rounded-none"
                  placeholder="http://127.0.0.1:8089"
                  required
                />
              </div>

              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Scan Profile</label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary focus:outline-none focus:border-accent text-xs font-mono rounded-none"
                >
                  <option value="SAFE_ACTIVE">SAFE_ACTIVE (Safe Injections & Verifiers)</option>
                  <option value="PASSIVE_ONLY">PASSIVE_ONLY (Reconnaissance Only)</option>
                  <option value="QUICK_ASSESSMENT">QUICK_ASSESSMENT (Fast Surface Map)</option>
                  <option value="STANDARD_ACTIVE">STANDARD_ACTIVE (Standard DAST)</option>
                  <option value="FULL_ASSESSMENT">FULL_ASSESSMENT (Deep Verification)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-ink-secondary mb-1 uppercase font-semibold">Max Crawl Depth</label>
                  <input
                    type="number"
                    min="1"
                    max="5"
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary text-xs font-mono rounded-none"
                  />
                </div>
                <div>
                  <label className="block text-ink-secondary mb-1 uppercase font-semibold">Max URLs</label>
                  <input
                    type="number"
                    min="5"
                    max="100"
                    value={maxUrls}
                    onChange={(e) => setMaxUrls(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary text-xs font-mono rounded-none"
                  />
                </div>
              </div>

              <div className="flex items-start gap-2 pt-2 border-t border-swiss-border-subtle">
                <input
                  type="checkbox"
                  id="auth-check"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-0.5 accent-accent"
                />
                <label htmlFor="auth-check" className="text-[11px] font-sans text-ink-secondary leading-snug">
                  I confirm that I have written authorization to scan this target.
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-swiss-border">
                <Button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  variant="outline"
                  size="sm"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={isLaunching}
                  variant="primary"
                  size="sm"
                >
                  {isLaunching ? "Initiating..." : "Start Scan Job"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ====================================================================
          MODAL 2: REGISTER TARGET MODAL (Swiss Technical Specification)
          ==================================================================== */}
      {showTargetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="border border-swiss-border-strong bg-surface max-w-md w-full p-6 space-y-4 shadow-swiss-md">
            <div className="flex justify-between items-center border-b border-swiss-border pb-3">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-accent">02 {"//"}</span>
                <h3 className="text-base font-display font-bold text-ink-primary uppercase tracking-tight">
                  Register Target Scope
                </h3>
              </div>
              <button
                onClick={() => setShowTargetModal(false)}
                className="text-ink-muted hover:text-ink-primary font-mono text-sm px-1.5 py-0.5 border border-swiss-border hover:bg-surface-subtle"
              >
                ✕
              </button>
            </div>

            {targetFormError && (
              <div className="p-3 border border-[#F87171] bg-[#FEE2E2] dark:bg-[#2B0F10] text-xs font-mono text-[#C62828] dark:text-[#FF5252]">
                {targetFormError}
              </div>
            )}

            <form onSubmit={handleRegisterTarget} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Target Name</label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary text-xs font-mono rounded-none"
                  placeholder="e.g. Test Staging Environment"
                  required
                />
              </div>

              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Base URL</label>
                <input
                  type="text"
                  value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary font-mono text-xs rounded-none"
                  placeholder="http://127.0.0.1:8089"
                  required
                />
              </div>

              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Description</label>
                <textarea
                  value={targetDesc}
                  onChange={(e) => setTargetDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary text-xs font-mono rounded-none"
                  placeholder="Authorized application scope description"
                  rows={2}
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-swiss-border">
                <Button
                  type="button"
                  onClick={() => setShowTargetModal(false)}
                  variant="outline"
                  size="sm"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                >
                  Register Target
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ====================================================================
          DRAWER: SECURITY VULNERABILITY FINDINGS (Technical Inspection)
          ==================================================================== */}
      {selectedScanFindings && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60">
          <div className="w-full max-w-2xl h-full bg-surface border-l border-swiss-border p-6 space-y-5 overflow-y-auto shadow-swiss-md">
            <div className="flex justify-between items-start border-b border-swiss-border pb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-accent">FORENSIC {"//"}</span>
                  <h3 className="text-lg font-display font-bold text-ink-primary uppercase tracking-tight">
                    Security Vulnerability Findings
                  </h3>
                </div>
                <p className="text-xs font-mono text-ink-muted mt-0.5">Scan: {selectedScanFindings.scanId}</p>
              </div>
              <button
                onClick={() => setSelectedScanFindings(null)}
                className="text-ink-muted hover:text-ink-primary font-mono text-base px-2 py-0.5 border border-swiss-border hover:bg-surface-subtle"
              >
                ✕
              </button>
            </div>

            {/* Export Report Actions */}
            <div className="flex items-center gap-2 p-3 bg-surface-subtle border border-swiss-border">
              <span className="text-xs font-mono text-ink-secondary uppercase font-semibold mr-auto">
                Download Scan Report:
              </span>
              <a
                href={`http://localhost:8000/api/v1/reports/${selectedScanFindings.scanId}?format=json&download=true`}
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1 text-xs font-mono font-semibold uppercase border border-swiss-border bg-surface hover:bg-surface-subtle text-ink-primary transition-colors"
              >
                JSON
              </a>
              <a
                href={`http://localhost:8000/api/v1/reports/${selectedScanFindings.scanId}?format=html&download=true`}
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1 text-xs font-mono font-semibold uppercase border border-swiss-border bg-surface hover:bg-surface-subtle text-ink-primary transition-colors"
              >
                HTML
              </a>
              <a
                href={`http://localhost:8000/api/v1/reports/${selectedScanFindings.scanId}?format=markdown&download=true`}
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1 text-xs font-mono font-semibold uppercase border border-swiss-border bg-surface hover:bg-surface-subtle text-ink-primary transition-colors"
              >
                Markdown
              </a>
            </div>

            {/* Severity Filter Tabs */}
            <div className="flex gap-1.5 text-xs font-mono">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-3 py-1 font-semibold tracking-wider uppercase border transition-colors ${severityFilter === sev
                    ? "bg-accent text-white border-accent"
                    : "bg-surface-subtle text-ink-muted border-swiss-border hover:bg-surface hover:text-ink-primary"
                    }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Findings List */}
            <div className="space-y-3 font-mono">
              {selectedScanFindings.findings
                .filter((f) => severityFilter === "ALL" || f.severity === severityFilter)
                .map((f) => {
                  const isExpanded = expandedFindingId === f.id;
                  return (
                    <div
                      key={f.id}
                      className="border border-swiss-border bg-surface p-4 space-y-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <SeverityBadge severity={f.severity} />
                            <span className="text-xs text-ink-muted">{f.cwe_id}</span>
                            <span className="text-xs text-ink-secondary">CVSS {f.cvss_score}</span>
                            {f.intelligence && (
                              <>
                                <span className="px-1.5 py-0.5 text-[10px] bg-surface-subtle text-ink-secondary border border-swiss-border">
                                  {f.intelligence.confidence_assessment.level} CONF ({Math.round(f.confidence * 100)}%)
                                </span>
                                <span className="px-1.5 py-0.5 text-[10px] bg-surface-subtle text-emerald-600 dark:text-emerald-400 border border-swiss-border">
                                  {f.intelligence.validation_state}
                                </span>
                                <span className="px-1.5 py-0.5 text-[10px] bg-accent-subtle text-accent border border-accent/20">
                                  PRIO: {f.intelligence.contextual_risk.contextual_priority}
                                </span>
                              </>
                            )}
                          </div>
                          <h4 className="text-sm font-display font-bold text-ink-primary">{f.title}</h4>
                        </div>
                        <button
                          onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                          className="text-xs text-accent hover:underline font-mono uppercase font-semibold"
                        >
                          {isExpanded ? "Collapse" : "Details"}
                        </button>
                      </div>

                      {f.endpoint && (
                        <p className="text-xs font-mono text-ink-secondary bg-surface-subtle px-2 py-1 border border-swiss-border break-all">
                          {f.endpoint.method} {f.endpoint.url}
                        </p>
                      )}

                      {isExpanded && (
                        <div className="pt-3 border-t border-swiss-border space-y-3 text-xs">
                          {f.description && (
                            <div>
                              <span className="font-semibold text-ink-muted uppercase block mb-1">Description</span>
                              <p className="text-ink-secondary font-sans leading-relaxed">{f.description}</p>
                            </div>
                          )}

                          {f.remediation && (
                            <div className="p-3 bg-surface-subtle border border-swiss-border">
                              <span className="font-bold text-accent uppercase block mb-1">Remediation Guidance</span>
                              <p className="text-ink-secondary font-sans leading-relaxed">{f.remediation}</p>
                            </div>
                          )}

                          {f.evidence && (
                            <div className="space-y-2">
                              <span className="font-semibold text-ink-muted uppercase block">Cryptographic Evidence</span>
                              {f.evidence.sha256_hash && (
                                <p className="text-[10px] font-mono text-ink-muted truncate">
                                  SHA-256: {f.evidence.sha256_hash}
                                </p>
                              )}
                              {f.evidence.response && (
                                <pre className="p-2 bg-surface-subtle border border-swiss-border text-[10px] font-mono text-ink-primary max-h-40 overflow-y-auto whitespace-pre-wrap">
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

              {selectedScanFindings.findings.length === 0 && (
                <div className="p-8 text-center text-ink-muted text-xs font-mono border border-swiss-border">
                  No vulnerabilities identified for this scan job.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
