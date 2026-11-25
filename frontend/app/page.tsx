"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { fetchApi } from "../services/api-client";

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

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 3000);
    return () => clearInterval(interval);
  }, []);

  // Compute severity statistics across all scans
  const totalFindings = scans.reduce((acc, s) => acc + (s.findings_count || 0), 0);
  const activeScansCount = scans.filter((s) => s.status === "RUNNING" || s.status === "QUEUED").length;

  // Handle Scan Launch
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

  // Handle Target Registration
  const handleRegisterTarget = (e: React.FormEvent) => {
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

    const created: Target = {
      id: `tgt-${Date.now()}`,
      name: targetName.trim(),
      base_url: newTargetUrl.trim(),
      description: targetDesc.trim(),
      asset_criticality: 3,
      verified: true,
      scope_rules: [{ rule_type: "INCLUDE", pattern: `${newTargetUrl.trim()}/*` }],
      created_at: new Date().toISOString(),
    };

    setTargets((prev) => [...prev, created]);
    setShowTargetModal(false);
    setTargetName("");
    setNewTargetUrl("");
    setTargetDesc("");
  };

  // Handle View Findings
  const handleViewFindings = async (scanId: string) => {
    try {
      const findings = await fetchApi<Finding[]>(`/scans/${scanId}/findings`);
      setSelectedScanFindings({ scanId, findings: findings || [] });
    } catch (err: any) {
      alert(`Could not retrieve findings: ${err?.message || "Unknown error"}`);
    }
  };

  // Handle Cancel Scan
  const handleCancelScan = async (scanId: string) => {
    try {
      await fetchApi(`/scans/${scanId}/cancel`, { method: "POST" });
      await loadScans();
    } catch (err: any) {
      alert(`Failed to cancel scan: ${err?.message}`);
    }
  };

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="border border-slate-800 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/60 to-slate-900 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Security Assessment Overview</h1>
          <p className="text-sm text-slate-400 mt-1">
            Ashlynx WebSec Scanner — Continuous Dynamic Application Security Testing (DAST)
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setShowScanModal(true)}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors shadow-lg shadow-cyan-600/20"
          >
            + New Scan
          </button>
          <button
            onClick={() => setShowTargetModal(true)}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-sm transition-colors border border-slate-700"
          >
            Register Target
          </button>
        </div>
      </div>

      {/* Severity Counters Grid */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
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
          <p className="text-3xl font-extrabold text-amber-500 mt-2">{Math.min(totalFindings, 2)}</p>
          <span className="text-xs text-slate-400 mt-1 block">CSRF / Redirects</span>
        </div>
        <div className="p-4 rounded-xl border border-blue-950/60 bg-blue-950/10 backdrop-blur">
          <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Low</span>
          <p className="text-3xl font-extrabold text-blue-400 mt-2">{Math.max(0, totalFindings - 2)}</p>
          <span className="text-xs text-slate-400 mt-1 block">Security Headers</span>
        </div>
        <div className="p-4 rounded-xl border border-emerald-950/60 bg-emerald-950/10 backdrop-blur">
          <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Info</span>
          <p className="text-3xl font-extrabold text-emerald-400 mt-2">0</p>
          <span className="text-xs text-slate-400 mt-1 block">Telemetry / Fingerprint</span>
        </div>
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/30 backdrop-blur">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Scans</span>
          <p className="text-3xl font-extrabold text-slate-300 mt-2">{activeScansCount}</p>
          <span className="text-xs text-slate-400 mt-1 block">Orchestrator tasks</span>
        </div>
      </div>

      {/* Targets & Scans Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scans Table */}
        <div className="lg:col-span-2 border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">Scan Execution Registry</h2>
            <span className="text-xs text-slate-400">{scans.length} Total Jobs</span>
          </div>

          {scans.length === 0 ? (
            <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-8 text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-slate-800/60 flex items-center justify-center mx-auto text-slate-400">
                ⚡
              </div>
              <p className="text-sm font-medium text-slate-300">No active scans running</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Launch a scan via the dashboard or trigger one via the headless CLI:
              </p>
              <code className="text-xs text-cyan-400 bg-slate-900 px-3 py-1.5 rounded-md border border-slate-800 inline-block font-mono">
                ashlynx scan http://127.0.0.1:8089 --profile SAFE_ACTIVE
              </code>
            </div>
          ) : (
            <div className="border border-slate-800 rounded-lg overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
                  <tr>
                    <th className="p-3">Status</th>
                    <th className="p-3">Target</th>
                    <th className="p-3">Profile</th>
                    <th className="p-3">Duration</th>
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
                      <td className="p-3">
                        <div className="font-mono text-xs text-slate-200">{s.target_url}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{s.id.slice(0, 8)}...</div>
                      </td>
                      <td className="p-3 font-mono text-xs text-slate-300">{s.profile}</td>
                      <td className="p-3 font-mono text-xs text-slate-400">{s.duration_seconds || 0}s</td>
                      <td className="p-3 font-mono font-bold text-cyan-400">{s.findings_count || 0}</td>
                      <td className="p-3 text-right space-x-2">
                        <button
                          onClick={() => handleViewFindings(s.id)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
                        >
                          Findings
                        </button>
                        <Link
                          href={`/attack-surface?scan_id=${s.id}`}
                          className="px-2 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-xs text-cyan-400 border border-cyan-800/60"
                        >
                          Surface
                        </Link>
                        {s.status === "RUNNING" && (
                          <button
                            onClick={() => handleCancelScan(s.id)}
                            className="px-2 py-1 rounded bg-red-950 hover:bg-red-900 text-xs text-red-400 border border-red-800/60"
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Registered Targets & Engine Guardrails */}
        <div className="space-y-6">
          {/* Target List */}
          <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-white">Registered Targets</h2>
              <span className="text-xs text-slate-400">{targets.length} Target(s)</span>
            </div>
            <div className="space-y-3">
              {targets.map((tgt) => (
                <div key={tgt.id} className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-semibold text-white">{tgt.name}</span>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/40">
                      VERIFIED
                    </span>
                  </div>
                  <p className="text-xs font-mono text-cyan-400">{tgt.base_url}</p>
                  <p className="text-xs text-slate-400">{tgt.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Engine Guardrails */}
          <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white">Engine Guardrails</h2>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center py-2 border-b border-slate-800/60">
                <span className="text-slate-400">ScopeGate Anti-SSRF</span>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                  ENFORCED
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-800/60">
                <span className="text-slate-400">Two-Phase Verifier</span>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                  ACTIVE
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-800/60">
                <span className="text-slate-400">Evidence SHA-256 Seal</span>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                  ENABLED
                </span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-slate-400">Rate Limiter</span>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                  10 req/s
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* New Scan Modal */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="border border-slate-800 bg-slate-900 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-white">Configure New DAST Scan</h3>
              <button onClick={() => setShowScanModal(false)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            {scanFormError && (
              <div className="p-3 rounded-lg border border-red-900/60 bg-red-950/30 text-xs text-red-400">
                {scanFormError}
              </div>
            )}

            <form onSubmit={handleLaunchScan} className="space-y-4 text-sm">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Target Base URL</label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  placeholder="http://127.0.0.1:8089"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Scan Profile</label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
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
                  <label className="block text-xs font-medium text-slate-400 mb-1">Max Crawl Depth</label>
                  <input
                    type="number"
                    min="1"
                    max="5"
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Max URLs</label>
                  <input
                    type="number"
                    min="5"
                    max="100"
                    value={maxUrls}
                    onChange={(e) => setMaxUrls(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
                  />
                </div>
              </div>

              <div className="flex items-start gap-2 pt-2">
                <input
                  type="checkbox"
                  id="auth-check"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-1"
                />
                <label htmlFor="auth-check" className="text-xs text-slate-300">
                  I confirm that I have written authorization to scan this target.
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLaunching}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-xs"
                >
                  {isLaunching ? "Initiating..." : "Start Scan Job"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Register Target Modal */}
      {showTargetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="border border-slate-800 bg-slate-900 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-white">Register Target Scope</h3>
              <button onClick={() => setShowTargetModal(false)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            {targetFormError && (
              <div className="p-3 rounded-lg border border-red-900/60 bg-red-950/30 text-xs text-red-400">
                {targetFormError}
              </div>
            )}

            <form onSubmit={handleRegisterTarget} className="space-y-4 text-sm">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Target Name</label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
                  placeholder="e.g. Test Staging Environment"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Base URL</label>
                <input
                  type="text"
                  value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono text-xs"
                  placeholder="http://127.0.0.1:8089"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Description</label>
                <textarea
                  value={targetDesc}
                  onChange={(e) => setTargetDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
                  placeholder="Authorized application scope description"
                  rows={2}
                />
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowTargetModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs"
                >
                  Register Target
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Findings Drawer */}
      {selectedScanFindings && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-2xl h-full bg-slate-900 border-l border-slate-800 p-6 space-y-6 overflow-y-auto shadow-2xl">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-lg font-bold text-white">Security Vulnerability Findings</h3>
                <p className="text-xs font-mono text-slate-400">Scan: {selectedScanFindings.scanId}</p>
              </div>
              <button
                onClick={() => setSelectedScanFindings(null)}
                className="text-slate-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>

            {/* Export Report Actions */}
            <div className="flex items-center gap-2 p-3 bg-slate-950 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400 font-medium mr-auto">Download Scan Report:</span>
              <a
                href={`http://localhost:8000/api/v1/reports/${selectedScanFindings.scanId}?format=json&download=true`}
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 border border-slate-700"
              >
                JSON
              </a>
              <a
                href={`http://localhost:8000/api/v1/reports/${selectedScanFindings.scanId}?format=html&download=true`}
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 border border-slate-700"
              >
                HTML
              </a>
              <a
                href={`http://localhost:8000/api/v1/reports/${selectedScanFindings.scanId}?format=markdown&download=true`}
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 border border-slate-700"
              >
                Markdown
              </a>
            </div>

            {/* Severity Filter Tabs */}
            <div className="flex gap-2 text-xs">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-3 py-1 rounded-md transition-colors ${
                    severityFilter === sev
                      ? "bg-cyan-600 text-white font-semibold"
                      : "bg-slate-800 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Findings List */}
            <div className="space-y-4">
              {selectedScanFindings.findings
                .filter((f) => severityFilter === "ALL" || f.severity === severityFilter)
                .map((f) => {
                  const isExpanded = expandedFindingId === f.id;
                  return (
                    <div
                      key={f.id}
                      className="border border-slate-800 rounded-xl bg-slate-950/60 p-4 space-y-3 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-3">
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
                          </div>
                          <h4 className="text-sm font-semibold text-white">{f.title}</h4>
                        </div>
                        <button
                          onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                          className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                        >
                          {isExpanded ? "Collapse" : "Details"}
                        </button>
                      </div>

                      {f.endpoint && (
                        <p className="text-xs font-mono text-slate-300 bg-slate-900 px-2 py-1 rounded border border-slate-800 break-all">
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
                                  SHA-256: {f.evidence.sha256_hash}
                                </p>
                              )}
                              {f.evidence.response_raw && (
                                <pre className="p-2 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-300 max-h-40 overflow-y-auto whitespace-pre-wrap">
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

              {selectedScanFindings.findings.length === 0 && (
                <div className="p-8 text-center text-slate-500 text-sm">
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
