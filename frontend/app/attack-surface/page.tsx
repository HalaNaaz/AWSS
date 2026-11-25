"use client";

import React, { useState, useEffect } from "react";
import { fetchApi } from "../../services/api-client";
import {
  AttackSurfaceSummary,
  PrioritizedEndpoint,
  DiscoveredEndpoint,
  ParameterIntelligence,
  APIEndpoint,
  AssetIntelligence,
  AttackSurfaceGraph
} from "../../types/models";

export default function AttackSurfaceDashboard() {
  const [scanId, setScanId] = useState<string>("");
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Search / filter state
  const [filterQuery, setFilterQuery] = useState<string>("");
  const [graphZoom, setGraphZoom] = useState<number>(1);
  const [selectedNodeType, setSelectedNodeType] = useState<string>("ALL");

  // Discovery data states
  const [summary, setSummary] = useState<AttackSurfaceSummary | null>(null);
  const [prioritized, setPrioritized] = useState<PrioritizedEndpoint[]>([]);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [parameters, setParameters] = useState<ParameterIntelligence[]>([]);
  const [apis, setApis] = useState<APIEndpoint[]>([]);
  const [assets, setAssets] = useState<AssetIntelligence[]>([]);
  const [graph, setGraph] = useState<AttackSurfaceGraph | null>(null);

  // Fetch telemetry when scanId changes
  const loadScanData = async (id: string) => {
    if (!id.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const summaryRes = await fetchApi<AttackSurfaceSummary>(`/discovery/${id}/summary`);
      setSummary(summaryRes);

      const [priRes, epRes, paramRes, apiRes, assetRes, graphRes] = await Promise.all([
        fetchApi<PrioritizedEndpoint[]>(`/discovery/${id}/prioritized`),
        fetchApi<DiscoveredEndpoint[]>(`/discovery/${id}/endpoints`),
        fetchApi<ParameterIntelligence[]>(`/discovery/${id}/parameters`),
        fetchApi<APIEndpoint[]>(`/discovery/${id}/apis`),
        fetchApi<AssetIntelligence[]>(`/discovery/${id}/assets`),
        fetchApi<AttackSurfaceGraph>(`/discovery/${id}/graph`)
      ]);

      setPrioritized(priRes || []);
      setEndpoints(epRes || []);
      setParameters(paramRes || []);
      setApis(apiRes || []);
      setAssets(assetRes || []);
      setGraph(graphRes || null);
    } catch (err: any) {
      setError(err?.message || "Failed to load attack surface data");
    } finally {
      setLoading(false);
    }
  };

  // Mount: auto-load scans and parse ?scan_id=...
  useEffect(() => {
    let initialScanId = "";
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const queryId = params.get("scan_id");
      if (queryId) {
        initialScanId = queryId;
        setScanId(queryId);
        loadScanData(queryId);
      }
    }

    fetchApi<any[]>("/scans/")
      .then((res) => {
        if (Array.isArray(res) && res.length > 0) {
          setRecentScans(res);
          if (!initialScanId) {
            const firstCompleted = res.find((s) => s.status === "COMPLETED") || res[0];
            setScanId(firstCompleted.id);
            loadScanData(firstCompleted.id);
          }
        }
      })
      .catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="border border-slate-800 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/60 to-slate-900 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
              PHASE 4
            </span>
            <h1 className="text-2xl font-bold tracking-tight text-white">Attack Surface Intelligence</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Automated asset mapping, parameter heuristic classification, API discovery, and topology graph
          </p>
        </div>

        {/* Scan Selector / Input */}
        <div className="flex flex-col sm:flex-row items-center gap-2 w-full md:w-auto">
          {recentScans.length > 0 && (
            <select
              value={scanId}
              onChange={(e) => {
                setScanId(e.target.value);
                loadScanData(e.target.value);
              }}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-full sm:w-48"
            >
              <option value="">Select Scan Job...</option>
              {recentScans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_url} ({s.status})
                </option>
              ))}
            </select>
          )}

          <input
            type="text"
            placeholder="Or enter Scan UUID..."
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-full sm:w-56 font-mono"
          />
          <button
            onClick={() => loadScanData(scanId)}
            disabled={loading || !scanId.trim()}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-xs rounded-lg transition-colors whitespace-nowrap w-full sm:w-auto"
          >
            {loading ? "Loading..." : "Load Surface"}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl border border-red-900/60 bg-red-950/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Metrics Row */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Endpoints</span>
            <p className="text-2xl font-bold text-cyan-400 mt-1">{summary.total_endpoints}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Parameters</span>
            <p className="text-2xl font-bold text-yellow-400 mt-1">{summary.total_parameters}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">APIs</span>
            <p className="text-2xl font-bold text-purple-400 mt-1">{summary.total_apis}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Assets</span>
            <p className="text-2xl font-bold text-blue-400 mt-1">{summary.total_assets}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Technologies</span>
            <p className="text-2xl font-bold text-emerald-400 mt-1">{summary.total_technologies}</p>
          </div>
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Graph Nodes</span>
            <p className="text-2xl font-bold text-slate-200 mt-1">{summary.graph_nodes_count}</p>
          </div>
          <div className="p-4 rounded-xl border border-red-950/60 bg-red-950/10">
            <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">High Priority</span>
            <p className="text-2xl font-bold text-red-500 mt-1">{summary.high_priority_endpoints_count}</p>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="border-b border-slate-800 flex flex-wrap gap-4 text-sm font-medium">
        {[
          { id: "overview", label: "Overview & Signals" },
          { id: "prioritized", label: `Prioritization Queue (${prioritized.length})` },
          { id: "endpoints", label: `Endpoints (${endpoints.length})` },
          { id: "parameters", label: `Parameters (${parameters.length})` },
          { id: "apis", label: `APIs (${apis.length})` },
          { id: "assets", label: `Assets (${assets.length})` },
          { id: "graph", label: `Topology Graph (${graph?.nodes?.length || 0})` }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
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

      {/* Search / Filter bar for data tables */}
      {activeTab !== "overview" && (
        <div className="flex items-center gap-3">
          <input
            type="text"
            placeholder={`Filter ${activeTab}...`}
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-full max-w-xs"
          />
          {filterQuery && (
            <button
              onClick={() => setFilterQuery("")}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Clear
            </button>
          )}
        </div>
      )}

      {/* Tab Panels */}
      <div className="min-h-[300px]">
        {/* Overview Tab */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {!summary ? (
              <div className="rounded-xl border border-slate-800 bg-slate-900/30 p-12 text-center text-slate-400">
                <p>No scan selected. Select a scan job from the dropdown above to visualize its attack surface.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
                  <h3 className="text-sm font-semibold text-white">Parameter Categories Breakdown</h3>
                  <div className="space-y-2 text-xs">
                    {Object.entries(summary.parameter_categories_breakdown || {}).map(([cat, count]) => (
                      <div key={cat} className="flex justify-between items-center py-1 border-b border-slate-800/60">
                        <span className="text-slate-400 font-mono">{cat}</span>
                        <span className="font-semibold text-cyan-400">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
                  <h3 className="text-sm font-semibold text-white">API Architectural Types</h3>
                  <div className="space-y-2 text-xs">
                    {Object.entries(summary.api_types_breakdown || {}).map(([type, count]) => (
                      <div key={type} className="flex justify-between items-center py-1 border-b border-slate-800/60">
                        <span className="text-slate-400 font-mono">{type}</span>
                        <span className="font-semibold text-purple-400">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-4">
                  <h3 className="text-sm font-semibold text-white">Client Asset Types</h3>
                  <div className="space-y-2 text-xs">
                    {Object.entries(summary.asset_types_breakdown || {}).map(([atype, count]) => (
                      <div key={atype} className="flex justify-between items-center py-1 border-b border-slate-800/60">
                        <span className="text-slate-400 font-mono">{atype}</span>
                        <span className="font-semibold text-blue-400">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Prioritized Endpoints Tab */}
        {activeTab === "prioritized" && (
          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3">Priority</th>
                  <th className="p-3">Score</th>
                  <th className="p-3">Method</th>
                  <th className="p-3">URL</th>
                  <th className="p-3">Signals</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {prioritized
                  .filter((p) => !filterQuery || p.url.toLowerCase().includes(filterQuery.toLowerCase()) || p.priority_level.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((p, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${
                          p.priority_level === "HIGH" ? "bg-red-950 text-red-400 border border-red-800/60" :
                          p.priority_level === "MEDIUM" ? "bg-amber-950 text-amber-400 border border-amber-800/60" :
                          "bg-blue-950 text-blue-400 border border-blue-800/60"
                        }`}>
                          {p.priority_level}
                        </span>
                      </td>
                      <td className="p-3 font-mono font-bold text-white">{p.priority_score}</td>
                      <td className="p-3 font-mono text-cyan-400">{p.method}</td>
                      <td className="p-3 font-mono text-xs text-slate-300 break-all">{p.url}</td>
                      <td className="p-3 text-xs text-slate-400">{p.risk_signals?.join("; ") || "-"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Endpoints Tab */}
        {activeTab === "endpoints" && (
          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3">Method</th>
                  <th className="p-3">URL</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Discovery Method</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {endpoints
                  .filter((ep) => !filterQuery || ep.url.toLowerCase().includes(filterQuery.toLowerCase()) || ep.endpoint_category.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((ep, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 font-mono text-cyan-400 font-semibold">{ep.method}</td>
                      <td className="p-3 font-mono text-xs text-slate-200 break-all">{ep.url}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                          {ep.endpoint_category}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-xs text-slate-400">{ep.status_code || 200}</td>
                      <td className="p-3 text-xs text-slate-500 font-mono">{ep.discovery_method}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Parameters Tab */}
        {activeTab === "parameters" && (
          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3">Parameter</th>
                  <th className="p-3">Location</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Confidence</th>
                  <th className="p-3">Sample (Redacted)</th>
                  <th className="p-3">Risk Signal</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {parameters
                  .filter((param) => !filterQuery || param.name.toLowerCase().includes(filterQuery.toLowerCase()) || param.category.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((param, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 font-mono font-bold text-white">{param.name}</td>
                      <td className="p-3 font-mono text-xs text-cyan-400">{param.location}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-yellow-950/60 text-yellow-400 border border-yellow-800/40">
                          {param.category}
                        </span>
                      </td>
                      <td className="p-3 text-slate-300">{Math.round(param.confidence * 100)}%</td>
                      <td className="p-3 font-mono text-xs text-slate-400">{param.sample_values_redacted?.[0] || "-"}</td>
                      <td className="p-3 text-xs text-red-400">{param.risk_signals?.[0] || "-"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* APIs Tab */}
        {activeTab === "apis" && (
          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3">Type</th>
                  <th className="p-3">Method</th>
                  <th className="p-3">URL</th>
                  <th className="p-3">Version</th>
                  <th className="p-3">Auth Required</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {apis
                  .filter((api) => !filterQuery || api.url.toLowerCase().includes(filterQuery.toLowerCase()) || api.api_type.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((api, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 font-mono text-purple-400 font-semibold">{api.api_type}</td>
                      <td className="p-3 font-mono text-cyan-400">{api.method}</td>
                      <td className="p-3 font-mono text-xs text-slate-300 break-all">{api.url}</td>
                      <td className="p-3 font-mono text-yellow-400">{api.version || "-"}</td>
                      <td className="p-3">
                        {api.auth_required ? (
                          <span className="px-2 py-0.5 rounded text-xs font-mono bg-red-950 text-red-400 border border-red-800/60">
                            REQUIRED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                            PUBLIC
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Assets Tab */}
        {activeTab === "assets" && (
          <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="p-3">Type</th>
                  <th className="p-3">URL</th>
                  <th className="p-3">MIME</th>
                  <th className="p-3">Source</th>
                  <th className="p-3">In Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {assets
                  .filter((asset) => !filterQuery || asset.url.toLowerCase().includes(filterQuery.toLowerCase()) || asset.asset_type.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((asset, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 font-mono text-blue-400">{asset.asset_type}</td>
                      <td className="p-3 font-mono text-xs text-slate-300 break-all">{asset.url}</td>
                      <td className="p-3 text-xs text-slate-400">{asset.mime_type || "-"}</td>
                      <td className="p-3 text-xs text-slate-400">{asset.discovery_source}</td>
                      <td className="p-3 text-xs text-emerald-400">{asset.in_scope ? "YES" : "NO"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Attack Surface Graph Tab */}
        {activeTab === "graph" && (
          <div className="border border-slate-800 rounded-xl p-6 bg-slate-900/30 space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <h3 className="text-base font-semibold text-white">Graph Topology Explorer</h3>
                <p className="text-xs text-slate-400">
                  {graph?.node_count || 0} nodes and {graph?.edge_count || 0} directed edges mapped
                </p>
              </div>

              <div className="flex items-center gap-2">
                {/* Node type filter */}
                <select
                  value={selectedNodeType}
                  onChange={(e) => setSelectedNodeType(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300"
                >
                  <option value="ALL">All Nodes</option>
                  <option value="DOMAIN">Domains</option>
                  <option value="ENDPOINT">Endpoints</option>
                  <option value="PARAMETER">Parameters</option>
                  <option value="API_ROUTE">API Routes</option>
                  <option value="JS_ASSET">JS Assets</option>
                </select>

                {/* Zoom Controls */}
                <div className="flex items-center border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
                  <button
                    onClick={() => setGraphZoom((z) => Math.max(0.5, z - 0.2))}
                    className="px-2 py-1 text-slate-400 hover:text-white text-xs border-r border-slate-800"
                    title="Zoom Out"
                  >
                    -
                  </button>
                  <span className="px-2 py-1 text-[10px] font-mono text-slate-400">
                    {Math.round(graphZoom * 100)}%
                  </span>
                  <button
                    onClick={() => setGraphZoom((z) => Math.min(2.0, z + 0.2))}
                    className="px-2 py-1 text-slate-400 hover:text-white text-xs border-l border-slate-800"
                    title="Zoom In"
                  >
                    +
                  </button>
                </div>

                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(graph, null, 2)], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `attack_surface_graph_${scanId || "scan"}.json`;
                    a.click();
                  }}
                  disabled={!graph}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700 transition-colors"
                >
                  Export Graph JSON
                </button>
              </div>
            </div>

            {/* Visual Canvas Representation */}
            <div
              className="border border-slate-800/80 rounded-xl bg-slate-950 p-6 min-h-[350px] overflow-auto transition-transform"
              style={{ transform: `scale(${graphZoom})`, transformOrigin: "top left" }}
            >
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {graph?.nodes
                  ?.filter((n) => selectedNodeType === "ALL" || n.node_type === selectedNodeType)
                  ?.slice(0, 48)
                  ?.map((n) => (
                    <div
                      key={n.id}
                      className="p-3 rounded-lg border border-slate-800 bg-slate-900/60 hover:border-cyan-500/50 transition-colors space-y-1.5"
                    >
                      <div className="flex justify-between items-center">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${
                            n.node_type === "DOMAIN"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                              : n.node_type === "API_ROUTE"
                              ? "bg-purple-950 text-purple-400 border border-purple-800/60"
                              : n.node_type === "PARAMETER"
                              ? "bg-yellow-950 text-yellow-400 border border-yellow-800/60"
                              : n.node_type === "FINDING"
                              ? "bg-red-950 text-red-400 border border-red-800/60"
                              : "bg-slate-800 text-slate-300"
                          }`}
                        >
                          {n.node_type}
                        </span>
                      </div>
                      <p className="text-xs font-semibold text-slate-200 truncate">{n.label}</p>
                      <p className="text-[10px] font-mono text-slate-500 truncate">{n.id}</p>
                    </div>
                  ))}
              </div>

              {(!graph?.nodes || graph.nodes.length === 0) && (
                <div className="p-12 text-center text-slate-500 text-sm">
                  No topology nodes to display.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
