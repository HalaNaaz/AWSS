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
import {
  PanelHeader,
  Button,
  MetricCell,
} from "../../components/ui/swiss-components";
import { Radio, Search, Download, ZoomIn, ZoomOut, RefreshCw } from "lucide-react";

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

  const tabList = [
    { id: "overview", label: "Overview & Signals" },
    { id: "prioritized", label: `Prioritization Queue (${prioritized.length})` },
    { id: "endpoints", label: `Endpoints (${endpoints.length})` },
    { id: "parameters", label: `Parameters (${parameters.length})` },
    { id: "apis", label: `APIs (${apis.length})` },
    { id: "assets", label: `Assets (${assets.length})` },
    { id: "graph", label: `Topology Graph (${graph?.nodes?.length || 0})` }
  ];

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <PanelHeader
        tag="PHASE 4 // DISCOVERY"
        title="Attack Surface Intelligence"
        subtitle="Automated asset mapping, parameter heuristic classification, API discovery, and topology graph"
        actions={
          <div className="flex flex-col sm:flex-row items-center gap-2 w-full sm:w-auto font-mono text-xs">
            {recentScans.length > 0 && (
              <select
                value={scanId}
                onChange={(e) => {
                  setScanId(e.target.value);
                  loadScanData(e.target.value);
                }}
                className="px-3 py-1.5 bg-surface-subtle border border-swiss-border text-ink-primary focus:outline-none focus:border-accent w-full sm:w-48 rounded-none text-xs"
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
              className="px-3 py-1.5 bg-surface-subtle border border-swiss-border text-ink-primary placeholder-ink-muted focus:outline-none focus:border-accent w-full sm:w-52 font-mono text-xs rounded-none"
            />
            <Button
              onClick={() => loadScanData(scanId)}
              disabled={loading || !scanId.trim()}
              variant="primary"
              size="md"
            >
              {loading ? "Loading..." : "Load Surface"}
            </Button>
          </div>
        }
      />

      {error && (
        <div className="p-3 border border-[#F87171] bg-[#FEE2E2] dark:bg-[#2B0F10] text-xs font-mono text-[#C62828] dark:text-[#FF5252]">
          {error}
        </div>
      )}

      {/* Metrics Row — Swiss Technical Grid */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 border border-swiss-border bg-surface divide-x divide-y sm:divide-y-0 divide-swiss-border">
          <MetricCell
            index="01"
            label="Endpoints"
            value={<span className="text-accent">{summary.total_endpoints}</span>}
            sublabel="Observed routes"
          />
          <MetricCell
            index="02"
            label="Parameters"
            value={<span className="text-[#D97706] dark:text-[#FBBF24]">{summary.total_parameters}</span>}
            sublabel="Classified inputs"
          />
          <MetricCell
            index="03"
            label="APIs"
            value={<span className="text-[#2563EB] dark:text-[#60A5FA]">{summary.total_apis}</span>}
            sublabel="REST/GraphQL"
          />
          <MetricCell
            index="04"
            label="Assets"
            value={<span className="text-ink-primary">{summary.total_assets}</span>}
            sublabel="Scripts & styles"
          />
          <MetricCell
            index="05"
            label="Technologies"
            value={<span className="text-[#15803D] dark:text-[#4ADE80]">{summary.total_technologies}</span>}
            sublabel="Fingerprinted stacks"
          />
          <MetricCell
            index="06"
            label="Graph Nodes"
            value={<span className="text-ink-secondary">{summary.graph_nodes_count}</span>}
            sublabel="Topology elements"
          />
          <MetricCell
            index="07"
            label="High Priority"
            value={<span className="text-[#C62828] dark:text-[#FF5252]">{summary.high_priority_endpoints_count}</span>}
            sublabel="Critical targets"
            indicatorColor="#C62828"
          />
        </div>
      )}

      {/* Navigation Tabs Bar */}
      <div className="border-b border-swiss-border bg-surface flex flex-wrap gap-1 px-2 pt-2 text-xs font-mono">
        {tabList.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-2 border-b-2 uppercase tracking-wider font-semibold transition-colors ${
              activeTab === tab.id
                ? "border-accent text-accent font-bold bg-surface-subtle"
                : "border-transparent text-ink-muted hover:text-ink-primary hover:border-swiss-border"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Search / Filter bar for tables */}
      {activeTab !== "overview" && (
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder={`Filter ${activeTab}...`}
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            className="px-3 py-1.5 bg-surface border border-swiss-border text-xs font-mono text-ink-primary placeholder-ink-muted focus:outline-none focus:border-accent w-full max-w-sm rounded-none"
          />
          {filterQuery && (
            <Button
              onClick={() => setFilterQuery("")}
              variant="outline"
              size="sm"
            >
              Clear
            </Button>
          )}
        </div>
      )}

      {/* Tab Panels */}
      <div className="min-h-[300px]">
        {/* Overview Tab */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {!summary ? (
              <div className="border border-swiss-border bg-surface p-12 text-center text-ink-muted font-mono text-xs">
                No scan selected. Select a scan job from the dropdown above to visualize its attack surface.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
                <div className="border border-swiss-border bg-surface">
                  <div className="px-4 py-2.5 border-b border-swiss-border bg-surface-subtle font-bold uppercase tracking-wider text-ink-primary">
                    Parameter Categories Breakdown
                  </div>
                  <div className="p-4 space-y-2 divide-y divide-swiss-border-subtle">
                    {Object.entries(summary.parameter_categories_breakdown || {}).map(([cat, count]) => (
                      <div key={cat} className="flex justify-between items-center pt-1.5 first:pt-0">
                        <span className="text-ink-secondary">{cat}</span>
                        <span className="font-bold text-accent tabular-nums">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="border border-swiss-border bg-surface">
                  <div className="px-4 py-2.5 border-b border-swiss-border bg-surface-subtle font-bold uppercase tracking-wider text-ink-primary">
                    API Architectural Types
                  </div>
                  <div className="p-4 space-y-2 divide-y divide-swiss-border-subtle">
                    {Object.entries(summary.api_types_breakdown || {}).map(([type, count]) => (
                      <div key={type} className="flex justify-between items-center pt-1.5 first:pt-0">
                        <span className="text-ink-secondary">{type}</span>
                        <span className="font-bold text-[#2563EB] dark:text-[#60A5FA] tabular-nums">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="border border-swiss-border bg-surface">
                  <div className="px-4 py-2.5 border-b border-swiss-border bg-surface-subtle font-bold uppercase tracking-wider text-ink-primary">
                    Client Asset Types
                  </div>
                  <div className="p-4 space-y-2 divide-y divide-swiss-border-subtle">
                    {Object.entries(summary.asset_types_breakdown || {}).map(([atype, count]) => (
                      <div key={atype} className="flex justify-between items-center pt-1.5 first:pt-0">
                        <span className="text-ink-secondary">{atype}</span>
                        <span className="font-bold text-ink-primary tabular-nums">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Prioritization Queue Tab */}
        {activeTab === "prioritized" && (
          <div className="border border-swiss-border bg-surface overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
                <tr>
                  <th className="p-3 font-semibold">Priority</th>
                  <th className="p-3 font-semibold">Score</th>
                  <th className="p-3 font-semibold">Method</th>
                  <th className="p-3 font-semibold">URL</th>
                  <th className="p-3 font-semibold">Signals</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-swiss-border-subtle font-mono text-xs">
                {prioritized
                  .filter((p) => !filterQuery || p.url.toLowerCase().includes(filterQuery.toLowerCase()) || p.priority_level.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((p, idx) => (
                    <tr key={idx} className="hover:bg-surface-subtle/80 transition-colors">
                      <td className="p-3">
                        <span className={`px-2 py-0.5 text-xs font-mono font-bold tracking-wider border rounded-none uppercase ${
                          p.priority_level === "HIGH" ? "bg-[#FEE2E2] dark:bg-[#2B0F10] text-[#C62828] dark:text-[#FF5252] border-[#F87171] dark:border-[#5C1D1E]" :
                          p.priority_level === "MEDIUM" ? "bg-[#FEF3C7] dark:bg-[#291B07] text-[#D97706] dark:text-[#FBBF24] border-[#FCD34D] dark:border-[#52380E]" :
                          "bg-[#EFF6FF] dark:bg-[#0C1A30] text-[#2563EB] dark:text-[#60A5FA] border-[#93C5FD] dark:border-[#1E3A8A]"
                        }`}>
                          {p.priority_level}
                        </span>
                      </td>
                      <td className="p-3 font-bold text-ink-primary tabular-nums">{p.priority_score}</td>
                      <td className="p-3 text-accent font-semibold">{p.method}</td>
                      <td className="p-3 text-ink-primary break-all">{p.url}</td>
                      <td className="p-3 text-ink-muted font-sans">{p.risk_signals?.join("; ") || "-"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Endpoints Tab */}
        {activeTab === "endpoints" && (
          <div className="border border-swiss-border bg-surface overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
                <tr>
                  <th className="p-3 font-semibold">Method</th>
                  <th className="p-3 font-semibold">URL</th>
                  <th className="p-3 font-semibold">Category</th>
                  <th className="p-3 font-semibold">Status</th>
                  <th className="p-3 font-semibold">Discovery Method</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-swiss-border-subtle font-mono text-xs">
                {endpoints
                  .filter((ep) => !filterQuery || ep.url.toLowerCase().includes(filterQuery.toLowerCase()) || ep.endpoint_category.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((ep, idx) => (
                    <tr key={idx} className="hover:bg-surface-subtle/80 transition-colors">
                      <td className="p-3 font-bold text-accent">{ep.method}</td>
                      <td className="p-3 text-ink-primary break-all">{ep.url}</td>
                      <td className="p-3">
                        <span className="px-1.5 py-0.5 text-[10px] bg-surface-subtle text-ink-secondary border border-swiss-border">
                          {ep.endpoint_category}
                        </span>
                      </td>
                      <td className="p-3 text-ink-muted tabular-nums">{ep.status_code || 200}</td>
                      <td className="p-3 text-ink-secondary">{ep.discovery_method}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Parameters Tab */}
        {activeTab === "parameters" && (
          <div className="border border-swiss-border bg-surface overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
                <tr>
                  <th className="p-3 font-semibold">Parameter</th>
                  <th className="p-3 font-semibold">Location</th>
                  <th className="p-3 font-semibold">Category</th>
                  <th className="p-3 font-semibold">Confidence</th>
                  <th className="p-3 font-semibold">Sample (Redacted)</th>
                  <th className="p-3 font-semibold">Risk Signal</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-swiss-border-subtle font-mono text-xs">
                {parameters
                  .filter((param) => !filterQuery || param.name.toLowerCase().includes(filterQuery.toLowerCase()) || param.category.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((param, idx) => (
                    <tr key={idx} className="hover:bg-surface-subtle/80 transition-colors">
                      <td className="p-3 font-bold text-ink-primary">{param.name}</td>
                      <td className="p-3 text-accent">{param.location}</td>
                      <td className="p-3">
                        <span className="px-1.5 py-0.5 text-[10px] bg-accent-subtle text-accent border border-accent/20 font-bold">
                          {param.category}
                        </span>
                      </td>
                      <td className="p-3 text-ink-secondary tabular-nums">{Math.round(param.confidence * 100)}%</td>
                      <td className="p-3 text-ink-muted font-mono">{param.sample_values_redacted?.[0] || "-"}</td>
                      <td className="p-3 text-[#C62828] dark:text-[#FF5252]">{param.risk_signals?.[0] || "-"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* APIs Tab */}
        {activeTab === "apis" && (
          <div className="border border-swiss-border bg-surface overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
                <tr>
                  <th className="p-3 font-semibold">Type</th>
                  <th className="p-3 font-semibold">Method</th>
                  <th className="p-3 font-semibold">URL</th>
                  <th className="p-3 font-semibold">Version</th>
                  <th className="p-3 font-semibold">Auth Required</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-swiss-border-subtle font-mono text-xs">
                {apis
                  .filter((api) => !filterQuery || api.url.toLowerCase().includes(filterQuery.toLowerCase()) || api.api_type.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((api, idx) => (
                    <tr key={idx} className="hover:bg-surface-subtle/80 transition-colors">
                      <td className="p-3 font-bold text-[#2563EB] dark:text-[#60A5FA]">{api.api_type}</td>
                      <td className="p-3 text-accent font-semibold">{api.method}</td>
                      <td className="p-3 text-ink-primary break-all">{api.url}</td>
                      <td className="p-3 text-ink-muted">{api.version || "-"}</td>
                      <td className="p-3">
                        {api.auth_required ? (
                          <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold bg-[#FEE2E2] dark:bg-[#2B0F10] text-[#C62828] dark:text-[#FF5252] border border-[#F87171] dark:border-[#5C1D1E]">
                            REQUIRED
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold bg-[#ECFDF5] dark:bg-[#092015] text-[#15803D] dark:text-[#4ADE80] border border-[#6EE7B7] dark:border-[#065F46]">
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
          <div className="border border-swiss-border bg-surface overflow-hidden">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-surface-subtle border-b border-swiss-border text-[11px] font-mono text-ink-muted uppercase">
                <tr>
                  <th className="p-3 font-semibold">Type</th>
                  <th className="p-3 font-semibold">URL</th>
                  <th className="p-3 font-semibold">MIME</th>
                  <th className="p-3 font-semibold">Source</th>
                  <th className="p-3 font-semibold">In Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-swiss-border-subtle font-mono text-xs">
                {assets
                  .filter((asset) => !filterQuery || asset.url.toLowerCase().includes(filterQuery.toLowerCase()) || asset.asset_type.toLowerCase().includes(filterQuery.toLowerCase()))
                  .map((asset, idx) => (
                    <tr key={idx} className="hover:bg-surface-subtle/80 transition-colors">
                      <td className="p-3 font-bold text-ink-secondary">{asset.asset_type}</td>
                      <td className="p-3 text-ink-primary break-all">{asset.url}</td>
                      <td className="p-3 text-ink-muted">{asset.mime_type || "-"}</td>
                      <td className="p-3 text-ink-muted">{asset.discovery_source}</td>
                      <td className="p-3 font-bold text-[#15803D] dark:text-[#4ADE80]">{asset.in_scope ? "YES" : "NO"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Attack Surface Graph Tab */}
        {activeTab === "graph" && (
          <div className="border border-swiss-border bg-surface p-4 sm:p-5 space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <h3 className="text-sm font-mono font-bold text-ink-primary uppercase tracking-wider">
                  Graph Topology Explorer
                </h3>
                <p className="text-xs font-mono text-ink-muted mt-0.5">
                  {graph?.node_count || 0} nodes and {graph?.edge_count || 0} directed edges mapped
                </p>
              </div>

              <div className="flex items-center gap-2 font-mono text-xs">
                <select
                  value={selectedNodeType}
                  onChange={(e) => setSelectedNodeType(e.target.value)}
                  className="px-2.5 py-1.5 bg-surface-subtle border border-swiss-border text-xs text-ink-primary rounded-none"
                >
                  <option value="ALL">All Nodes</option>
                  <option value="DOMAIN">Domains</option>
                  <option value="ENDPOINT">Endpoints</option>
                  <option value="PARAMETER">Parameters</option>
                  <option value="API_ROUTE">API Routes</option>
                  <option value="JS_ASSET">JS Assets</option>
                </select>

                <div className="flex items-center border border-swiss-border bg-surface-subtle">
                  <button
                    onClick={() => setGraphZoom((z) => Math.max(0.5, z - 0.2))}
                    className="px-2 py-1 text-ink-secondary hover:text-ink-primary border-r border-swiss-border"
                    title="Zoom Out"
                  >
                    -
                  </button>
                  <span className="px-2 py-1 text-[10px] font-mono text-ink-muted tabular-nums">
                    {Math.round(graphZoom * 100)}%
                  </span>
                  <button
                    onClick={() => setGraphZoom((z) => Math.min(2.0, z + 0.2))}
                    className="px-2 py-1 text-ink-secondary hover:text-ink-primary border-l border-swiss-border"
                    title="Zoom In"
                  >
                    +
                  </button>
                </div>

                <Button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(graph, null, 2)], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `attack_surface_graph_${scanId || "scan"}.json`;
                    a.click();
                  }}
                  disabled={!graph}
                  variant="outline"
                  size="sm"
                >
                  Export Graph JSON
                </Button>
              </div>
            </div>

            {/* Visual Canvas Representation */}
            <div
              className="border border-swiss-border bg-surface-subtle p-5 min-h-[350px] overflow-auto transition-transform"
              style={{ transform: `scale(${graphZoom})`, transformOrigin: "top left" }}
            >
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {graph?.nodes
                  ?.filter((n) => selectedNodeType === "ALL" || n.node_type === selectedNodeType)
                  ?.slice(0, 48)
                  ?.map((n) => (
                    <div
                      key={n.id}
                      className="p-3 border border-swiss-border bg-surface hover:border-accent transition-colors space-y-1 font-mono text-xs"
                    >
                      <div className="flex justify-between items-center">
                        <span className="px-1.5 py-0.5 text-[9px] font-bold tracking-widest border border-swiss-border bg-surface-subtle uppercase">
                          {n.node_type}
                        </span>
                      </div>
                      <p className="font-bold text-ink-primary truncate">{n.label}</p>
                      <p className="text-[10px] text-ink-muted truncate">{n.id}</p>
                    </div>
                  ))}
              </div>

              {(!graph?.nodes || graph.nodes.length === 0) && (
                <div className="p-12 text-center text-ink-muted text-xs font-mono">
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
