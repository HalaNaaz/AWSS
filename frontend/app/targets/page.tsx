"use client";

import React, { useState } from "react";
import Link from "next/link";

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

export default function TargetsPage() {
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

  const [showAddModal, setShowAddModal] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [desc, setDesc] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const handleAddTarget = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError("Target name is required");
      return;
    }
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      setFormError("Target URL must start with http:// or https://");
      return;
    }

    const newTarget: Target = {
      id: `tgt-${Date.now()}`,
      name: name.trim(),
      base_url: url.trim(),
      description: desc.trim(),
      asset_criticality: 3,
      verified: true,
      scope_rules: [{ rule_type: "INCLUDE", pattern: `${url.trim()}/*` }],
      created_at: new Date().toISOString(),
    };

    setTargets((prev) => [...prev, newTarget]);
    setShowAddModal(false);
    setName("");
    setUrl("");
    setDesc("");
  };

  return (
    <div className="space-y-6">
      <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-6 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Authorized Target Management</h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure application roots, verified ownership boundaries, and ScopeGate rules
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors"
        >
          + Add Target
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {targets.map((tgt) => (
          <div key={tgt.id} className="border border-slate-800 rounded-xl bg-slate-900/40 p-5 space-y-4">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-base font-semibold text-white">{tgt.name}</h3>
                <p className="text-xs font-mono text-cyan-400 mt-0.5">{tgt.base_url}</p>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-emerald-400 bg-emerald-950/80 border border-emerald-800/60">
                VERIFIED
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">{tgt.description || "No description provided."}</p>

            <div className="border-t border-slate-800/80 pt-3 space-y-2">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">Scope Boundaries</span>
              {tgt.scope_rules.map((r, i) => (
                <div key={i} className="flex items-center gap-2 text-xs font-mono text-slate-300">
                  <span className="text-emerald-400 text-[10px] font-bold">[{r.rule_type}]</span>
                  <span className="truncate">{r.pattern}</span>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Link
                href={`/?target_id=${tgt.id}`}
                className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-xs text-cyan-400 border border-cyan-800/60 transition-colors"
              >
                Scan Target
              </Link>
            </div>
          </div>
        ))}
      </div>

      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="border border-slate-800 bg-slate-900 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-white">Register Target Scope</h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            {formError && (
              <div className="p-3 rounded-lg border border-red-900/60 bg-red-950/30 text-xs text-red-400">
                {formError}
              </div>
            )}

            <form onSubmit={handleAddTarget} className="space-y-4 text-sm">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Target Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
                  placeholder="e.g. Staging Environment"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Base URL</label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono text-xs"
                  placeholder="http://127.0.0.1:8089"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Description</label>
                <textarea
                  value={desc}
                  onChange={(e) => setDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs"
                  placeholder="Target purpose and boundaries"
                  rows={2}
                />
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs"
                >
                  Register
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
