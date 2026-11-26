"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  PanelHeader,
  Button,
} from "../../components/ui/swiss-components";
import { ShieldCheck, Plus, ExternalLink, Globe, Layers, AlertCircle } from "lucide-react";

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
      {/* Editorial Header */}
      <PanelHeader
        tag="SCOPE // INVENTORY"
        title="Authorized Target Management"
        subtitle="Configure application roots, verified ownership boundaries, and ScopeGate rules"
        actions={
          <Button
            onClick={() => setShowAddModal(true)}
            variant="primary"
            size="md"
          >
            + Add Target
          </Button>
        }
      />

      {/* Targets Modular Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {targets.map((tgt, idx) => (
          <div
            key={tgt.id}
            className="border border-swiss-border bg-surface flex flex-col justify-between"
          >
            <div>
              <div className="px-4 py-3 border-b border-swiss-border bg-surface-subtle flex justify-between items-center">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-accent">
                    {String(idx + 1).padStart(2, "0")} {"//"}
                  </span>
                  <h3 className="text-sm font-mono font-bold text-ink-primary uppercase tracking-wider truncate">
                    {tgt.name}
                  </h3>
                </div>
                <span className="px-1.5 py-0.5 text-[10px] font-mono font-bold tracking-wider text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-800">
                  VERIFIED
                </span>
              </div>

              <div className="p-4 space-y-3 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-ink-muted uppercase block">Root Endpoint</span>
                  <p className="text-accent text-xs font-bold break-all mt-0.5">{tgt.base_url}</p>
                </div>

                <div className="font-sans text-xs text-ink-secondary leading-relaxed border-t border-swiss-border-subtle pt-2">
                  {tgt.description || "No description provided."}
                </div>

                <div className="border-t border-swiss-border-subtle pt-2 space-y-1.5">
                  <span className="text-[10px] font-semibold text-ink-muted uppercase tracking-wider block">
                    Scope Boundaries
                  </span>
                  {tgt.scope_rules.map((r, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-xs text-ink-secondary bg-surface-subtle p-1.5 border border-swiss-border">
                      <span className="text-emerald-600 dark:text-emerald-400 text-[10px] font-bold">[{r.rule_type}]</span>
                      <span className="truncate">{r.pattern}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-3 border-t border-swiss-border bg-surface-subtle flex justify-between items-center text-xs font-mono">
              <span className="text-[11px] text-ink-muted">CRITICALITY: {tgt.asset_criticality}/5</span>
              <Link
                href={`/?target_id=${tgt.id}`}
                className="px-2.5 py-1 text-xs font-mono font-semibold uppercase tracking-wider border border-accent bg-accent text-white hover:bg-accent-hover transition-colors"
              >
                Scan Target
              </Link>
            </div>
          </div>
        ))}
      </div>

      {/* Add Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="border border-swiss-border-strong bg-surface max-w-md w-full p-6 space-y-4 shadow-swiss-md">
            <div className="flex justify-between items-center border-b border-swiss-border pb-3">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-accent">01 {"//"}</span>
                <h3 className="text-base font-display font-bold text-ink-primary uppercase tracking-tight">
                  Register Target Scope
                </h3>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-ink-muted hover:text-ink-primary font-mono text-sm px-1.5 py-0.5 border border-swiss-border hover:bg-surface-subtle"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-3 border border-[#F87171] bg-[#FEE2E2] dark:bg-[#2B0F10] text-xs font-mono text-[#C62828] dark:text-[#FF5252]">
                {formError}
              </div>
            )}

            <form onSubmit={handleAddTarget} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Target Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary text-xs font-mono rounded-none"
                  placeholder="e.g. Staging Environment"
                  required
                />
              </div>

              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Base URL</label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary font-mono text-xs rounded-none"
                  placeholder="http://127.0.0.1:8089"
                  required
                />
              </div>

              <div>
                <label className="block text-ink-secondary mb-1 uppercase font-semibold">Description</label>
                <textarea
                  value={desc}
                  onChange={(e) => setDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-subtle border border-swiss-border text-ink-primary text-xs font-mono rounded-none"
                  placeholder="Target purpose and boundaries"
                  rows={2}
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-swiss-border">
                <Button
                  type="button"
                  onClick={() => setShowAddModal(false)}
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
                  Register
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
