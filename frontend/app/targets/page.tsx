"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { fetchApi } from "../../services/api-client";
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
  const [syncError, setSyncError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const loadTargets = async () => {
    try {
      const res = await fetchApi<Target[]>("/targets/");
      if (Array.isArray(res) && res.length > 0) {
        setTargets(res);
      }
      setSyncError(null);
    } catch (err: any) {
      setSyncError(err?.message || "Unable to synchronize target inventory with backend API.");
    }
  };

  useEffect(() => {
    loadTargets();
  }, []);

  useEffect(() => {
    if (!showAddModal) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setShowAddModal(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [showAddModal]);

  const handleAddTarget = async (e: React.FormEvent) => {
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

    setIsSubmitting(true);
    try {
      const created = await fetchApi<Target>("/targets/", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          base_url: url.trim(),
          description: desc.trim() || undefined,
          asset_criticality: 3,
        }),
      });
      setTargets((prev) => [...prev, created]);
      setShowAddModal(false);
      setName("");
      setUrl("");
      setDesc("");
    } catch (err: any) {
      setFormError(err?.message || "Failed to register target");
    } finally {
      setIsSubmitting(false);
    }
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

      {syncError && (
        <div
          role="alert"
          className="p-3 border border-[#F87171] bg-[#FEE2E2] dark:bg-[#2B0F10] flex items-center justify-between gap-3 text-xs font-mono text-[#C62828] dark:text-[#FF5252]"
        >
          <span>INVENTORY SYNC WARNING // {syncError}</span>
          <Button onClick={loadTargets} variant="outline" size="sm">
            Retry
          </Button>
        </div>
      )}

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
