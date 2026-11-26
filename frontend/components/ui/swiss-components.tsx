"use client";

import React from "react";
import Link from "next/link";
import { Check, Copy } from "lucide-react";

/* ==========================================================================
   SEVERITY BADGE — SWISS TECHNICAL GRID
   Accessible, high-contrast, flat, 1px structural border
   ========================================================================== */
export interface SeverityBadgeProps {
  severity: string;
  count?: number;
  className?: string;
  size?: "sm" | "md";
}

export function SeverityBadge({ severity, count, className = "", size = "md" }: SeverityBadgeProps) {
  const norm = (severity || "INFO").toUpperCase();
  
  let styles = "bg-[#F1F5F9] dark:bg-[#141A23] text-[#64748B] dark:text-[#94A3B8] border-[#CBD5E1] dark:border-[#334155]";
  if (norm === "CRITICAL") {
    styles = "bg-[#FEE2E2] dark:bg-[#2B0F10] text-[#C62828] dark:text-[#FF5252] border-[#F87171] dark:border-[#5C1D1E]";
  } else if (norm === "HIGH") {
    styles = "bg-[#FFEBEE] dark:bg-[#2A1313] text-[#E53935] dark:text-[#FF6E6A] border-[#FCA5A5] dark:border-[#5A2020]";
  } else if (norm === "MEDIUM") {
    styles = "bg-[#FEF3C7] dark:bg-[#291B07] text-[#D97706] dark:text-[#FBBF24] border-[#FCD34D] dark:border-[#52380E]";
  } else if (norm === "LOW") {
    styles = "bg-[#EFF6FF] dark:bg-[#0C1A30] text-[#2563EB] dark:text-[#60A5FA] border-[#93C5FD] dark:border-[#1E3A8A]";
  } else if (norm === "INFORMATIONAL" || norm === "INFO") {
    styles = "bg-[#F1F5F9] dark:bg-[#141A23] text-[#64748B] dark:text-[#94A3B8] border-[#CBD5E1] dark:border-[#334155]";
  }

  const padding = size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs";

  return (
    <span
      className={`inline-flex items-center gap-1 font-mono font-bold uppercase tracking-wider border rounded-none tabular-nums ${padding} ${styles} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      <span>{norm}</span>
      {count !== undefined && <span className="opacity-90 ml-0.5">({count})</span>}
    </span>
  );
}

/* ==========================================================================
   STATUS BADGE — SWISS TECHNICAL GRID
   ========================================================================== */
export function StatusBadge({ status, className = "" }: { status: string; className?: string }) {
  const norm = (status || "UNKNOWN").toUpperCase();
  let color = "bg-surface-subtle text-ink-secondary border-swiss-border";

  if (norm === "COMPLETED" || norm === "VERIFIED" || norm === "RESOLVED") {
    color = "bg-[#ECFDF5] dark:bg-[#092015] text-[#15803D] dark:text-[#4ADE80] border-[#6EE7B7] dark:border-[#065F46]";
  } else if (norm === "RUNNING" || norm === "IN_PROGRESS") {
    color = "bg-[#EFF6FF] dark:bg-[#0C1A30] text-[#2563EB] dark:text-[#60A5FA] border-[#93C5FD] dark:border-[#1E3A8A] animate-pulse";
  } else if (norm === "FAILED" || norm === "ERROR") {
    color = "bg-[#FEE2E2] dark:bg-[#2B0F10] text-[#C62828] dark:text-[#FF5252] border-[#F87171] dark:border-[#5C1D1E]";
  } else if (norm === "QUEUED" || norm === "SUSPECTED" || norm === "NEEDS_REVIEW") {
    color = "bg-[#FEF3C7] dark:bg-[#291B07] text-[#D97706] dark:text-[#FBBF24] border-[#FCD34D] dark:border-[#52380E]";
  } else if (norm === "CANCELLED" || norm === "DISMISSED") {
    color = "bg-surface-subtle text-ink-muted border-swiss-border";
  }

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono font-semibold tracking-wider uppercase border rounded-none ${color} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-none bg-current" />
      {norm}
    </span>
  );
}

/* ==========================================================================
   BUTTON — SWISS TECHNICAL GRID
   Sharp, precise, 1px border, uppercase or technical labels
   ========================================================================== */
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "outline" | "ghost" | "destructive";
  size?: "sm" | "md" | "lg";
}

export function Button({
  children,
  variant = "secondary",
  size = "md",
  className = "",
  disabled,
  ...props
}: ButtonProps) {
  const base = "inline-flex items-center justify-center font-mono font-semibold tracking-wider uppercase transition-colors rounded-none border disabled:opacity-40 disabled:cursor-not-allowed";
  
  let sizeStyles = "px-3 py-1.5 text-xs";
  if (size === "sm") sizeStyles = "px-2 py-1 text-[11px]";
  if (size === "lg") sizeStyles = "px-4 py-2 text-sm";

  let variantStyles = "bg-surface hover:bg-surface-subtle text-ink-primary border-swiss-border";
  if (variant === "primary") {
    variantStyles = "bg-[#E53935] hover:bg-[#C62828] text-white border-[#C62828]";
  } else if (variant === "secondary") {
    variantStyles = "bg-surface-subtle hover:bg-surface text-ink-primary border-swiss-border";
  } else if (variant === "outline") {
    variantStyles = "bg-transparent hover:bg-surface-subtle text-ink-primary border-swiss-border";
  } else if (variant === "ghost") {
    variantStyles = "bg-transparent hover:bg-surface-subtle text-ink-secondary border-transparent";
  } else if (variant === "destructive") {
    variantStyles = "bg-[#C62828] hover:bg-[#991B1B] text-white border-[#991B1B]";
  }

  return (
    <button className={`${base} ${sizeStyles} ${variantStyles} ${className}`} disabled={disabled} {...props}>
      {children}
    </button>
  );
}

/* ==========================================================================
   METRIC CARD / CELL — SWISS TECHNICAL GRID
   Dense, technical, tabular numbers, index tags (e.g., 01 // CRITICAL)
   ========================================================================== */
export function MetricCell({
  index,
  label,
  value,
  sublabel,
  trend,
  indicatorColor,
  className = "",
}: {
  index?: string;
  label: string;
  value: React.ReactNode;
  sublabel?: string;
  trend?: string;
  indicatorColor?: string;
  className?: string;
}) {
  const displaySublabel = sublabel || trend;
  return (
    <div className={`p-4 bg-surface border border-swiss-border relative flex flex-col justify-between ${className}`}>
      <div className="flex items-center justify-between text-xs text-ink-muted font-mono tracking-wider mb-2">
        <span className="flex items-center gap-1.5">
          {indicatorColor && (
            <span className="w-2 h-2 rounded-none inline-block" style={{ backgroundColor: indicatorColor }} />
          )}
          {index && <span className="opacity-60">{index} {"//"}</span>}
          <span className="uppercase">{label}</span>
        </span>
      </div>
      <div className="text-2xl font-display font-bold text-ink-primary tabular-nums tracking-tight">
        {value}
      </div>
      {displaySublabel && (
        <div className="text-[11px] font-mono text-ink-muted mt-1.5 pt-1.5 border-t border-swiss-border-subtle truncate">
          {displaySublabel}
        </div>
      )}
    </div>
  );
}

/* ==========================================================================
   PANEL HEADER — SWISS TECHNICAL GRID
   ========================================================================== */
export function PanelHeader({
  tag,
  index,
  title,
  subtitle,
  actions,
  className = "",
}: {
  tag?: string;
  index?: string;
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  className?: string;
}) {
  const displayTag = tag || index;
  return (
    <div className={`p-4 sm:p-5 bg-surface border border-swiss-border flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 ${className}`}>
      <div>
        <div className="flex items-center gap-2">
          {displayTag && (
            <span className="text-[10px] font-mono font-bold tracking-widest text-accent uppercase px-1.5 py-0.5 bg-accent-subtle border border-accent/20">
              {displayTag}
            </span>
          )}
          <h1 className="text-xl sm:text-2xl font-display font-bold text-ink-primary tracking-tight">
            {title}
          </h1>
        </div>
        {subtitle && (
          <p className="text-xs sm:text-sm font-sans text-ink-secondary mt-1 max-w-3xl">
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 w-full sm:w-auto">{actions}</div>}
    </div>
  );
}

/* ==========================================================================
   EVIDENCE VIEWER & COPY BOX — SWISS TECHNICAL GRID
   Monospace technical data with copy button and SHA-256 seal tag
   ========================================================================== */
export function EvidenceViewer({
  title,
  content,
  hash,
  className = "",
}: {
  title?: string;
  content: string;
  hash?: string;
  className?: string;
}) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`border border-swiss-border bg-surface-subtle overflow-hidden ${className}`}>
      <div className="px-3 py-1.5 bg-surface border-b border-swiss-border flex items-center justify-between text-[11px] font-mono text-ink-muted">
        <span className="uppercase font-semibold text-ink-primary tracking-wider">{title || "Raw Telemetry"}</span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 hover:text-ink-primary px-1.5 py-0.5 border border-transparent hover:border-swiss-border transition-colors"
          title="Copy contents"
        >
          {copied ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
          <span>{copied ? "COPIED" : "COPY"}</span>
        </button>
      </div>
      {hash && (
        <div className="px-3 py-1 bg-surface-subtle border-b border-swiss-border text-[10px] font-mono text-ink-secondary flex items-center gap-1.5">
          <span className="text-accent font-bold">SHA-256:</span>
          <span className="truncate">{hash}</span>
        </div>
      )}
      <pre className="p-3 text-xs font-mono text-ink-primary overflow-x-auto whitespace-pre-wrap break-all max-h-60">
        {content}
      </pre>
    </div>
  );
}
