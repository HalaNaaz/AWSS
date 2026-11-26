"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "./theme-provider";
import {
  LayoutDashboard,
  Radio,
  Crosshair,
  ShieldAlert,
  BarChart3,
  FileText,
  Sun,
  Moon,
  Menu,
  X,
  Target,
  ShieldCheck,
  Terminal,
} from "lucide-react";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { theme, toggleTheme } = useTheme();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { name: "Dashboard", href: "/", icon: LayoutDashboard },
    { name: "Attack Surface", href: "/attack-surface", icon: Radio },
    { name: "Scans", href: "/scans", icon: Crosshair },
    { name: "Targets", href: "/targets", icon: Target },
    { name: "Findings", href: "/findings", icon: ShieldAlert },
    { name: "Analytics", href: "/analytics", icon: BarChart3 },
    { name: "Reports", href: "/reports", icon: FileText },
  ];

  const currentNav = navItems.find((item) =>
    item.href === "/" ? pathname === "/" : pathname?.startsWith(item.href)
  );

  return (
    <div className="min-h-screen bg-canvas text-ink-primary flex flex-col font-sans">
      {/* ====================================================================
          TOP WORKSTATION BAR — Swiss Technical Grid Header
          ==================================================================== */}
      <header className="border-b border-swiss-border bg-surface sticky top-0 z-40">
        <div className="max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          {/* Brand & Edition */}
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-1.5 border border-swiss-border text-ink-secondary hover:text-ink-primary"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
            <Link href="/" className="flex items-center space-x-2.5">
              <div className="w-7 h-7 bg-accent text-white flex items-center justify-center font-display font-black text-sm tracking-tighter">
                A
              </div>
              <div className="flex items-baseline space-x-2">
                <span className="font-display font-extrabold tracking-tight text-ink-primary text-base">
                  ASHLYNX
                </span>
                <span className="text-[10px] text-accent font-mono font-bold tracking-widest px-1 py-0.2 border border-accent/30 bg-accent-subtle hidden sm:inline-block">
                  WEBSEC
                </span>
                <span className="text-[10px] text-ink-muted font-mono hidden xl:inline-block">
                  AWSS-CORE v2.0
                </span>
              </div>
            </Link>
          </div>

          {/* Desktop Navigation */}
          <nav aria-label="Primary Navigation" className="hidden lg:flex items-center space-x-0.5 xl:space-x-1 font-mono text-[11px] xl:text-xs">
            {navItems.map((item) => {
              const active =
                item.href === "/" ? pathname === "/" : pathname?.startsWith(item.href);
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`px-2 xl:px-3 py-1.5 border-b-2 uppercase tracking-wider whitespace-nowrap transition-colors ${
                    active
                      ? "border-accent text-ink-primary font-bold bg-surface-subtle"
                      : "border-transparent text-ink-secondary hover:text-ink-primary hover:border-swiss-border"
                  }`}
                >
                  {item.name}
                </Link>
              );
            })}
          </nav>

          {/* Status Indicators & Theme Toggle */}
          <div className="flex items-center space-x-2 xl:space-x-3 shrink-0">
            <div className="hidden sm:flex items-center space-x-2 text-[11px] font-mono text-ink-secondary sm:border-r border-swiss-border sm:pr-2 xl:pr-3">
              <span className="inline-flex items-center px-2 py-0.5 border border-[#6EE7B7] dark:border-[#065F46] bg-[#ECFDF5] dark:bg-[#092015] text-[#15803D] dark:text-[#4ADE80] font-semibold whitespace-nowrap">
                <span className="w-1.5 h-1.5 rounded-full bg-[#15803D] dark:bg-[#4ADE80] mr-1.5 animate-pulse"></span>
                Engine Ready
              </span>
              <span className="inline-flex items-center px-2 py-0.5 border border-swiss-border bg-surface-subtle text-ink-muted hidden xl:inline-flex whitespace-nowrap">
                <ShieldCheck size={12} className="mr-1 text-accent" />
                SCOPE LOCKED
              </span>
            </div>

            {/* Functional Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="p-1.5 border border-swiss-border bg-surface hover:bg-surface-subtle text-ink-secondary hover:text-ink-primary transition-colors flex items-center gap-1.5 text-xs font-mono"
              title={`Switch to ${theme === "light" ? "Dark" : "Light"} Theme`}
              aria-label="Toggle Theme"
            >
              {theme === "light" ? (
                <>
                  <Moon size={14} className="text-ink-primary" />
                  <span className="text-[10px] hidden xl:inline">DARK</span>
                </>
              ) : (
                <>
                  <Sun size={14} className="text-[#FBBF24]" />
                  <span className="text-[10px] hidden xl:inline">LIGHT</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <nav aria-label="Mobile Navigation" className="lg:hidden border-t border-swiss-border bg-surface px-4 py-3 space-y-1 font-mono text-xs">
            {navItems.map((item) => {
              const active =
                item.href === "/" ? pathname === "/" : pathname?.startsWith(item.href);
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`block px-3 py-2 border uppercase tracking-wider ${
                    active
                      ? "border-accent bg-accent-subtle text-accent font-bold"
                      : "border-transparent text-ink-secondary hover:bg-surface-subtle"
                  }`}
                >
                  {item.name}
                </Link>
              );
            })}
          </nav>
        )}
      </header>

      {/* Sub-Header / Workspace Context Strip */}
      <div className="border-b border-swiss-border bg-surface-subtle px-4 sm:px-6 lg:px-8 py-2 overflow-hidden">
        <div className="max-w-[1720px] mx-auto flex items-center justify-between gap-2 text-[11px] font-mono text-ink-muted min-w-0">
          <div className="flex items-center space-x-2 min-w-0 flex-1">
            <span className="text-accent font-bold whitespace-nowrap">{"WORKSTATION //"}</span>
            <span className="text-ink-primary uppercase font-bold whitespace-nowrap">{currentNav?.name || "OVERVIEW"}</span>
            <span className="text-ink-muted">/</span>
            <span className="text-ink-secondary truncate min-w-0">127.0.0.1:8089 [AUTHORIZED TEST FIXTURE]</span>
          </div>
          <div className="hidden sm:flex items-center space-x-3 tabular-nums shrink-0">
            <span>{"DAST PHASE 7 // ACTIVE"}</span>
            <span>CIDR: RFC1918_PINNED</span>
          </div>
        </div>
      </div>

      {/* Main Workstation Workspace */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 min-w-0">
        {children}
      </main>

      {/* Technical Footer */}
      <footer className="border-t border-swiss-border bg-surface px-4 sm:px-6 lg:px-8 py-3 text-xs font-mono text-ink-muted">
        <div className="max-w-[1720px] mx-auto flex flex-col sm:flex-row justify-between items-center gap-2 text-center sm:text-left">
          <div className="flex flex-wrap items-center justify-center sm:justify-start gap-x-3 gap-y-1">
            <span className="font-bold text-ink-primary">ASHLYNX WEBSEC SCANNER</span>
            <span className="hidden sm:inline">·</span>
            <span>PRECISION SWISS TECHNICAL GRID</span>
            <span className="hidden sm:inline">·</span>
            <span className="hidden md:inline">CONFIDENTIAL SECURITY WORKSTATION</span>
          </div>
          <div className="flex flex-wrap items-center justify-center sm:justify-end gap-x-3 gap-y-1 tabular-nums text-[11px]">
            <span>STRICT TWO-PHASE VERIFICATION</span>
            <span className="hidden sm:inline">·</span>
            <span>SHA-256 FORENSIC SEALS</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
