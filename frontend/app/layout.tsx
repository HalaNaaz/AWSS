import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Ashlynx WebSec Scanner | Enterprise DAST Dashboard",
  description: "Automated DAST & Web Vulnerability Assessment Platform by AshlynxCyber",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#090d16] text-slate-100 antialiased">
        <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-white shadow-lg shadow-cyan-500/20">
                A
              </div>
              <div>
                <span className="font-bold tracking-tight text-white text-lg">ASHLYNX</span>
                <span className="text-xs text-cyan-400 font-mono ml-2 px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50">WEBSEC</span>
              </div>
            </div>
            <nav className="flex items-center space-x-6 text-sm font-medium text-slate-400">
              <a href="/" className="text-cyan-400 hover:text-cyan-300">Dashboard</a>
              <a href="/scans" className="hover:text-slate-200">Scans</a>
              <a href="/targets" className="hover:text-slate-200">Targets</a>
              <a href="/findings" className="hover:text-slate-200">Findings</a>
              <a href="/reports" className="hover:text-slate-200">Reports</a>
            </nav>
            <div className="flex items-center space-x-3">
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span>
                Engine Ready
              </span>
            </div>
          </div>
        </header>
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
