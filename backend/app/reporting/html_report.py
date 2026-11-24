import html
from typing import List
from shared.schemas.report import ReportFormat, UnifiedScanReport
from shared.schemas.common import Severity
from backend.app.reporting.base import BaseReportGenerator


class HTMLReportGenerator(BaseReportGenerator):
    """Generates self-contained, responsive, secure HTML security assessment reports.
    
    STRICT SECURITY INVARIANT: All dynamic variables are strictly escaped using html.escape()
    to eliminate any stored XSS or HTML injection vector from scanned application content.
    """

    @property
    def format_name(self) -> ReportFormat:
        return ReportFormat.HTML

    @property
    def content_type(self) -> str:
        return "text/html; charset=utf-8"

    def _badge_color(self, severity: Severity) -> str:
        if severity == Severity.CRITICAL:
            return "#ef4444"
        elif severity == Severity.HIGH:
            return "#f97316"
        elif severity == Severity.MEDIUM:
            return "#eab308"
        elif severity == Severity.LOW:
            return "#3b82f6"
        return "#64748b"

    def generate(self, report: UnifiedScanReport) -> str:
        s = report.severity_summary
        esc = lambda val: html.escape(str(val if val is not None else ""), quote=True)

        findings_html = []
        if not report.findings:
            findings_html.append("""
            <div class="empty-state">
                <div class="icon">✓</div>
                <h3>No Security Vulnerabilities Identified</h3>
                <p>The automated assessment completed without flagging any configuration defects or security anomalies.</p>
            </div>
            """)
        else:
            for idx, f in enumerate(report.findings, start=1):
                sev_color = self._badge_color(f.severity)
                evidence_block = ""
                if f.evidence:
                    evidence_block = f"""
                    <div class="evidence-box">
                        <div class="evidence-header">
                            <span>Cryptographic Evidence (Redacted)</span>
                            <span class="sha-seal">SHA-256: {esc(f.evidence.sha256_hash)}</span>
                        </div>
                        <pre class="evidence-code"><code>{esc(f.evidence.response)}</code></pre>
                    </div>
                    """

                remediation_block = ""
                if f.remediation:
                    remediation_block = f"""
                    <div class="remediation-box">
                        <h4>Remediation Guidance</h4>
                        <p>{esc(f.remediation)}</p>
                    </div>
                    """

                param_info = f" <span class='meta-tag'>Param: {esc(f.endpoint.parameter)}</span>" if f.endpoint.parameter else ""

                findings_html.append(f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <div class="finding-title-group">
                            <span class="badge" style="background-color: {sev_color};">{esc(f.severity.value)}</span>
                            <h3 class="finding-title">{idx}. {esc(f.title)}</h3>
                        </div>
                        <div class="cvss-pill">CVSS {f.cvss_score:.1f}</div>
                    </div>
                    <div class="finding-meta">
                        <span class="meta-tag"><strong>URL:</strong> {esc(f.endpoint.url)}</span>
                        <span class="meta-tag"><strong>Method:</strong> {esc(f.endpoint.method)}</span>
                        {param_info}
                        <span class="meta-tag"><strong>CWE:</strong> {esc(f.cwe_id)}</span>
                        <span class="meta-tag"><strong>Status:</strong> {esc(f.status.value)}</span>
                        <span class="meta-tag"><strong>Confidence:</strong> {int(f.confidence * 100)}%</span>
                    </div>
                    <div class="finding-body">
                        <p>{esc(f.description)}</p>
                    </div>
                    {remediation_block}
                    {evidence_block}
                </div>
                """)

        tech_rows = []
        for t in report.technologies:
            tech_rows.append(f"""
            <tr>
                <td><strong>{esc(t.technology_name)}</strong></td>
                <td><span class="category-tag">{esc(t.category)}</span></td>
                <td>{esc(t.version or '-')}</td>
                <td>{int(t.confidence * 100)}%</td>
                <td><code>{esc(t.detection_source)}</code></td>
            </tr>
            """)

        tech_section = ""
        if report.technologies:
            tech_section = f"""
            <section class="section">
                <h2>2. Discovered Technology Stack</h2>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Technology</th>
                                <th>Category</th>
                                <th>Version</th>
                                <th>Confidence</th>
                                <th>Detection Source</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(tech_rows)}
                        </tbody>
                    </table>
                </div>
            </section>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ashlynx WebSec Report - {esc(report.target_url)}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #131b2e;
            --bg-card: #1a233a;
            --border: #263352;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header.report-header {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, #1e293b 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .brand {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--accent-cyan);
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        h1.title {{
            font-size: 1.85rem;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 1rem;
        }}
        .header-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }}
        .header-item {{
            font-size: 0.85rem;
        }}
        .header-item span.label {{
            color: var(--text-secondary);
            display: block;
            margin-bottom: 0.25rem;
        }}
        .header-item span.value {{
            font-weight: 600;
            color: var(--text-primary);
            word-break: break-all;
        }}
        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        h2 {{
            font-size: 1.35rem;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-bottom: 1.25rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }}
        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem 1rem;
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 0.25rem;
        }}
        .summary-card .card-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 1px;
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        .data-table th, .data-table td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        .data-table th {{
            background: var(--bg-card);
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .data-table tbody tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            margin-bottom: 0.75rem;
        }}
        .finding-title-group {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}
        .finding-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 800;
            color: #ffffff;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .cvss-pill {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            padding: 0.25rem 0.6rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--text-secondary);
            white-space: nowrap;
        }}
        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .meta-tag {{
            background: var(--bg-secondary);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}
        .finding-body {{
            font-size: 0.9rem;
            color: #cbd5e1;
            margin-bottom: 1rem;
        }}
        .remediation-box {{
            background: rgba(6, 182, 212, 0.05);
            border-left: 3px solid var(--accent-cyan);
            padding: 0.75rem 1rem;
            border-radius: 0 4px 4px 0;
            margin-bottom: 1rem;
        }}
        .remediation-box h4 {{
            font-size: 0.8rem;
            color: var(--accent-cyan);
            margin-bottom: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .remediation-box p {{
            font-size: 0.85rem;
            color: #cbd5e1;
        }}
        .evidence-box {{
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            overflow: hidden;
            margin-top: 1rem;
        }}
        .evidence-header {{
            background: #1e293b;
            padding: 0.4rem 0.75rem;
            font-size: 0.75rem;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .evidence-code {{
            padding: 0.75rem 1rem;
            font-family: "JetBrains Mono", Consolas, monospace;
            font-size: 0.8rem;
            color: #e2e8f0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .empty-state {{
            text-align: center;
            padding: 3rem 1rem;
        }}
        .empty-state .icon {{
            font-size: 3rem;
            color: #10b981;
            margin-bottom: 1rem;
        }}
        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.8rem;
            margin-top: 3rem;
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
        }}
        @media print {{
            body {{ background: #ffffff; color: #000000; }}
            .section, header.report-header, .finding-card {{ border: 1px solid #cccccc; background: #ffffff; color: #000000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <div class="brand">Ashlynx WebSec Scanner | Assessment Report</div>
            <h1 class="title">{esc(report.target_url)}</h1>
            <div class="header-grid">
                <div class="header-item">
                    <span class="label">Scan Job ID</span>
                    <span class="value">{esc(report.scan_id)}</span>
                </div>
                <div class="header-item">
                    <span class="label">Profile</span>
                    <span class="value">{esc(report.profile.value)}</span>
                </div>
                <div class="header-item">
                    <span class="label">Status</span>
                    <span class="value">{esc(report.status.value)}</span>
                </div>
                <div class="header-item">
                    <span class="label">Scan Date</span>
                    <span class="value">{esc(report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}</span>
                </div>
                <div class="header-item">
                    <span class="label">Execution Duration</span>
                    <span class="value">{report.duration_seconds} seconds</span>
                </div>
                <div class="header-item">
                    <span class="label">Recon Scope</span>
                    <span class="value">{report.urls_crawled} URLs / {report.endpoints_discovered} Endpoints</span>
                </div>
            </div>
        </header>

        <section class="section">
            <h2>1. Executive Risk Summary</h2>
            <p>
                Automated security assessment conducted on <strong>{esc(report.target_url)}</strong>. 
                A total of <strong>{s.total}</strong> security observations and misconfigurations were identified.
            </p>
            <div class="summary-grid">
                <div class="summary-card" style="border-top: 3px solid var(--critical);">
                    <div class="count" style="color: var(--critical);">{s.critical}</div>
                    <div class="card-label" style="color: var(--critical);">Critical</div>
                </div>
                <div class="summary-card" style="border-top: 3px solid var(--high);">
                    <div class="count" style="color: var(--high);">{s.high}</div>
                    <div class="card-label" style="color: var(--high);">High</div>
                </div>
                <div class="summary-card" style="border-top: 3px solid var(--medium);">
                    <div class="count" style="color: var(--medium);">{s.medium}</div>
                    <div class="card-label" style="color: var(--medium);">Medium</div>
                </div>
                <div class="summary-card" style="border-top: 3px solid var(--low);">
                    <div class="count" style="color: var(--low);">{s.low}</div>
                    <div class="card-label" style="color: var(--low);">Low</div>
                </div>
                <div class="summary-card" style="border-top: 3px solid var(--info);">
                    <div class="count" style="color: var(--info);">{s.informational}</div>
                    <div class="card-label" style="color: var(--info);">Info</div>
                </div>
            </div>
        </section>

        {tech_section}

        <section class="section">
            <h2>3. Vulnerabilities & Remediation</h2>
            {"".join(findings_html)}
        </section>

        <footer>
            Generated by <strong>Ashlynx WebSec Scanner</strong> — Enterprise Application Security Assessment Platform
        </footer>
    </div>
</body>
</html>
"""
        return html_template
