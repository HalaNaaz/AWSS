import json
import pytest
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

from shared.schemas.common import Severity, FindingStatus, ScanProfile, ScanStatus
from shared.schemas.finding import FindingResponse, EndpointSchema, EvidenceSchema
from shared.schemas.discovery import TechnologyObservationSchema
from shared.schemas.report import ReportFormat, SeveritySummarySchema, UnifiedScanReport
from backend.app.reporting.manager import ReportManager
from backend.app.reporting.json_report import JSONReportGenerator
from backend.app.reporting.markdown_report import MarkdownReportGenerator
from backend.app.reporting.html_report import HTMLReportGenerator
from backend.app.core.exceptions import ScanConfigurationError


@pytest.fixture
def sample_report() -> UnifiedScanReport:
    scan_id = uuid4()
    findings = [
        FindingResponse(
            id=uuid4(),
            scan_id=scan_id,
            title="Missing Content-Security-Policy",
            description="Content-Security-Policy header is missing from the response.",
            severity=Severity.MEDIUM,
            confidence=0.9,
            status=FindingStatus.SUSPECTED,
            cwe_id="CWE-693",
            cvss_score=5.4,
            remediation="Implement a strong Content-Security-Policy (CSP) header.",
            endpoint=EndpointSchema(url="https://example.com/app", method="GET"),
            evidence=EvidenceSchema(
                request="GET /app HTTP/1.1\r\nHost: example.com",
                response="HTTP/1.1 200 OK\r\nContent-Type: text/html",
                sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            created_at=datetime.now(timezone.utc),
        ),
        FindingResponse(
            id=uuid4(),
            scan_id=scan_id,
            title="Insecure Cookie without HttpOnly",
            description="Session cookie is missing HttpOnly flag.",
            severity=Severity.HIGH,
            confidence=0.85,
            status=FindingStatus.SUSPECTED,
            cwe_id="CWE-1004",
            cvss_score=7.1,
            remediation="Ensure all sensitive cookies specify the HttpOnly attribute.",
            endpoint=EndpointSchema(url="https://example.com/login", method="POST"),
            evidence=EvidenceSchema(
                request="POST /login HTTP/1.1\r\nHost: example.com",
                response="HTTP/1.1 200 OK\r\nSet-Cookie: session_id=xyz; Path=/; Secure",
                sha256_hash="f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb",
            ),
            created_at=datetime.now(timezone.utc),
        ),
    ]

    technologies = [
        TechnologyObservationSchema(
            scan_id=scan_id,
            technology_name="Nginx",
            category="Web Server",
            version="1.24.0",
            confidence=0.95,
            detection_source="Server Header",
        ),
        TechnologyObservationSchema(
            scan_id=scan_id,
            technology_name="Express",
            category="Web Framework",
            version="4.18.2",
            confidence=0.90,
            detection_source="X-Powered-By Header",
        ),
    ]

    return UnifiedScanReport(
        scan_id=scan_id,
        target_url="https://example.com",
        profile=ScanProfile.QUICK_ASSESSMENT,
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=12.45,
        urls_crawled=25,
        endpoints_discovered=18,
        forms_discovered=4,
        technologies=technologies,
        severity_summary=SeveritySummarySchema.from_findings(findings),
        findings=findings,
    )


def test_severity_summary_calculation(sample_report: UnifiedScanReport):
    summary = sample_report.severity_summary
    assert summary.total == 2
    assert summary.high == 1
    assert summary.medium == 1
    assert summary.critical == 0
    assert summary.low == 0
    assert summary.informational == 0


def test_json_report_generation(sample_report: UnifiedScanReport):
    generator = JSONReportGenerator()
    assert generator.format_name == ReportFormat.JSON
    assert generator.content_type.startswith("application/json")

    rendered = generator.generate(sample_report)
    data = json.loads(rendered)

    assert data["target_url"] == "https://example.com"
    assert data["profile"] == "QUICK_ASSESSMENT"
    assert data["status"] == "COMPLETED"
    assert data["severity_summary"]["high"] == 1
    assert data["severity_summary"]["medium"] == 1
    assert len(data["findings"]) == 2
    assert len(data["technologies"]) == 2


def test_markdown_report_generation(sample_report: UnifiedScanReport):
    generator = MarkdownReportGenerator()
    assert generator.format_name == ReportFormat.MARKDOWN
    assert generator.content_type == "text/markdown; charset=utf-8"

    rendered = generator.generate(sample_report)
    assert "# Ashlynx WebSec Scanner Assessment Report" in rendered
    assert "https://example.com" in rendered
    assert "Vulnerability Severity Breakdown" in rendered
    assert "Missing Content-Security-Policy" in rendered
    assert "CWE-693" in rendered
    assert "Insecure Cookie without HttpOnly" in rendered
    assert "CWE-1004" in rendered
    assert "Detected Technology Stack" in rendered
    assert "Nginx" in rendered


def test_html_report_generation_and_xss_sanitization():
    generator = HTMLReportGenerator()
    assert generator.format_name == ReportFormat.HTML
    assert generator.content_type == "text/html; charset=utf-8"

    scan_id = uuid4()
    # Malicious injection payloads inside findings and URLs
    xss_payload_title = '<script>alert("XSS-TITLE")</script>'
    xss_payload_desc = '<img src=x onerror=alert("XSS-DESC")>'
    xss_payload_remed = '"><svg onload=alert(1)>'
    xss_payload_url = 'https://example.com/test?q=<script>alert("XSS-URL")</script>'
    xss_payload_evidence = 'Raw Header: <script>evil()</script>'

    malicious_finding = FindingResponse(
        id=uuid4(),
        scan_id=scan_id,
        title=xss_payload_title,
        description=xss_payload_desc,
        severity=Severity.CRITICAL,
        confidence=0.99,
        status=FindingStatus.VERIFIED,
        cwe_id="CWE-79",
        cvss_score=9.8,
        remediation=xss_payload_remed,
        endpoint=EndpointSchema(url=xss_payload_url, method="GET"),
        evidence=EvidenceSchema(
            request="GET / HTTP/1.1",
            response=xss_payload_evidence,
            sha256_hash="112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        ),
        created_at=datetime.now(timezone.utc),
    )

    report = UnifiedScanReport(
        scan_id=scan_id,
        target_url='https://example.com/<script>alert("TARGET-XSS")</script>',
        profile=ScanProfile.FULL_ASSESSMENT,
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=5.0,
        urls_crawled=1,
        endpoints_discovered=1,
        forms_discovered=0,
        technologies=[
            TechnologyObservationSchema(
                scan_id=scan_id,
                technology_name='<b onmouseover=alert(1)>Apache</b>',
                category='Web Server',
                version='2.4',
                confidence=1.0,
                detection_source='HTML Comment',
            )
        ],
        severity_summary=SeveritySummarySchema.from_findings([malicious_finding]),
        findings=[malicious_finding],
    )

    html_content = generator.generate(report)

    # 1. Output must be valid HTML structure
    assert "<!DOCTYPE html>" in html_content
    assert "</html>" in html_content

    # 2. Strict XSS sanitization check: raw scripts and tags MUST NOT appear
    assert '<script>alert("XSS-TITLE")</script>' not in html_content
    assert '<img src=x onerror=' not in html_content
    assert '<svg onload=' not in html_content
    assert '<script>alert("XSS-URL")</script>' not in html_content
    assert '<script>alert("TARGET-XSS")</script>' not in html_content
    assert '<b onmouseover=' not in html_content

    # 3. Escaped entities must be present
    assert "&lt;script&gt;alert(&quot;XSS-TITLE&quot;)&lt;/script&gt;" in html_content
    assert "&lt;img src=x onerror=alert(&quot;XSS-DESC&quot;)&gt;" in html_content
    assert "&quot;&gt;&lt;svg onload=alert(1)&gt;" in html_content
    assert "&lt;b onmouseover=alert(1)&gt;Apache&lt;/b&gt;" in html_content


def test_report_manager_dispatch(sample_report: UnifiedScanReport):
    manager = ReportManager()

    json_out = manager.generate_report(sample_report, ReportFormat.JSON)
    assert json_out.startswith("{")

    html_out = manager.generate_report(sample_report, ReportFormat.HTML)
    assert "<!DOCTYPE html>" in html_out

    md_out = manager.generate_report(sample_report, ReportFormat.MARKDOWN)
    assert "# Ashlynx WebSec Scanner" in md_out


def test_report_manager_path_traversal_validation(tmp_path: Path):
    manager = ReportManager()

    # Rejects relative path traversal sequences
    with pytest.raises(ScanConfigurationError, match="Path traversal sequence"):
        manager.validate_and_resolve_output_path("../../etc/passwd")

    with pytest.raises(ScanConfigurationError, match="Path traversal sequence"):
        manager.validate_and_resolve_output_path(tmp_path / "sub" / ".." / ".." / "evil.html")

    # Rejects prohibited system paths
    with pytest.raises(ScanConfigurationError, match="protected system directory"):
        manager.validate_and_resolve_output_path("C:\\Windows\\System32\\report.html")

    # Valid relative/absolute path inside allowed root
    valid_file = tmp_path / "report.json"
    resolved = manager.validate_and_resolve_output_path(valid_file, allowed_root_dir=tmp_path)
    assert resolved == valid_file.resolve()

    # Outside allowed root directory
    outside_file = tmp_path.parent / "outside.html"
    with pytest.raises(ScanConfigurationError, match="outside allowed root directory"):
        manager.validate_and_resolve_output_path(outside_file, allowed_root_dir=tmp_path)


def test_report_manager_export_to_file(sample_report: UnifiedScanReport, tmp_path: Path):
    manager = ReportManager()
    output_file = tmp_path / "reports" / "assessment.html"

    result_path = manager.export_to_file(
        report=sample_report,
        format_type=ReportFormat.HTML,
        output_path=output_file,
    )

    assert result_path.exists()
    assert result_path.is_file()
    content = result_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Missing Content-Security-Policy" in content
