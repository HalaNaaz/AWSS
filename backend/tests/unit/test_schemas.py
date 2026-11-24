from uuid import uuid4
from shared.schemas.common import Severity, FindingStatus
from shared.schemas.finding import FindingBase, FindingResponse, EndpointSchema, EvidenceSchema
from shared.schemas.scan import ScanJobCreate, ScanProfile


def test_scan_job_schema_defaults():
    target_id = uuid4()
    job = ScanJobCreate(target_id=target_id)
    assert job.profile == ScanProfile.QUICK_ASSESSMENT
    assert job.max_crawl_depth == 3
    assert job.concurrency == 5


def test_finding_schema_serialization():
    scan_id = uuid4()
    finding = FindingBase(
        title="Reflected Cross-Site Scripting in search parameter",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        cvss_score=7.5,
        status=FindingStatus.VERIFIED,
        confidence=1.0,
        remediation="Ensure all user-controlled inputs are contextually encoded."
    )
    assert finding.severity == Severity.HIGH
    assert finding.cvss_score == 7.5
    assert finding.status == FindingStatus.VERIFIED
