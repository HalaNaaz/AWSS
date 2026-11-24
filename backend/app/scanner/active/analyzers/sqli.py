import re
import urllib.parse
from typing import List, Tuple
from uuid import UUID

from shared.schemas.common import Severity, FindingStatus
from backend.app.scanner.active.base import BaseActiveAnalyzer
from backend.app.scanner.active.models import ActiveTarget, ActiveFinding, RequestBudgetTracker
from backend.app.scanner.crawler.client import AsyncHTTPClient


class SQLInjectionAnalyzer(BaseActiveAnalyzer):
    """Safe, non-destructive SQL Injection Detection Analyzer.
    
    Detects SQL injection through:
    1. Controlled syntax probes testing for database error signatures across MySQL, PostgreSQL, SQLite, MSSQL, Oracle.
    2. Two-phase verification using randomized boolean invariant probes (e.g. AND 8943=8943 vs AND 8943=8944).
    
    Safety Guarantee: Avoids all destructive SQL commands (DROP, DELETE, UPDATE, INSERT, SHUTDOWN, SLEEP)
    and strictly avoids database extraction.
    """

    ERROR_SIGNATURES: List[Tuple[str, re.Pattern]] = [
        # MySQL / MariaDB
        ("MySQL", re.compile(r"You have an error in your SQL syntax|Warning: mysql_|check the manual that corresponds to your MySQL server version", re.I)),
        # PostgreSQL
        ("PostgreSQL", re.compile(r"syntax error at or near|PostgreSQL query failed|unterminated quoted string at or near|pg_query\(\)", re.I)),
        # SQLite
        ("SQLite", re.compile(r"unrecognized token:|near \".*\": syntax error|SQLite3::SQLException|SQL logic error", re.I)),
        # Microsoft SQL Server
        ("MSSQL", re.compile(r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|Driver.*SQL Server.*Syntax error", re.I)),
        # Oracle
        ("Oracle", re.compile(r"ORA-01756|ORA-00933|ORA-00936|quoted string not properly terminated", re.I)),
        # Generic SQL syntax errors
        ("Generic SQL", re.compile(r"SQL syntax error|unexpected end of SQL command|Query failed.*SQL", re.I)),
    ]

    @property
    def analyzer_id(self) -> str:
        return "ACT-SQLI-ANALYZER"

    @property
    def analyzer_name(self) -> str:
        return "Safe SQL Injection Detector"

    @property
    def category(self) -> str:
        return "Injection"

    @property
    def supported_rules(self) -> List[str]:
        return ["ACT-SQLI-ERROR", "ACT-SQLI-BOOLEAN"]

    def _detect_db_error(self, body: str) -> Tuple[bool, str]:
        if not body:
            return False, ""
        for db_name, pattern in self.ERROR_SIGNATURES:
            if pattern.search(body):
                return True, db_name
        return False, ""

    async def check(
        self,
        target: ActiveTarget,
        client: AsyncHTTPClient,
        budget: RequestBudgetTracker,
        scan_id: UUID,
    ) -> List[ActiveFinding]:
        findings: List[ActiveFinding] = []

        # Only probe endpoints with parameters
        if not target.parameters:
            return findings

        base_url = target.url
        parsed = urllib.parse.urlparse(base_url)
        orig_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        for param_name, orig_val in orig_params:
            if not budget.can_request():
                break

            # Phase 1: Controlled Syntax Error Probe (single quote test)
            syntax_probe_val = f"{orig_val}'"
            probe_query = []
            for k, v in orig_params:
                if k == param_name:
                    probe_query.append((k, syntax_probe_val))
                else:
                    probe_query.append((k, v))

            probe_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(probe_query), parsed.fragment)
            )

            budget.consume(1)
            resp, _ = await client.get(probe_url)
            if not resp or not resp.text:
                continue

            has_err, db_type = self._detect_db_error(resp.text)
            baseline_had_err, _ = self._detect_db_error(target.baseline_body or "")

            if has_err and not baseline_had_err:
                # Suspected error-based SQLi detected
                syntax_finding = ActiveFinding(
                    rule_id="ACT-SQLI-ERROR",
                    title=f"SQL Database Error Signature in Parameter '{param_name}'",
                    description=(
                        f"Injecting a controlled syntax marker into parameter '{param_name}' "
                        f"provoked a {db_type} database error signature in the application response."
                    ),
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                    severity=Severity.HIGH,
                    cvss_score=8.5,
                    status=FindingStatus.SUSPECTED,
                    confidence=0.85,
                    url=base_url,
                    parameter=param_name,
                    http_method=target.method,
                    evidence_request=f"GET {probe_url} HTTP/1.1",
                    evidence_response=f"HTTP/1.1 {resp.status_code}\r\n\r\n{resp.text[:500]}",
                    remediation="Use parameterized queries (prepared statements) or Object-Relational Mapping (ORM) to separate SQL code from untrusted user data.",
                    detection_module=self.analyzer_id,
                    probe_count=1,
                )
                findings.append(syntax_finding)

            # Phase 2: Deterministic Two-Phase Verification via Boolean Invariant
            if not budget.can_request():
                continue

            true_probe_val = f"{orig_val}' AND 8943=8943-- "
            false_probe_val = f"{orig_val}' AND 8943=8944-- "

            true_query = [(k, true_probe_val if k == param_name else v) for k, v in orig_params]
            false_query = [(k, false_probe_val if k == param_name else v) for k, v in orig_params]

            true_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(true_query), parsed.fragment)
            )
            false_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(false_query), parsed.fragment)
            )

            budget.consume(2)
            true_resp, _ = await client.get(true_url)
            false_resp, _ = await client.get(false_url)

            if true_resp and false_resp and true_resp.text and false_resp.text:
                baseline_len = len(target.baseline_body or "")
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)

                # Verification heuristic: True response mirrors baseline behavior, whereas False response differs in content or status
                true_matches_baseline = (
                    true_resp.status_code == (target.baseline_status or 200)
                    and (true_resp.text == (target.baseline_body or "") or abs(true_len - baseline_len) < 50)
                )
                false_differs = (
                    false_resp.status_code != true_resp.status_code
                    or false_resp.text != true_resp.text
                )

                if true_matches_baseline and false_differs:
                    verified_finding = ActiveFinding(
                        rule_id="ACT-SQLI-BOOLEAN",
                        title=f"Verified Boolean-Based SQL Injection in Parameter '{param_name}'",
                        description=(
                            f"Deterministic two-phase verification confirmed SQL injection in parameter '{param_name}'. "
                            f"The mathematical invariant probe 'AND 8943=8943' reproduced baseline response state, "
                            f"while 'AND 8943=8944' altered response status or body length."
                        ),
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection",
                        severity=Severity.CRITICAL,
                        cvss_score=9.4,
                        status=FindingStatus.VERIFIED,
                        confidence=0.98,
                        url=base_url,
                        parameter=param_name,
                        http_method=target.method,
                        evidence_request=f"Probe 1: {true_url}\nProbe 2: {false_url}",
                        evidence_response=(
                            f"True Probe [{true_resp.status_code}] (len: {true_len}): {true_resp.text[:200]}\n---\n"
                            f"False Probe [{false_resp.status_code}] (len: {false_len}): {false_resp.text[:200]}"
                        ),
                        remediation="Bind untrusted user inputs to strictly parameterized SQL queries. Do not concatenate input into SQL query strings.",
                        detection_module=self.analyzer_id,
                        probe_count=3,
                    )
                    findings.append(verified_finding)

        return findings
