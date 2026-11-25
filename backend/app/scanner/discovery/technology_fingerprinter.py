import re
from typing import Dict, List, Optional
from uuid import UUID

from shared.schemas.discovery import TechnologyObservationSchema


class AdvancedTechnologyFingerprinter:
    """Multi-signal passive web application technology fingerprinter.
    
    Correlates evidence across HTTP headers, cookies, HTML DOM patterns, script paths,
    and meta tags to distinguish confirmed indicators from inferred guesses with confidence scores.
    """

    # Confirmed Server Header Signatures
    SERVER_CONFIRMED = [
        (re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE), "Nginx", "web-server"),
        (re.compile(r"apache(?:/([\d.]+))?", re.IGNORECASE), "Apache HTTP Server", "web-server"),
        (re.compile(r"microsoft-iis(?:/([\d.]+))?", re.IGNORECASE), "Microsoft IIS", "web-server"),
        (re.compile(r"caddy(?:/([\d.]+))?", re.IGNORECASE), "Caddy", "web-server"),
        (re.compile(r"openresty(?:/([\d.]+))?", re.IGNORECASE), "OpenResty", "web-server"),
        (re.compile(r"gunicorn(?:/([\d.]+))?", re.IGNORECASE), "Gunicorn", "wsgi-server"),
        (re.compile(r"uvicorn", re.IGNORECASE), "Uvicorn", "asgi-server"),
        (re.compile(r"cloudflare", re.IGNORECASE), "Cloudflare", "cdn"),
    ]

    # Confirmed X-Powered-By Signatures
    POWERED_BY_CONFIRMED = [
        (re.compile(r"php(?:/([\d.]+))?", re.IGNORECASE), "PHP", "language"),
        (re.compile(r"asp\.net", re.IGNORECASE), "ASP.NET", "backend-framework"),
        (re.compile(r"next\.js(?:/([\d.]+))?", re.IGNORECASE), "Next.js", "frontend-framework"),
        (re.compile(r"express", re.IGNORECASE), "Express", "backend-framework"),
    ]

    # Additional Header Indicators
    HEADER_INDICATORS = [
        ("cf-ray", "Cloudflare", "cdn", 0.95, True),
        ("x-amz-cf-id", "Amazon CloudFront", "cdn", 0.95, True),
        ("x-drupal-cache", "Drupal", "cms", 0.95, True),
        ("x-generator", "Drupal", "cms", 0.90, True),
        ("x-varnish", "Varnish", "cache-server", 0.95, True),
        ("fastly-restarts", "Fastly", "cdn", 0.95, True),
        ("x-powered-by-plesk", "Plesk", "control-panel", 0.90, True),
    ]

    # Cookie Indicators
    COOKIE_INDICATORS = [
        (re.compile(r"PHPSESSID", re.IGNORECASE), "PHP", "language", 0.85, False),
        (re.compile(r"csrftoken", re.IGNORECASE), "Django", "backend-framework", 0.85, False),
        (re.compile(r"laravel_session", re.IGNORECASE), "Laravel", "backend-framework", 0.90, False),
        (re.compile(r"JSESSIONID", re.IGNORECASE), "Java Servlet", "application-server", 0.85, False),
        (re.compile(r"connect\.sid", re.IGNORECASE), "Express", "backend-framework", 0.85, False),
        (re.compile(r"ASP\.NET_SessionId", re.IGNORECASE), "ASP.NET", "backend-framework", 0.90, False),
    ]

    # HTML Generator & Meta Signatures (Confirmed)
    HTML_META_CONFIRMED = [
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)["\']', re.IGNORECASE), "WordPress", "cms"),
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!\s*([\d.]*)["\']', re.IGNORECASE), "Joomla", "cms"),
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]*)["\']', re.IGNORECASE), "Drupal", "cms"),
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost\s*([\d.]*)["\']', re.IGNORECASE), "Ghost", "cms"),
    ]

    # HTML / Script Inferred Indicators
    HTML_INFERRED = [
        (re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\']', re.IGNORECASE), "Next.js", "frontend-framework", 0.90),
        (re.compile(r'data-reactroot=', re.IGNORECASE), "React", "frontend-framework", 0.85),
        (re.compile(r'ng-version=', re.IGNORECASE), "Angular", "frontend-framework", 0.90),
        (re.compile(r'data-v-[a-f0-9]{8}', re.IGNORECASE), "Vue.js", "frontend-framework", 0.85),
        (re.compile(r'/wp-content/|/wp-includes/', re.IGNORECASE), "WordPress", "cms", 0.85),
        (re.compile(r'class=["\'][^"\']*bootstrap', re.IGNORECASE), "Bootstrap", "css-framework", 0.70),
        (re.compile(r'swagger-ui', re.IGNORECASE), "Swagger UI", "api-documentation", 0.90),
    ]

    @classmethod
    def fingerprint(
        cls,
        scan_id: UUID,
        headers: Dict[str, str],
        html_body: Optional[str] = None
    ) -> List[TechnologyObservationSchema]:
        """Passively analyzes HTTP headers, cookies, and HTML markup to detect technologies.
        
        Correlates multiple indicators and distinguishes confirmed from inferred technology signals.
        """
        observations: Dict[str, TechnologyObservationSchema] = {}

        def add_observation(
            name: str,
            category: str,
            version: Optional[str],
            confidence: float,
            source: str,
            evidence: str,
            is_confirmed: bool
        ):
            if name in observations:
                existing = observations[name]
                existing.indicators_count += 1
                # Boost confidence with multiple indicators
                existing.confidence = min(0.99, existing.confidence + 0.05)
                if version and not existing.version:
                    existing.version = version
                if is_confirmed:
                    existing.is_confirmed = True
                if evidence and existing.evidence:
                    if evidence not in existing.evidence:
                        existing.evidence += f" | {evidence}"
            else:
                observations[name] = TechnologyObservationSchema(
                    scan_id=scan_id,
                    technology_name=name,
                    category=category,
                    version=version,
                    confidence=confidence,
                    detection_source=source,
                    evidence=evidence,
                    is_confirmed=is_confirmed,
                    indicators_count=1
                )

        # 1. Analyze Server Header
        server = headers.get("server") or headers.get("Server")
        if server:
            for pattern, name, cat in cls.SERVER_CONFIRMED:
                m = pattern.search(server)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    add_observation(name, cat, ver, 0.95, "header:Server", f"Server: {server}", True)

        # 2. Analyze X-Powered-By Header
        powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
        if powered:
            for pattern, name, cat in cls.POWERED_BY_CONFIRMED:
                m = pattern.search(powered)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    add_observation(name, cat, ver, 0.95, "header:X-Powered-By", f"X-Powered-By: {powered}", True)

        # 3. Analyze Other Known Headers
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for hdr_name, tech_name, cat, conf, confirmed in cls.HEADER_INDICATORS:
            if hdr_name in headers_lower:
                val = headers_lower[hdr_name]
                add_observation(tech_name, cat, None, conf, f"header:{hdr_name}", f"{hdr_name}: {val}", confirmed)

        # 4. Analyze Set-Cookie Header
        cookie_header = headers.get("set-cookie") or headers.get("Set-Cookie")
        if cookie_header:
            for pattern, name, cat, conf, confirmed in cls.COOKIE_INDICATORS:
                if pattern.search(cookie_header):
                    add_observation(name, cat, None, conf, "header:Set-Cookie", f"Cookie pattern matched: {pattern.pattern}", confirmed)

        # 5. Analyze HTML Body
        if html_body and isinstance(html_body, str):
            # Confirmed meta generators
            for pattern, name, cat in cls.HTML_META_CONFIRMED:
                m = pattern.search(html_body)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    matched_snippet = m.group(0)[:80]
                    add_observation(name, cat, ver, 0.95, "html:meta[generator]", matched_snippet, True)

            # Inferred DOM markers
            for pattern, name, cat, conf in cls.HTML_INFERRED:
                if pattern.search(html_body):
                    add_observation(name, cat, None, conf, "html:dom_marker", f"DOM pattern: {pattern.pattern}", False)

        return list(observations.values())
