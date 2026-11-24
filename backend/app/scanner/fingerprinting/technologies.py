import re
from typing import List, Dict, Any, Optional
from uuid import UUID
from shared.schemas.discovery import TechnologyObservationSchema


class TechnologyFingerprinter:
    """Passive web application technology and framework fingerprinter."""

    # Server header fingerprints
    SERVER_SIGNATURES = [
        (re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE), "Nginx", "web-server"),
        (re.compile(r"apache(?:/([\d.]+))?", re.IGNORECASE), "Apache HTTP Server", "web-server"),
        (re.compile(r"cloudflare", re.IGNORECASE), "Cloudflare", "cdn"),
        (re.compile(r"microsoft-iis(?:/([\d.]+))?", re.IGNORECASE), "Microsoft IIS", "web-server"),
        (re.compile(r"caddy", re.IGNORECASE), "Caddy", "web-server"),
        (re.compile(r"openresty", re.IGNORECASE), "OpenResty", "web-server"),
        (re.compile(r"gunicorn(?:/([\d.]+))?", re.IGNORECASE), "Gunicorn", "wsgi-server"),
        (re.compile(r"uvicorn", re.IGNORECASE), "Uvicorn", "asgi-server"),
        (re.compile(r"express", re.IGNORECASE), "Express", "backend-framework"),
    ]

    # X-Powered-By header fingerprints
    POWERED_BY_SIGNATURES = [
        (re.compile(r"php(?:/([\d.]+))?", re.IGNORECASE), "PHP", "language"),
        (re.compile(r"asp\.net", re.IGNORECASE), "ASP.NET", "backend-framework"),
        (re.compile(r"next\.js", re.IGNORECASE), "Next.js", "frontend-framework"),
        (re.compile(r"express", re.IGNORECASE), "Express", "backend-framework"),
    ]

    # HTML body / meta / DOM signatures
    HTML_SIGNATURES = [
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)["\']', re.IGNORECASE), "WordPress", "cms"),
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!\s*([\d.]*)["\']', re.IGNORECASE), "Joomla", "cms"),
        (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]*)["\']', re.IGNORECASE), "Drupal", "cms"),
        (re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\']', re.IGNORECASE), "Next.js", "frontend-framework"),
        (re.compile(r'data-reactroot=', re.IGNORECASE), "React", "frontend-framework"),
        (re.compile(r'ng-version=', re.IGNORECASE), "Angular", "frontend-framework"),
        (re.compile(r'data-v-[a-f0-9]{8}', re.IGNORECASE), "Vue.js", "frontend-framework"),
        (re.compile(r'/wp-content/', re.IGNORECASE), "WordPress", "cms"),
    ]

    # Cookie signatures
    COOKIE_SIGNATURES = [
        (re.compile(r'PHPSESSID', re.IGNORECASE), "PHP", "language"),
        (re.compile(r'csrftoken', re.IGNORECASE), "Django", "backend-framework"),
        (re.compile(r'laravel_session', re.IGNORECASE), "Laravel", "backend-framework"),
        (re.compile(r'JSESSIONID', re.IGNORECASE), "Java Servlet", "application-server"),
        (re.compile(r'connect\.sid', re.IGNORECASE), "Express", "backend-framework"),
    ]

    @classmethod
    def _add_or_update(
        cls,
        observations: Dict[str, TechnologyObservationSchema],
        name: str,
        obs: TechnologyObservationSchema
    ):
        """Adds or updates an observation, preserving version info and preferring higher confidence."""
        if name in observations:
            existing = observations[name]
            if obs.version and not existing.version:
                existing.version = obs.version
            if obs.confidence > existing.confidence:
                existing.confidence = obs.confidence
                existing.detection_source = obs.detection_source
                existing.evidence = obs.evidence
        else:
            observations[name] = obs

    @classmethod
    def fingerprint(
        cls,
        scan_id: UUID,
        headers: Dict[str, str],
        html_body: Optional[str] = None
    ) -> List[TechnologyObservationSchema]:
        """Passively analyzes HTTP headers, cookies, and HTML markup to detect technologies."""
        observations: Dict[str, TechnologyObservationSchema] = {}

        # 1. Analyze Server Header
        server = headers.get("server") or headers.get("Server")
        if server:
            for pattern, name, cat in cls.SERVER_SIGNATURES:
                m = pattern.search(server)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    obs = TechnologyObservationSchema(
                        scan_id=scan_id,
                        technology_name=name,
                        category=cat,
                        version=ver,
                        confidence=0.9,
                        detection_source="header:Server",
                        evidence=f"Server: {server}"
                    )
                    cls._add_or_update(observations, name, obs)

        # 2. Analyze X-Powered-By Header
        powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
        if powered:
            for pattern, name, cat in cls.POWERED_BY_SIGNATURES:
                m = pattern.search(powered)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    obs = TechnologyObservationSchema(
                        scan_id=scan_id,
                        technology_name=name,
                        category=cat,
                        version=ver,
                        confidence=0.95,
                        detection_source="header:X-Powered-By",
                        evidence=f"X-Powered-By: {powered}"
                    )
                    cls._add_or_update(observations, name, obs)

        # 3. Analyze Cookies
        cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
        if cookie:
            for pattern, name, cat in cls.COOKIE_SIGNATURES:
                if pattern.search(cookie):
                    obs = TechnologyObservationSchema(
                        scan_id=scan_id,
                        technology_name=name,
                        category=cat,
                        confidence=0.85,
                        detection_source="header:Set-Cookie",
                        evidence=f"Matched cookie signature pattern: {pattern.pattern}"
                    )
                    cls._add_or_update(observations, name, obs)

        # 4. Analyze HTML Body
        if html_body:
            for pattern, name, cat in cls.HTML_SIGNATURES:
                m = pattern.search(html_body)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    obs = TechnologyObservationSchema(
                        scan_id=scan_id,
                        technology_name=name,
                        category=cat,
                        version=ver,
                        confidence=0.85,
                        detection_source="html:pattern",
                        evidence=f"Matched DOM markup pattern: {pattern.pattern}"
                    )
                    cls._add_or_update(observations, name, obs)

        return list(observations.values())
