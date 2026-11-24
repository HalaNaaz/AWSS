import re
import xml.etree.ElementTree as ET
from typing import List, Set, Tuple
from urllib.parse import urljoin
from backend.app.scanner.crawler.client import AsyncHTTPClient
from backend.app.scanner.crawler.normalizer import URLNormalizer
from backend.app.scanner.scope.scope_gate import ScopeGate


class RobotsSitemapDiscovery:
    """Discovers paths and endpoints from /robots.txt and /sitemap.xml files."""

    def __init__(self, base_url: str, client: AsyncHTTPClient, scope_gate: ScopeGate):
        self.base_url = base_url
        self.client = client
        self.scope_gate = scope_gate

    async def discover_robots(self) -> Tuple[Set[str], List[str]]:
        """Fetches /robots.txt, extracts disallowed/allowed paths and sitemap references.
        
        Returns:
            Tuple of (discovered_urls_set, sitemap_urls_list)
        """
        discovered_urls: Set[str] = set()
        sitemaps: List[str] = []

        robots_url = urljoin(self.base_url, "/robots.txt")
        resp, err = await self.client.get(robots_url)
        if not resp or resp.status_code != 200 or not resp.text:
            return discovered_urls, sitemaps

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check Sitemap directive
            if re.match(r"^sitemap:\s*", line, re.IGNORECASE):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    sm_url = parts[1].strip()
                    if URLNormalizer.is_valid_url(sm_url):
                        sitemaps.append(sm_url)
                continue

            # Check Disallow / Allow directives
            match = re.match(r"^(?:disallow|allow):\s*(\S+)", line, re.IGNORECASE)
            if match:
                path = match.group(1).strip()
                if path and path != "/":
                    resolved = URLNormalizer.normalize_url(path, self.base_url)
                    if resolved and self.scope_gate.validate_url_in_scope(resolved):
                        discovered_urls.add(resolved)

        return discovered_urls, sitemaps

    async def discover_sitemap(self, sitemap_url: str, depth: int = 0) -> Set[str]:
        """Parses sitemap.xml or sitemap index files recursively up to depth 2.
        
        Returns:
            Set of discovered, in-scope, normalized URLs.
        """
        discovered: Set[str] = set()
        if depth > 2:
            return discovered

        resp, err = await self.client.get(sitemap_url)
        if not resp or resp.status_code != 200 or not resp.text:
            return discovered

        try:
            # Strip XML namespace for clean tag traversal
            xml_text = re.sub(r'\sxmlns="[^"]+"', '', resp.text, count=1)
            root = ET.fromstring(xml_text)

            # Check if this is a Sitemap Index (<sitemapindex><sitemap><loc>...</loc>)
            if "sitemapindex" in root.tag.lower():
                for loc in root.findall(".//sitemap/loc"):
                    if loc.text:
                        sub_sitemap = loc.text.strip()
                        if self.scope_gate.validate_url_in_scope(sub_sitemap):
                            sub_urls = await self.discover_sitemap(sub_sitemap, depth + 1)
                            discovered.update(sub_urls)

            # Standard Urlset (<urlset><url><loc>...</loc>)
            for loc in root.findall(".//url/loc"):
                if loc.text:
                    url_str = loc.text.strip()
                    norm_url = URLNormalizer.normalize_url(url_str)
                    if norm_url and self.scope_gate.validate_url_in_scope(norm_url):
                        discovered.add(norm_url)

        except Exception:
            pass

        return discovered
