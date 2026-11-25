from typing import Dict, List, Optional
from urllib.parse import urlparse

from shared.schemas.discovery import (
    AssetType,
    AssetIntelligenceSchema
)


class AssetInventoryManager:
    """Bounded asset inventory manager.
    
    Catalogs and tracks client assets (JavaScript bundles, CSS stylesheets, images, fonts,
    documents, and source maps) without downloading large binary payloads.
    Guarantees strict memory boundaries.
    """

    MAX_ASSETS = 2000

    ASSET_EXTENSIONS = {
        ".js": AssetType.JAVASCRIPT,
        ".mjs": AssetType.JAVASCRIPT,
        ".cjs": AssetType.JAVASCRIPT,
        ".css": AssetType.CSS,
        ".png": AssetType.IMAGE,
        ".jpg": AssetType.IMAGE,
        ".jpeg": AssetType.IMAGE,
        ".gif": AssetType.IMAGE,
        ".svg": AssetType.IMAGE,
        ".webp": AssetType.IMAGE,
        ".ico": AssetType.IMAGE,
        ".woff": AssetType.FONT,
        ".woff2": AssetType.FONT,
        ".ttf": AssetType.FONT,
        ".eot": AssetType.FONT,
        ".otf": AssetType.FONT,
        ".pdf": AssetType.DOCUMENT,
        ".doc": AssetType.DOCUMENT,
        ".docx": AssetType.DOCUMENT,
        ".xls": AssetType.DOCUMENT,
        ".xlsx": AssetType.DOCUMENT,
        ".zip": AssetType.DOCUMENT,
        ".tar": AssetType.DOCUMENT,
        ".gz": AssetType.DOCUMENT,
        ".map": AssetType.SOURCEMAP,
    }

    def __init__(self, max_assets: int = MAX_ASSETS):
        self.max_assets = max_assets
        # Map: url -> AssetIntelligenceSchema
        self._assets: Dict[str, AssetIntelligenceSchema] = {}

    @classmethod
    def categorize_asset(cls, url: str, content_type: Optional[str] = None) -> AssetType:
        """Determines the asset type from file extension or Content-Type header."""
        path = urlparse(url).path.lower()

        if path.endswith(".map") or "sourcemappingurl" in url.lower():
            return AssetType.SOURCEMAP

        for ext, atype in cls.ASSET_EXTENSIONS.items():
            if path.endswith(ext):
                return atype

        if content_type:
            ct = content_type.lower()
            if "javascript" in ct:
                return AssetType.JAVASCRIPT
            if "css" in ct:
                return AssetType.CSS
            if "image/" in ct:
                return AssetType.IMAGE
            if "font/" in ct or "application/font" in ct:
                return AssetType.FONT
            if "application/pdf" in ct or "application/zip" in ct:
                return AssetType.DOCUMENT

        return AssetType.OTHER

    def record_asset(
        self,
        url: str,
        content_type: Optional[str] = None,
        size_bytes: Optional[int] = None,
        discovery_source: str = "CRAWLER",
        in_scope: bool = True,
        associated_endpoint: Optional[str] = None
    ) -> Optional[AssetIntelligenceSchema]:
        """Records an asset in the bounded asset inventory."""
        clean_url = url.strip()
        if not clean_url:
            return None

        if clean_url in self._assets:
            existing = self._assets[clean_url]
            if content_type and not existing.mime_type:
                existing.mime_type = content_type
                existing.asset_type = self.categorize_asset(clean_url, content_type)
            if size_bytes is not None and existing.size_bytes is None:
                existing.size_bytes = size_bytes
            if associated_endpoint and associated_endpoint not in existing.associated_endpoints:
                if len(existing.associated_endpoints) < 20:
                    existing.associated_endpoints.append(associated_endpoint)
            return existing

        # Check bounds
        if len(self._assets) >= self.max_assets:
            return None

        asset_type = self.categorize_asset(clean_url, content_type)
        associated = [associated_endpoint] if associated_endpoint else []

        asset = AssetIntelligenceSchema(
            url=clean_url,
            asset_type=asset_type,
            mime_type=content_type,
            size_bytes=size_bytes,
            discovery_source=discovery_source,
            in_scope=in_scope,
            associated_endpoints=associated
        )
        self._assets[clean_url] = asset
        return asset

    def get_assets(self) -> List[AssetIntelligenceSchema]:
        """Returns all recorded assets."""
        return list(self._assets.values())

    def get_by_type(self, asset_type: AssetType) -> List[AssetIntelligenceSchema]:
        """Filters assets by asset type."""
        return [a for a in self._assets.values() if a.asset_type == asset_type]
