import pytest
from backend.app.scanner.discovery.asset_inventory import AssetInventoryManager
from shared.schemas.discovery import AssetType


def test_asset_categorization():
    manager = AssetInventoryManager(max_assets=100)

    assert manager.categorize_asset("https://example.com/app.min.js") == AssetType.JAVASCRIPT
    assert manager.categorize_asset("https://example.com/theme.css") == AssetType.CSS
    assert manager.categorize_asset("https://example.com/icon.svg") == AssetType.IMAGE
    assert manager.categorize_asset("https://example.com/font.woff2") == AssetType.FONT
    assert manager.categorize_asset("https://example.com/whitepaper.pdf") == AssetType.DOCUMENT
    assert manager.categorize_asset("https://example.com/app.js.map") == AssetType.SOURCEMAP


def test_asset_inventory_bounded_limit():
    manager = AssetInventoryManager(max_assets=5)

    for i in range(10):
        manager.record_asset(f"https://example.com/script_{i}.js", content_type="application/javascript")

    # Should never exceed bounded limit
    assert len(manager.get_assets()) == 5


def test_asset_recording_and_endpoint_association():
    manager = AssetInventoryManager(max_assets=50)

    a1 = manager.record_asset(
        url="https://example.com/static/bundle.js",
        content_type="application/javascript",
        size_bytes=10240,
        associated_endpoint="https://example.com/dashboard"
    )
    assert a1 is not None
    assert a1.size_bytes == 10240
    assert "https://example.com/dashboard" in a1.associated_endpoints

    # Associate another endpoint
    manager.record_asset(
        url="https://example.com/static/bundle.js",
        associated_endpoint="https://example.com/settings"
    )
    assert len(manager.get_assets()) == 1
    assert len(manager.get_assets()[0].associated_endpoints) == 2
