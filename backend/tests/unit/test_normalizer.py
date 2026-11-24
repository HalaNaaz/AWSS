import pytest
from backend.app.scanner.crawler.normalizer import URLNormalizer
from shared.schemas.discovery import EndpointCategory


def test_url_normalizer_validity():
    assert URLNormalizer.is_valid_url("https://example.com") is True
    assert URLNormalizer.is_valid_url("http://sub.example.com/path?a=1") is True
    assert URLNormalizer.is_valid_url("ftp://example.com") is False
    assert URLNormalizer.is_valid_url("javascript:alert(1)") is False
    assert URLNormalizer.is_valid_url("") is False
    assert URLNormalizer.is_valid_url("not-a-url") is False


def test_url_normalizer_relative_resolution():
    base = "https://app.example.com/dashboard/index.html"
    assert URLNormalizer.normalize_url("users", base) == "https://app.example.com/dashboard/users"
    assert URLNormalizer.normalize_url("/api/v1/data", base) == "https://app.example.com/api/v1/data"
    assert URLNormalizer.normalize_url("../settings", base) == "https://app.example.com/settings"


def test_url_normalizer_port_and_fragment_removal():
    assert URLNormalizer.normalize_url("https://example.com:443/page#section1") == "https://example.com/page"
    assert URLNormalizer.normalize_url("http://example.com:80/index#anchor") == "http://example.com/index"
    assert URLNormalizer.normalize_url("https://example.com:8443/custom") == "https://example.com:8443/custom"


def test_url_normalizer_deterministic_query_sorting():
    url1 = "https://example.com/search?b=2&a=1&c=3"
    url2 = "https://example.com/search?c=3&b=2&a=1"
    assert URLNormalizer.normalize_url(url1) == "https://example.com/search?a=1&b=2&c=3"
    assert URLNormalizer.normalize_url(url1) == URLNormalizer.normalize_url(url2)


def test_url_normalizer_path_collapse():
    assert URLNormalizer.normalize_url("https://example.com//api///v1////users") == "https://example.com/api/v1/users"


def test_url_normalizer_prohibited_schemes():
    base = "https://example.com"
    assert URLNormalizer.normalize_url("javascript:void(0)", base) is None
    assert URLNormalizer.normalize_url("mailto:security@example.com", base) is None
    assert URLNormalizer.normalize_url("data:text/html,<h1>Test</h1>", base) is None
    assert URLNormalizer.normalize_url("tel:+1234567890", base) is None


def test_url_normalizer_destructive_urls():
    assert URLNormalizer.is_destructive_url("https://example.com/logout") is True
    assert URLNormalizer.is_destructive_url("https://example.com/account/signout") is True
    assert URLNormalizer.is_destructive_url("https://example.com/users/delete") is True
    assert URLNormalizer.is_destructive_url("https://example.com/dashboard") is False


def test_url_normalizer_endpoint_classification():
    assert URLNormalizer.classify_endpoint("https://example.com/app.js") == EndpointCategory.JAVASCRIPT
    assert URLNormalizer.classify_endpoint("https://example.com/styles.css") == EndpointCategory.CSS
    assert URLNormalizer.classify_endpoint("https://example.com/logo.png") == EndpointCategory.IMAGE
    assert URLNormalizer.classify_endpoint("https://example.com/report.pdf") == EndpointCategory.DOCUMENT
    assert URLNormalizer.classify_endpoint("https://example.com/api/v1/users") == EndpointCategory.API
    assert URLNormalizer.classify_endpoint("https://example.com/graphql") == EndpointCategory.API
    assert URLNormalizer.classify_endpoint("https://example.com/home", content_type="text/html") == EndpointCategory.PAGE
    assert URLNormalizer.classify_endpoint("https://example.com/feed", content_type="application/json") == EndpointCategory.API
