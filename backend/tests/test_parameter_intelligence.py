import pytest
from backend.app.scanner.discovery.parameter_intelligence import ParameterIntelligenceEngine
from shared.schemas.discovery import ParameterCategory, ParameterLocation


def test_parameter_classification():
    engine = ParameterIntelligenceEngine()

    cat_auth, conf_auth, sig_auth = engine.classify_parameter("api_key")
    assert cat_auth == ParameterCategory.AUTH
    assert conf_auth >= 0.90
    assert "Authentication" in sig_auth[0]

    cat_sess, _, _ = engine.classify_parameter("session_id")
    assert cat_sess == ParameterCategory.SESSION

    cat_redir, _, _ = engine.classify_parameter("redirect_url")
    assert cat_redir == ParameterCategory.REDIRECT

    cat_file, _, _ = engine.classify_parameter("filepath")
    assert cat_file == ParameterCategory.FILE

    cat_search, _, _ = engine.classify_parameter("query")
    assert cat_search == ParameterCategory.SEARCH

    cat_id, _, _ = engine.classify_parameter("user_id")
    assert cat_id == ParameterCategory.IDENTIFIER

    cat_pii, _, _ = engine.classify_parameter("credit_card")
    assert cat_pii == ParameterCategory.SENSITIVE

    cat_unk, conf_unk, _ = engine.classify_parameter("custom_foo_bar")
    assert cat_unk == ParameterCategory.UNKNOWN
    assert conf_unk == 0.50


def test_parameter_sanitization_redaction():
    engine = ParameterIntelligenceEngine()

    # Redact sensitive values
    assert engine.sanitize_value(ParameterCategory.AUTH, "super_secret_token_123") == "[REDACTED]"
    assert engine.sanitize_value(ParameterCategory.SESSION, "sess_abc123xyz") == "[REDACTED]"
    assert engine.sanitize_value(ParameterCategory.SENSITIVE, "4111-2222-3333-4444") == "[REDACTED]"

    # Non-sensitive value truncation
    safe_val = engine.sanitize_value(ParameterCategory.SEARCH, "normal search query")
    assert safe_val == "normal search query"


def test_extract_from_url_and_form():
    engine = ParameterIntelligenceEngine()

    url = "https://example.com/search?q=security&page=2&redirect_to=/home"
    params = engine.extract_from_url(url)
    assert len(params) == 3

    categories = {p.name: p.category for p in params}
    assert categories["q"] == ParameterCategory.SEARCH
    assert categories["page"] == ParameterCategory.PAGINATION
    assert categories["redirect_to"] == ParameterCategory.REDIRECT

    form_fields = [
        {"name": "username", "field_type": "text", "default_value": "admin"},
        {"name": "password", "field_type": "password", "default_value": "secret"}
    ]
    form_params = engine.extract_from_form_fields(form_fields, "https://example.com/login")
    assert len(form_params) == 2
    pwd_param = [p for p in form_params if p.name == "password"][0]
    assert pwd_param.category == ParameterCategory.AUTH
    assert pwd_param.sample_values_redacted == ["[REDACTED]"]
