from security.url_analyzer import analyze_url_security
from security.url_parser import validate_and_normalize_url


def test_validate_and_normalize_url_accepts_public_domain():
    is_valid, normalized_url, error = validate_and_normalize_url("example.com")

    assert is_valid is True
    assert normalized_url == "https://example.com"
    assert error is None


def test_analyze_url_security_returns_safe_for_clean_url():
    analysis = analyze_url_security("https://example.com")

    assert analysis["success"] is True
    assert analysis["verdict"] == "SAFE"
    assert analysis["risk_score"] == 0
