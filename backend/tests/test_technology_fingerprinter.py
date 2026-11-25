import pytest
from uuid import uuid4
from backend.app.scanner.discovery.technology_fingerprinter import AdvancedTechnologyFingerprinter


def test_technology_fingerprinting_confirmed_vs_inferred():
    scan_id = uuid4()
    headers = {
        "Server": "nginx/1.22.1",
        "X-Powered-By": "PHP/8.1.0",
        "Set-Cookie": "PHPSESSID=abcdef123456"
    }
    html = """
    <html>
      <head>
        <meta name="generator" content="WordPress 6.4.2" />
        <script id="__NEXT_DATA__">{}</script>
      </head>
      <body>
        <div data-reactroot="">Content</div>
      </body>
    </html>
    """

    techs = AdvancedTechnologyFingerprinter.fingerprint(
        scan_id=scan_id,
        headers=headers,
        html_body=html
    )

    tech_map = {t.technology_name: t for t in techs}

    # Nginx - Confirmed via Server header
    assert "Nginx" in tech_map
    assert tech_map["Nginx"].is_confirmed
    assert tech_map["Nginx"].version == "1.22.1"
    assert tech_map["Nginx"].confidence >= 0.95

    # PHP - Confirmed via X-Powered-By and cookie correlation
    assert "PHP" in tech_map
    assert tech_map["PHP"].version == "8.1.0"
    assert tech_map["PHP"].indicators_count >= 2

    # WordPress - Confirmed via Meta tag
    assert "WordPress" in tech_map
    assert tech_map["WordPress"].is_confirmed
    assert tech_map["WordPress"].version == "6.4.2"

    # React / Next.js - Inferred via DOM / Script markers
    assert "React" in tech_map
    assert not tech_map["React"].is_confirmed
    assert tech_map["React"].confidence <= 0.90
