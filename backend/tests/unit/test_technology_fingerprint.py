from uuid import uuid4
from backend.app.scanner.fingerprinting.technologies import TechnologyFingerprinter


def test_technology_fingerprinting_headers():
    scan_id = uuid4()
    headers = {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.2.10",
        "Set-Cookie": "PHPSESSID=abcdef123456; path=/; HttpOnly"
    }
    techs = TechnologyFingerprinter.fingerprint(scan_id=scan_id, headers=headers)

    names = {t.technology_name: t for t in techs}
    assert "Nginx" in names
    assert names["Nginx"].version == "1.24.0"
    assert names["Nginx"].category == "web-server"

    assert "PHP" in names
    assert names["PHP"].version == "8.2.10"
    assert names["PHP"].category == "language"


def test_technology_fingerprinting_dom_and_meta():
    scan_id = uuid4()
    headers = {"Server": "cloudflare"}
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="generator" content="WordPress 6.4.2" />
        <script id="__NEXT_DATA__" type="application/json">{}</script>
      </head>
      <body>
        <div data-reactroot="">Content</div>
      </body>
    </html>
    """
    techs = TechnologyFingerprinter.fingerprint(scan_id=scan_id, headers=headers, html_body=html)

    names = {t.technology_name: t for t in techs}
    assert "Cloudflare" in names
    assert "WordPress" in names
    assert names["WordPress"].version == "6.4.2"
    assert "Next.js" in names
    assert "React" in names
