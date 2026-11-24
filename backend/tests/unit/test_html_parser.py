import pytest
from backend.app.scanner.crawler.parser import HTMLParser


def test_html_parser_links_and_meta():
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <title>Test Page</title>
        <meta name="generator" content="WordPress 6.4.2" />
        <link rel="canonical" href="https://example.com/canonical-page" />
        <link rel="stylesheet" href="/assets/style.css" />
        <script src="/static/bundle.js"></script>
      </head>
      <body>
        <a href="/about">About Us</a>
        <a href="https://example.com/contact">Contact</a>
        <a href="javascript:alert(1)">Invalid</a>
      </body>
    </html>
    """
    base_url = "https://example.com/home"
    parsed = HTMLParser.parse(html, base_url)

    assert parsed["canonical_url"] == "https://example.com/canonical-page"
    assert parsed["meta_tags"].get("generator") == "WordPress 6.4.2"
    assert "https://example.com/about" in parsed["links"]
    assert "https://example.com/contact" in parsed["links"]
    assert "https://example.com/assets/style.css" in parsed["stylesheets"]
    assert "https://example.com/static/bundle.js" in parsed["scripts"]


def test_html_parser_form_extraction():
    html = """
    <form action="/login.php" method="POST" enctype="multipart/form-data">
        <input type="text" name="username" value="guest" required />
        <input type="password" name="password" required />
        <input type="hidden" name="csrf_token" value="abc123token" />
        <select name="role">
            <option value="user">User</option>
            <option value="admin">Admin</option>
        </select>
        <textarea name="comment"></textarea>
        <button type="submit">Sign In</button>
    </form>
    """
    base_url = "https://example.com/app/"
    parsed = HTMLParser.parse(html, base_url)

    assert len(parsed["forms"]) == 1
    form = parsed["forms"][0]
    assert form.action == "https://example.com/login.php"
    assert form.method == "POST"
    assert form.enctype == "multipart/form-data"

    field_names = [f.name for f in form.fields]
    assert "username" in field_names
    assert "password" in field_names
    assert "csrf_token" in field_names
    assert "role" in field_names
    assert "comment" in field_names

    username_field = next(f for f in form.fields if f.name == "username")
    assert username_field.field_type == "text"
    assert username_field.default_value == "guest"
    assert username_field.is_required is True
