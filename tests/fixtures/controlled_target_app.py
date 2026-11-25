"""
Controlled Local Test Target Application for Ashlynx WebSec Scanner Operational Validation.
Provides synthetic fixtures for Phase 2A/2B/3/4 verification:
- HTML pages, anchors, forms, query parameters
- JavaScript with embedded routes, WebSockets, API keys
- Assets: CSS, images
- REST API and OpenAPI specification
- robots.txt and sitemap.xml
- Passive security headers and cookies
"""

import sys
from typing import Optional
from fastapi import FastAPI, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
import uvicorn

app = FastAPI(title="Ashlynx Controlled Test Target", version="1.0.0")


# Custom middleware to inject synthetic headers and cookies for passive security testing
@app.middleware("http")
async def add_security_and_fingerprint_headers(request: Request, call_next):
    response = await call_next(request)
    # Technology fingerprinting triggers
    response.headers["Server"] = "nginx/1.18.0"
    response.headers["X-Powered-By"] = "Express"
    # Provide one security header, intentionally omit others (CSP, HSTS, XFO) to verify passive engine
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Set a session cookie missing the Secure attribute to test cookie analyzer
    if request.url.path == "/":
        response.set_cookie(
            key="test_session_id",
            value="sec_token_987654321",
            httponly=True,
            samesite="lax",
            path="/"
        )
    return response


@app.get("/", response_class=HTMLResponse)
async def root_index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Controlled Test Target - Home</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>Welcome to Ashlynx Target Application</h1>
    <nav>
        <a href="/about">About Us</a>
        <a href="/contact">Contact Support</a>
        <a href="/items?page=1&limit=10">Product Catalog</a>
        <a href="/search?q=test&filter=all">Search</a>
        <a href="/redirect?dest=/about">Redirect Link</a>
    </nav>
    <section>
        <h2>Account Login</h2>
        <form action="/login" method="POST">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <input type="hidden" name="csrf_token" value="synthetic_csrf_token_xyz">
            <button type="submit">Sign In</button>
        </form>
    </section>
    <footer>
        <img src="/static/logo.png" alt="Company Logo">
        <p>&copy; 2026 Controlled Target App</p>
    </footer>
    <script src="/static/app.js"></script>
</body>
</html>
"""


@app.get("/about", response_class=HTMLResponse)
async def about_page():
    return """<!DOCTYPE html>
<html>
<head><title>About Us</title></head>
<body>
    <h1>About Our System</h1>
    <p>This is a controlled test application for automated security scanning validation.</p>
    <a href="/team">Our Team</a>
    <a href="/">Back Home</a>
</body>
</html>
"""


@app.get("/team", response_class=HTMLResponse)
async def team_page():
    return """<!DOCTYPE html>
<html>
<head><title>Team</title></head>
<body>
    <h1>Engineering Team</h1>
    <p>DevSecOps validation team.</p>
    <a href="/">Home</a>
</body>
</html>
"""


@app.get("/contact", response_class=HTMLResponse)
async def contact_page():
    return """<!DOCTYPE html>
<html>
<head><title>Contact</title></head>
<body>
    <h1>Contact Us</h1>
    <p>Email: security@test-target.local</p>
    <a href="/">Home</a>
</body>
</html>
"""


@app.get("/items", response_class=HTMLResponse)
async def items_catalog(page: int = 1, limit: int = 10):
    return f"""<!DOCTYPE html>
<html>
<head><title>Items</title></head>
<body>
    <h1>Catalog Page {page} (Limit: {limit})</h1>
    <ul>
        <li>Item 1</li>
        <li>Item 2</li>
    </ul>
    <a href="/items?page={page + 1}&limit={limit}">Next Page</a>
</body>
</html>
"""


@app.get("/search", response_class=HTMLResponse)
async def search_endpoint(q: str = "", filter: str = "all"):
    return f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search Results for "{q}" (Filter: {filter})</h1>
    <p>No results found.</p>
</body>
</html>
"""


@app.post("/login", response_class=JSONResponse)
async def login_submit(request: Request):
    return {"status": "success", "message": "Authenticated"}


@app.get("/redirect")
async def safe_redirect(dest: str = "/about"):
    return RedirectResponse(url=dest, status_code=302)


@app.get("/static/app.js", response_class=Response)
async def static_js():
    js_code = """
// Client-side Application Intelligence Fixture
console.log("App script loaded.");

async function fetchUsers() {
    const res = await fetch('/api/v1/users');
    return await res.json();
}

async function fetchOrders(status) {
    const res = await fetch('/api/v1/orders?status=' + encodeURIComponent(status));
    return await res.json();
}

async function fetchAnalytics() {
    const res = await fetch('/api/v2/analytics');
    return await res.json();
}

function initWebSocket() {
    const ws = new WebSocket('wss://app.local/ws/notifications');
    ws.onmessage = (e) => console.log(e.data);
}

const API_KEY_SAMPLE = "key_live_998877665544";
"""
    return Response(content=js_code, media_type="application/javascript")


@app.get("/static/style.css", response_class=Response)
async def static_css():
    css = "body { font-family: sans-serif; background: #fafafa; }"
    return Response(content=css, media_type="text/css")


@app.get("/static/logo.png", response_class=Response)
async def static_logo():
    # 1x1 transparent PNG
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    return Response(content=png_bytes, media_type="image/png")


@app.get("/api/v1/users", response_class=JSONResponse)
async def api_get_users():
    return {
        "status": "success",
        "data": [
            {"id": 1, "username": "admin", "role": "administrator"},
            {"id": 2, "username": "analyst", "role": "security"}
        ]
    }


@app.get("/api/v1/orders", response_class=JSONResponse)
async def api_get_orders(status: str = "active"):
    return {
        "status": "success",
        "filter": status,
        "orders": []
    }


@app.get("/api/v2/analytics", response_class=JSONResponse)
async def api_get_analytics():
    return {"metrics": {"scans_executed": 42}}


@app.get("/openapi.json", response_class=JSONResponse)
async def openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Target App API",
            "version": "1.0.0"
        },
        "paths": {
            "/api/v1/users": {
                "get": {
                    "summary": "List all users",
                    "responses": {"200": {"description": "User list"}}
                }
            },
            "/api/v1/orders": {
                "get": {
                    "summary": "List orders with status filter",
                    "parameters": [
                        {
                            "name": "status",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {"200": {"description": "Order list"}}
                }
            }
        }
    }


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    return """User-agent: *
Disallow: /admin/
Disallow: /private/
Sitemap: http://127.0.0.1:8089/sitemap.xml
"""


@app.get("/sitemap.xml", response_class=Response)
async def sitemap_xml():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>http://127.0.0.1:8089/</loc>
    </url>
    <url>
        <loc>http://127.0.0.1:8089/about</loc>
    </url>
    <url>
        <loc>http://127.0.0.1:8089/contact</loc>
    </url>
</urlset>"""
    return Response(content=xml, media_type="application/xml")


if __name__ == "__main__":
    port = 8089
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    print(f"Starting Controlled Local Test Target on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
