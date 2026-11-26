# AWSS-CORE — PERFORMANCE & RELIABILITY REPORT

## 1. Bounded API & Scan Latency Measurements
Executed against live FastAPI backend (`127.0.0.1:8000`) and controlled local target (`127.0.0.1:8089`):

| Operation / Endpoint | Measured Latency | Outcome | Threshold |
|---|---:|---|---|
| Synchronous `SAFE_ACTIVE` Scan (`max_urls=20`) | `2.59s` | Completed (`91` findings) | `< 15.0s` (**PASS**) |
| `GET /api/v1/scans/` | `3.58ms` | HTTP 200 | `< 2000ms` (**PASS**) |
| `GET /api/v1/findings/?scan_id=...&page=1&page_size=20` | `8.24ms` | HTTP 200 | `< 2000ms` (**PASS**) |
| `GET /api/v1/discovery/{id}/graph` | `7.73ms` | HTTP 200 | `< 2000ms` (**PASS**) |
| `GET /api/v1/analytics/overview` | `5.42ms` | HTTP 200 | `< 2000ms` (**PASS**) |

## 2. Frontend Build & Reliability Controls
- **Next.js Production Bundle:** `87.1 kB` shared first-load JS across 10 static routes; route bundles range from `3.42 kB` (`/reports`) to `7.31 kB` (`/`).
- **Concurrency & Rate Limiting:** `AsyncHTTPClient` enforces `asyncio.Semaphore`, 5 MB response cap, manual redirect validation (`max_redirects=5`), and bounded exponential backoff on HTTP 429 / timeouts.
- **Cooperative Cancellation:** Verified via `test_cancel_scan_job` (`POST /api/v1/scans/{id}/cancel` transitions to `CANCELLED`).
