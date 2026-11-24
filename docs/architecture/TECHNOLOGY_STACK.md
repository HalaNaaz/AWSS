# Technology Stack Specification & Evaluation

**Document Identifier:** TECH-WSS-2026-V1.0  
**Parent Specification:** Master PRD (`PRD-WSS-2026-V2.0-FINAL`)

---

## 1. Approved Technology Selections

| Subsystem | Approved Technology | Version | Justification & Capabilities |
| :--- | :--- | :--- | :--- |
| **Backend Core & Engine** | Python | 3.11+ | Native asynchronous I/O (`asyncio`), mature security research ecosystem, rich parsing libraries. |
| **API Gateway Framework** | FastAPI | 0.115+ | High-performance asynchronous ASGI, automated OpenAPI 3.1 generation, native Pydantic v2 validation. |
| **Relational Database** | PostgreSQL | 16+ | ACID compliance, JSONB evidence storage, native Row-Level Security (RLS) for multi-tenancy. |
| **Task Queue & Cache** | Redis | 7+ | Low-latency in-memory queueing, pub/sub for real-time finding feeds, worker heartbeat leasing. |
| **Async HTTP Client** | HTTPX | 0.27+ | Full async/await support, connection pooling, custom transport hooks for socket-level IP pinning. |
| **HTML / DOM Parsing** | BeautifulSoup4 / lxml | 4.12+ | Robust parsing of malformed HTML, form extraction, and anchor tag discovery. |
| **CLI Framework** | Typer & Rich | Latest | Clean subcommands, automated shell completion, elegant color-coded tables, sub-500ms startup. |
| **Frontend Framework** | Next.js (App Router) | 14.2+ | React Server Components, server-side rendering, robust routing, optimized bundle size. |
| **Frontend Styling** | Tailwind CSS | 3.4+ | Utility-first responsive design, dark security dashboard theme, zero runtime CSS overhead. |
| **Containerization** | Docker & Compose | Latest | Reproducible local and CI environments, isolated network namespaces. |

---

## 2. Release-Specific Capability Roadmap

- **MVP (Current Foundation):** Async HTTPX crawling, regex/AST JS extraction, active injection fuzzing, Typer CLI, single-node dashboard.
- **V1:** Playwright (Headless Chromium) for dynamic DOM and client-side SPA execution, OpenAPI/GraphQL fuzzing.
- **V2:** Local LLM integration (via vLLM/Ollama) for remediation advice; community sandboxed plugins.
- **V3:** Kubernetes Helm charts and distributed worker pools.
