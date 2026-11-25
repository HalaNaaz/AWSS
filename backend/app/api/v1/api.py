from fastapi import APIRouter
from backend.app.api.v1.endpoints import health, scans, findings, recon, passive, reports, active, discovery

api_router = APIRouter()

api_router.include_router(health.router, prefix="", tags=["System Health"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scan Orchestration"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reporting & Export"])
api_router.include_router(recon.router, prefix="/recon", tags=["Reconnaissance & Crawling"])
api_router.include_router(passive.router, prefix="/passive", tags=["Passive Security Analysis"])
api_router.include_router(active.router, prefix="/active", tags=["Active Vulnerability Detection"])
api_router.include_router(discovery.router, prefix="/discovery", tags=["Attack Surface Discovery & Intelligence"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings & Evidence"])
