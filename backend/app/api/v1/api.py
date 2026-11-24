from fastapi import APIRouter
from backend.app.api.v1.endpoints import health, scans, findings

api_router = APIRouter()

api_router.include_router(health.router, prefix="", tags=["System Health"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scan Orchestration"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings & Evidence"])
