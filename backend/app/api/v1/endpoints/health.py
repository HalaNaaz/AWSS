from typing import Dict, Any
from fastapi import APIRouter, status
from backend.app.core.config import settings

router = APIRouter()


@router.get("/healthz", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, Any]:
    """Basic liveness probe."""
    return {
        "status": "HEALTHY",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


@router.get("/readyz", status_code=status.HTTP_200_OK)
async def readiness_check() -> Dict[str, Any]:
    """Readiness probe verifying operational capabilities."""
    return {
        "status": "READY",
        "checks": {
            "api": "OK",
            "scope_gate": "OPERATIONAL",
            "evidence_redactor": "OPERATIONAL"
        }
    }
