from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.api import api_router
from backend.app.core.config import settings
from backend.app.core.exceptions import AshlynxException, ScopeViolationError, SSRFValidationError
from backend.app.core.logging import logger
from backend.app.middleware.correlation import CorrelationIdMiddleware
from backend.app.middleware.security import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.ENVIRONMENT}]")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise DAST & Automated Web Vulnerability Assessment Platform API",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    lifespan=lifespan
)

# --- Middleware Stack ---
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


# --- Global Exception Handlers ---
@app.exception_handler(SSRFValidationError)
async def ssrf_exception_handler(request: Request, exc: SSRFValidationError):
    logger.warning(f"SSRF Gate Intercepted: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"success": False, "error_code": exc.code, "message": exc.message, "details": exc.details}
    )


@app.exception_handler(ScopeViolationError)
async def scope_exception_handler(request: Request, exc: ScopeViolationError):
    logger.warning(f"Scope Gate Intercepted: {exc.message}")
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"success": False, "error_code": exc.code, "message": exc.message, "details": exc.details}
    )


@app.exception_handler(AshlynxException)
async def ashlynx_generic_exception_handler(request: Request, exc: AshlynxException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"success": False, "error_code": exc.code, "message": exc.message, "details": exc.details}
    )


# --- API Routes ---
app.include_router(api_router, prefix=settings.API_PREFIX)
# Direct root liveness probe for Kubernetes / Docker healthchecks
@app.get("/healthz", include_in_schema=False)
async def root_health():
    return {"status": "HEALTHY", "version": settings.APP_VERSION}
