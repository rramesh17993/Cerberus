import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.core.database import db_manager
from app.models import Base

# Prometheus metrics
REQUEST_COUNT = Counter(
    'securescan_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'securescan_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

SCAN_COUNT = Counter(
    'securescan_scans_total',
    'Total number of security scans',
    ['scanner_type', 'status']
)

VULNERABILITY_COUNT = Counter(
    'securescan_vulnerabilities_total',
    'Total number of vulnerabilities found',
    ['severity', 'scanner']
)

class MetricsMiddleware(BaseHTTPMiddleware):
    """Custom middleware for collecting Prometheus metrics"""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        
        # Extract path template for better grouping
        path_template = request.url.path
        for route in request.app.routes:
            match, _ = route.matches(request.scope)
            if match:
                path_template = route.path
                break
        
        response = await call_next(request)
        
        # Record metrics
        duration = time.time() - start_time
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=path_template,
            status_code=response.status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=path_template
        ).observe(duration)
        
        # Add response headers
        response.headers["X-Process-Time"] = str(duration)
        response.headers["X-Request-ID"] = str(id(request))
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown"""
    
    # Startup
    logger = structlog.get_logger()
    logger.info("Starting SecureScan Framework...")
    
    # Initialize database
    try:
        async with db_manager.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        raise
    
    # Initialize scanners
    try:
        from app.scanners.manager import ScannerManager
        scanner_manager = ScannerManager()
        await scanner_manager.initialize()
        app.state.scanner_manager = scanner_manager
        logger.info("Scanner manager initialized")
    except Exception as e:
        logger.error("Scanner manager initialization failed", error=str(e))
        raise
    
    # Initialize Celery (if enabled)
    settings = get_settings()
    if settings.CELERY_ENABLED:
        try:
            from app.workers.celery_app import celery_app
            # Test Celery connection
            celery_app.control.inspect().stats()
            logger.info("Celery worker connected")
        except Exception as e:
            logger.warning("Celery connection failed", error=str(e))
    
    logger.info("SecureScan Framework started successfully!")
    
    yield
    
    # Shutdown
    logger.info("Shutting down SecureScan Framework...")
    
    # Cleanup scanner manager
    if hasattr(app.state, 'scanner_manager'):
        await app.state.scanner_manager.cleanup()
        logger.info("Scanner manager cleaned up")
    
    logger.info("SecureScan Framework shutdown complete")


def create_application() -> FastAPI:
    settings = get_settings()
    setup_logging()
    logger = structlog.get_logger()
    
    app = FastAPI(
        title="SecureScan Framework API",
        description="SecureScan Framework - Open-source security orchestration platform",
        version="1.0.0",
        contact={
            "name": "SecureScan Team",
            "url": "https://github.com/securescan/securescan-framework",
            "email": "team@securescan.dev"
        },
        license_info={
            "name": "MIT License",
            "url": "https://opensource.org/licenses/MIT"
        },
        lifespan=lifespan,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
    )
    
    # Security Middleware
    if not settings.DEBUG:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS
        )
    
    app.add_middleware(SecurityHeadersMiddleware)
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Process-Time", "X-Request-ID"]
    )
    
    # Performance Middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(MetricsMiddleware)
    
    @app.get("/health", tags=["monitoring"])
    async def health_check():
        from app.core.health import HealthChecker
        
        health_checker = HealthChecker()
        health_status = await health_checker.check_all()
        
        status_code = 200 if health_status["status"] == "healthy" else 503
        return JSONResponse(
            status_code=status_code,
            content=health_status
        )
    
    @app.get("/metrics", tags=["monitoring"])
    async def metrics():
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            generate_latest(),
            media_type="text/plain"
        )
    
    @app.get("/", tags=["root"])
    async def root():
        return {
            "name": "SecureScan Framework API",
            "version": "1.0.0",
            "description": "Open-source security orchestration platform",
            "docs_url": "/docs",
            "health_url": "/health",
            "metrics_url": "/metrics",
            "api_base": "/api/v1",
            "features": [
                "Multi-scanner orchestration",
                "Real-time WebSocket updates",
                "SARIF compliance",
                "Enterprise authentication",
                "Scalable architecture"
            ],
            "supported_scanners": [
                "semgrep", "trivy", "zap", "bandit", "checkov", 
                "gitleaks", "safety", "dependency-check"
            ]
        }
    
    # API Routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Exception Handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger = structlog.get_logger()
        logger.error(
            "Unhandled exception occurred",
            path=request.url.path,
            method=request.method,
            error=str(exc),
            exc_info=True
        )
        
        if settings.DEBUG:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "detail": str(exc),
                    "type": type(exc).__name__
                }
            )
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "detail": "An unexpected error occurred"
                }
            )
    
    logger.info("FastAPI application configured successfully")
    return app

app = create_application()