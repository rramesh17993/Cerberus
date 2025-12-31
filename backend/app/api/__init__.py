"""
🌐 SecureScan Framework - API Router

This module combines all API routes and provides a unified router
for the SecureScan Framework REST API.

Features:
- Versioned API routing (v1)
- Centralized route registration
- API documentation and OpenAPI schema
- Middleware integration
- Health checks and status endpoints

Author: SecureScan Team
"""

try:
    from fastapi import APIRouter, Depends, HTTPException, status
    from fastapi.responses import JSONResponse
except ImportError:
    # Graceful fallback for development
    APIRouter = Depends = HTTPException = status = JSONResponse = None

from app.core.logging import get_logger
from app.core.health import HealthChecker

# Import API route modules
try:
    from app.api.v1.auth import router as auth_router
    from app.api.v1.projects import router as projects_router
    from app.api.v1.scans import router as scans_router
    from app.api.v1.vulnerabilities import router as vulnerabilities_router
except ImportError:
    # Graceful fallback if routers not available
    auth_router = projects_router = scans_router = vulnerabilities_router = None

logger = get_logger("securescan.api")


# =============================================================================
# 🌐 MAIN API ROUTER
# =============================================================================

# Create main API router
api_router = APIRouter() if APIRouter else None

if api_router:
    
    # =============================================================================
    # 🏥 HEALTH CHECK ENDPOINTS
    # =============================================================================
    
    @api_router.get("/health", tags=["Health"])
    async def health_check():
        """
        Basic health check endpoint
        
        Returns simple health status for load balancers and monitoring.
        """
        return {"status": "healthy", "service": "securescan-api"}
    
    
    @api_router.get("/health/detailed", tags=["Health"])
    async def detailed_health_check():
        """
        Detailed health check with component status
        
        Returns comprehensive health information including database,
        Redis, scanners, and system resources.
        """
        try:
            health_checker = HealthChecker()
            health_status = await health_checker.check_all()
            
            # Return appropriate HTTP status based on health
            if health_status["status"] == "healthy":
                return health_status
            elif health_status["status"] == "degraded":
                return JSONResponse(
                    status_code=status.HTTP_207_MULTI_STATUS,
                    content=health_status
                )
            else:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content=health_status
                )
                
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "unhealthy",
                    "error": "Health check failed",
                    "details": str(e)
                }
            )
    
    
    @api_router.get("/status", tags=["Status"])
    async def service_status():
        """
        Service status and version information
        
        Returns basic service information including version,
        uptime, and configuration details.
        """
        from app.core.config import get_settings
        import time
        import os
        
        settings = get_settings()
        
        return {
            "service": "SecureScan Framework API",
            "version": "1.0.0",
            "environment": settings.ENVIRONMENT,
            "debug": settings.DEBUG,
            "uptime_seconds": time.time() - (os.environ.get("START_TIME", time.time())),
            "api_version": "v1",
            "documentation": "/docs",
            "openapi_schema": "/openapi.json"
        }


# =============================================================================
# 🔌 V1 API ROUTER
# =============================================================================

# Create v1 API router
v1_router = APIRouter(prefix="/v1") if APIRouter else None

if v1_router and all([auth_router, projects_router, scans_router, vulnerabilities_router]):
    
    # Include all v1 route modules
    v1_router.include_router(auth_router)
    v1_router.include_router(projects_router)
    v1_router.include_router(scans_router)
    v1_router.include_router(vulnerabilities_router)
    
    # Add v1 specific endpoints
    @v1_router.get("/", tags=["API Info"])
    async def v1_info():
        """
        API v1 information and available endpoints
        
        Returns information about the v1 API including
        available endpoints and their descriptions.
        """
        return {
            "version": "1.0.0",
            "description": "SecureScan Framework REST API v1",
            "endpoints": {
                "/auth": "Authentication and user management",
                "/projects": "Project creation and management",
                "/scans": "Security scan execution and results",
                "/vulnerabilities": "Vulnerability management and tracking"
            },
            "features": [
                "JWT authentication",
                "Role-based access control",
                "Multi-scanner orchestration",
                "SARIF compliance",
                "Real-time scan updates",
                "Vulnerability lifecycle management"
            ],
            "documentation": "/docs",
            "openapi_schema": "/openapi.json"
        }


# =============================================================================
# 🚀 ROUTER REGISTRATION
# =============================================================================

def create_api_router() -> APIRouter:
    """
    Create and configure the main API router
    
    Returns:
        Configured FastAPI router with all endpoints
    """
    if not api_router:
        raise RuntimeError("FastAPI not available")
    
    # Include v1 router
    if v1_router:
        api_router.include_router(v1_router)
    
    # Add global API information endpoint
    @api_router.get("/", tags=["API Info"])
    async def api_info():
        """
        API root endpoint with general information
        
        Returns information about the SecureScan Framework API
        including available versions and capabilities.
        """
        return {
            "name": "SecureScan Framework API",
            "description": "Comprehensive security scanning and vulnerability management platform",
            "version": "1.0.0",
            "api_versions": ["v1"],
            "current_version": "v1",
            "features": [
                "Multi-scanner security testing",
                "SARIF-compliant reporting",
                "Vulnerability management",
                "Project-based organization",
                "Real-time scan execution",
                "RESTful API design",
                "JWT authentication",
                "Role-based access control"
            ],
            "supported_scanners": [
                "Semgrep (SAST)",
                "Trivy (SCA & Container)",
                "OWASP ZAP (DAST)",
                "Gitleaks (Secrets)",
                "Checkov (IaC)"
            ],
            "documentation": {
                "swagger_ui": "/docs",
                "redoc": "/redoc",
                "openapi_schema": "/openapi.json"
            },
            "endpoints": {
                "/health": "Health check endpoints",
                "/status": "Service status information",
                "/v1": "API version 1 endpoints"
            }
        }
    
    return api_router


# =============================================================================
# 🛠️ UTILITY FUNCTIONS
# =============================================================================

def get_api_router() -> APIRouter:
    """Get the configured API router"""
    return create_api_router()


def get_available_routes() -> list:
    """Get list of all available API routes"""
    if not api_router:
        return []
    
    routes = []
    for route in api_router.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            for method in route.methods:
                routes.append({
                    "method": method,
                    "path": route.path,
                    "name": getattr(route, 'name', 'unknown'),
                    "tags": getattr(route, 'tags', [])
                })
    
    return routes


# Export main components
if api_router:
    __all__ = [
        "api_router",
        "v1_router", 
        "create_api_router",
        "get_api_router",
        "get_available_routes"
    ]
else:
    __all__ = []