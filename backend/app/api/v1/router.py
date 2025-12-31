"""
🔌 API Router - Central routing configuration for SecureScan Framework
"""

from fastapi import APIRouter
from app.api.v1 import auth, projects, scans, vulnerabilities

# =============================================================================
# 🚦 MAIN API ROUTER
# =============================================================================

api_router = APIRouter()

# Include all API routes
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

api_router.include_router(
    projects.router,
    prefix="/projects", 
    tags=["Projects"]
)

api_router.include_router(
    scans.router,
    prefix="/scans",
    tags=["Scans"]
)

api_router.include_router(
    vulnerabilities.router,
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"]
)

# Health check endpoint at root level
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "securescan-api"}