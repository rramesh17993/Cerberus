"""
🔬 SecureScan Framework - Scans API

This module provides scan execution and management endpoints including:
- Scan creation and execution
- Scan result retrieval and analysis
- SARIF report processing
- Vulnerability correlation
- Scan history and analytics

Features:
- Multi-scanner orchestration
- Real-time scan progress updates
- SARIF-compliant result format
- Vulnerability deduplication
- Scan scheduling and automation
- Performance metrics and analytics

Author: SecureScan Team
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
import asyncio

try:
    from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
    from pydantic import BaseModel, validator
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select, and_, or_, func, desc
    from sqlalchemy.orm import selectinload
except ImportError:
    # Graceful fallback for development
    APIRouter = Depends = HTTPException = status = BackgroundTasks = Query = None
    BaseModel = validator = AsyncSession = None
    select = and_ = or_ = func = desc = selectinload = None

from app.api.dependencies import (
    get_database_session,
    get_current_active_user,
    require_developer,
    get_pagination_params,
    get_filter_params,
    PaginationParams,
    FilterParams,
    log_request
)
from app.core.logging import get_logger
from app.models import (
    Project, ScanResult, Vulnerability, User,
    ScanType, ScanStatus, VulnerabilitySeverity
)
from app.scanners.manager import ScannerManager, SARIFProcessor

logger = get_logger("securescan.api.scans")

# Create router
router = APIRouter(prefix="/scans", tags=["Scans"]) if APIRouter else None


# =============================================================================
# 📋 REQUEST/RESPONSE MODELS
# =============================================================================

class ScanCreateRequest(BaseModel):
    """Scan creation request model"""
    project_id: str
    scan_types: List[str]
    target_url: Optional[str] = None
    branch: str = "main"
    commit_hash: Optional[str] = None
    trigger_type: str = "manual"
    scanner_configs: Dict[str, Any] = {}
    
    @validator('scan_types')
    def validate_scan_types(cls, v):
        valid_types = ["sast", "dast", "sca", "secrets", "iac", "container", "full"]
        for scan_type in v:
            if scan_type not in valid_types:
                raise ValueError(f'Invalid scan type: {scan_type}')
        return v
    
    @validator('trigger_type')
    def validate_trigger_type(cls, v):
        valid_triggers = ["manual", "scheduled", "webhook", "api"]
        if v not in valid_triggers:
            raise ValueError(f'Invalid trigger type: {v}')
        return v


class ScanResponse(BaseModel):
    """Scan response model"""
    id: str
    project_id: str
    scan_type: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[int]
    scanner_name: str
    scanner_version: Optional[str]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    commit_hash: Optional[str]
    branch: str
    trigger_type: str
    triggered_by: str
    error_message: Optional[str]
    created_at: str
    
    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Paginated scan list response"""
    items: List[ScanResponse]
    total: int
    page: int
    size: int
    pages: int


class VulnerabilityResponse(BaseModel):
    """Vulnerability response model"""
    id: str
    rule_id: str
    cwe_id: Optional[str]
    cve_id: Optional[str]
    title: str
    description: Optional[str]
    severity: str
    confidence: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    column_number: Optional[int]
    code_snippet: Optional[str]
    category: Optional[str]
    status: str
    first_seen: str
    last_seen: str
    
    class Config:
        from_attributes = True


class ScanSummaryResponse(BaseModel):
    """Scan summary statistics"""
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    avg_scan_duration: float
    last_scan_date: Optional[str]


# =============================================================================
# 🚀 SCAN EXECUTION ENDPOINTS
# =============================================================================

if router:
    
    @router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
    async def create_scan(
        request: ScanCreateRequest,
        background_tasks: BackgroundTasks,
        current_user: User = Depends(require_developer),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Create and execute a new security scan
        
        Creates a new scan job and starts execution in the background.
        The scan will run multiple security scanners based on the requested types.
        """
        try:
            # Verify project access
            project_result = await db.execute(
                select(Project)
                .where(Project.id == UUID(request.project_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                    )
                )
            )
            
            project = project_result.scalar_one_or_none()
            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found or access denied"
                )
            
            # Convert scan types
            scan_type_mapping = {
                "sast": ScanType.SAST,
                "dast": ScanType.DAST,
                "sca": ScanType.SCA,
                "secrets": ScanType.SECRETS,
                "iac": ScanType.IAC,
                "container": ScanType.CONTAINER,
                "full": [ScanType.SAST, ScanType.SCA, ScanType.SECRETS, ScanType.IAC]
            }
            
            scan_types = []
            for scan_type_str in request.scan_types:
                mapped = scan_type_mapping.get(scan_type_str)
                if isinstance(mapped, list):
                    scan_types.extend(mapped)
                else:
                    scan_types.append(mapped)
            
            # Create scan result records for each scanner
            scan_results = []
            for scan_type in set(scan_types):  # Remove duplicates
                scan_result = ScanResult(
                    project_id=project.id,
                    scan_type=scan_type,
                    status=ScanStatus.PENDING,
                    branch=request.branch,
                    commit_hash=request.commit_hash,
                    trigger_type=request.trigger_type,
                    triggered_by=current_user.id,
                    scanner_config=request.scanner_configs
                )
                db.add(scan_result)
                scan_results.append(scan_result)
            
            await db.commit()
            
            # Refresh all scan results to get IDs
            for scan_result in scan_results:
                await db.refresh(scan_result)
            
            # Start scan execution in background
            background_tasks.add_task(
                execute_scan_background,
                scan_results=[sr.id for sr in scan_results],
                project_repository_url=project.repository_url,
                target_url=request.target_url,
                branch=request.branch,
                scanner_configs=request.scanner_configs
            )
            
            logger.info(f"Scan created for project {project.name} by user {current_user.email}")
            
            # Return first scan result as response
            first_scan = scan_results[0]
            return {
                "id": str(first_scan.id),
                "project_id": str(first_scan.project_id),
                "scan_type": first_scan.scan_type.value,
                "status": first_scan.status.value,
                "started_at": None,
                "completed_at": None,
                "duration_seconds": None,
                "scanner_name": "multiple",
                "scanner_version": None,
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "commit_hash": first_scan.commit_hash,
                "branch": first_scan.branch,
                "trigger_type": first_scan.trigger_type,
                "triggered_by": str(first_scan.triggered_by),
                "error_message": None,
                "created_at": first_scan.created_at.isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Scan creation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create scan"
            )
    
    
    @router.get("/", response_model=ScanListResponse)
    async def list_scans(
        current_user: User = Depends(get_current_active_user),
        pagination: PaginationParams = Depends(get_pagination_params),
        filters: FilterParams = Depends(get_filter_params),
        db: AsyncSession = Depends(get_database_session),
        project_id: Optional[str] = Query(None, description="Filter by project"),
        status_filter: Optional[str] = Query(None, description="Filter by status"),
        scan_type: Optional[str] = Query(None, description="Filter by scan type"),
        _: None = Depends(log_request)
    ):
        """
        List scans accessible to the current user
        
        Returns paginated list of scans from projects the user has access to.
        """
        try:
            # Build base query - scans from accessible projects
            base_query = select(ScanResult).join(Project).where(
                or_(
                    Project.owner_id == current_user.id,
                    Project.is_public == True,
                    # TODO: Add member-based access
                )
            )
            
            # Apply filters
            if project_id:
                base_query = base_query.where(ScanResult.project_id == UUID(project_id))
            
            if status_filter:
                base_query = base_query.where(ScanResult.status == status_filter)
            
            if scan_type:
                base_query = base_query.where(ScanResult.scan_type == scan_type)
            
            if filters.created_after:
                base_query = base_query.where(ScanResult.created_at >= filters.created_after)
            
            if filters.created_before:
                base_query = base_query.where(ScanResult.created_at <= filters.created_before)
            
            # Apply sorting
            if pagination.sort_by:
                sort_column = getattr(ScanResult, pagination.sort_by, None)
                if sort_column:
                    if pagination.sort_order == "desc":
                        base_query = base_query.order_by(sort_column.desc())
                    else:
                        base_query = base_query.order_by(sort_column.asc())
            else:
                base_query = base_query.order_by(ScanResult.created_at.desc())
            
            # Get total count
            count_query = select(func.count()).select_from(base_query.subquery())
            total_result = await db.execute(count_query)
            total = total_result.scalar()
            
            # Apply pagination
            scans_query = base_query.offset(pagination.offset).limit(pagination.limit)
            result = await db.execute(scans_query)
            scans = result.scalars().all()
            
            # Convert to response models
            items = []
            for scan in scans:
                scan_data = {
                    "id": str(scan.id),
                    "project_id": str(scan.project_id),
                    "scan_type": scan.scan_type.value,
                    "status": scan.status.value,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "duration_seconds": scan.duration_seconds,
                    "scanner_name": scan.scanner_name or "unknown",
                    "scanner_version": scan.scanner_version,
                    "total_vulnerabilities": scan.total_vulnerabilities,
                    "critical_count": scan.critical_count,
                    "high_count": scan.high_count,
                    "medium_count": scan.medium_count,
                    "low_count": scan.low_count,
                    "info_count": scan.info_count,
                    "commit_hash": scan.commit_hash,
                    "branch": scan.branch,
                    "trigger_type": scan.trigger_type,
                    "triggered_by": str(scan.triggered_by),
                    "error_message": scan.error_message,
                    "created_at": scan.created_at.isoformat()
                }
                items.append(scan_data)
            
            pages = (total + pagination.size - 1) // pagination.size
            
            return {
                "items": items,
                "total": total,
                "page": pagination.page,
                "size": pagination.size,
                "pages": pages
            }
            
        except Exception as e:
            logger.error(f"Failed to list scans: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list scans"
            )
    
    
    @router.get("/{scan_id}", response_model=ScanResponse)
    async def get_scan(
        scan_id: str,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Get scan details by ID
        
        Returns detailed scan information including results and vulnerabilities.
        """
        try:
            # Get scan with project access check
            result = await db.execute(
                select(ScanResult)
                .join(Project)
                .where(ScanResult.id == UUID(scan_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                        # TODO: Add member-based access
                    )
                )
            )
            
            scan = result.scalar_one_or_none()
            if not scan:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan not found or access denied"
                )
            
            scan_data = {
                "id": str(scan.id),
                "project_id": str(scan.project_id),
                "scan_type": scan.scan_type.value,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "scanner_name": scan.scanner_name or "unknown",
                "scanner_version": scan.scanner_version,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "info_count": scan.info_count,
                "commit_hash": scan.commit_hash,
                "branch": scan.branch,
                "trigger_type": scan.trigger_type,
                "triggered_by": str(scan.triggered_by),
                "error_message": scan.error_message,
                "created_at": scan.created_at.isoformat()
            }
            
            return scan_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get scan: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get scan"
            )
    
    
    @router.get("/{scan_id}/vulnerabilities")
    async def get_scan_vulnerabilities(
        scan_id: str,
        current_user: User = Depends(get_current_active_user),
        pagination: PaginationParams = Depends(get_pagination_params),
        db: AsyncSession = Depends(get_database_session),
        severity: Optional[str] = Query(None, description="Filter by severity"),
        status_filter: Optional[str] = Query(None, description="Filter by status"),
        _: None = Depends(log_request)
    ):
        """
        Get vulnerabilities found in a specific scan
        
        Returns paginated list of vulnerabilities with filtering options.
        """
        try:
            # Verify scan access
            scan_result = await db.execute(
                select(ScanResult)
                .join(Project)
                .where(ScanResult.id == UUID(scan_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                        # TODO: Add member-based access
                    )
                )
            )
            
            scan = scan_result.scalar_one_or_none()
            if not scan:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan not found or access denied"
                )
            
            # Build vulnerability query
            vuln_query = select(Vulnerability).where(Vulnerability.scan_result_id == scan.id)
            
            # Apply filters
            if severity:
                vuln_query = vuln_query.where(Vulnerability.severity == severity)
            
            if status_filter:
                vuln_query = vuln_query.where(Vulnerability.status == status_filter)
            
            # Apply sorting
            vuln_query = vuln_query.order_by(
                Vulnerability.severity.desc(),
                Vulnerability.created_at.desc()
            )
            
            # Get total count
            count_query = select(func.count()).select_from(vuln_query.subquery())
            total_result = await db.execute(count_query)
            total = total_result.scalar()
            
            # Apply pagination
            paginated_query = vuln_query.offset(pagination.offset).limit(pagination.limit)
            result = await db.execute(paginated_query)
            vulnerabilities = result.scalars().all()
            
            # Convert to response models
            items = []
            for vuln in vulnerabilities:
                vuln_data = {
                    "id": str(vuln.id),
                    "rule_id": vuln.rule_id,
                    "cwe_id": vuln.cwe_id,
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "description": vuln.description,
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "column_number": vuln.column_number,
                    "code_snippet": vuln.code_snippet,
                    "category": vuln.category,
                    "status": vuln.status.value,
                    "first_seen": vuln.first_seen.isoformat(),
                    "last_seen": vuln.last_seen.isoformat()
                }
                items.append(vuln_data)
            
            pages = (total + pagination.size - 1) // pagination.size
            
            return {
                "items": items,
                "total": total,
                "page": pagination.page,
                "size": pagination.size,
                "pages": pages
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get scan vulnerabilities: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get scan vulnerabilities"
            )
    
    
    @router.get("/{scan_id}/sarif")
    async def get_scan_sarif(
        scan_id: str,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Get SARIF report for a specific scan
        
        Returns the raw SARIF report generated by the scanners.
        """
        try:
            # Get scan with access check
            result = await db.execute(
                select(ScanResult)
                .join(Project)
                .where(ScanResult.id == UUID(scan_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                        # TODO: Add member-based access
                    )
                )
            )
            
            scan = result.scalar_one_or_none()
            if not scan:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan not found or access denied"
                )
            
            if not scan.sarif_report:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="SARIF report not available for this scan"
                )
            
            return scan.sarif_report
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get SARIF report: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get SARIF report"
            )


# =============================================================================
# 🏃 BACKGROUND SCAN EXECUTION
# =============================================================================

async def execute_scan_background(
    scan_results: List[str],
    project_repository_url: str = None,
    target_url: str = None,
    branch: str = "main",
    scanner_configs: Dict[str, Any] = None
):
    """
    Execute scan in background task
    
    Args:
        scan_results: List of scan result IDs
        project_repository_url: Repository URL to clone and scan
        target_url: Target URL for DAST scanning
        branch: Git branch to scan
        scanner_configs: Scanner configurations
    """
    from app.core.database import get_db_manager
    
    db_manager = get_db_manager()
    scanner_manager = ScannerManager()
    sarif_processor = SARIFProcessor()
    
    logger.info(f"Background scan execution started for {len(scan_results)} scans")
    
    async with db_manager.get_session() as db:
        try:
            # Update scan status to running
            for scan_result_id in scan_results:
                result = await db.execute(
                    select(ScanResult).where(ScanResult.id == UUID(scan_result_id))
                )
                scan_result = result.scalar_one_or_none()
                if scan_result:
                    scan_result.status = ScanStatus.RUNNING
                    scan_result.started_at = datetime.now()
            
            await db.commit()
            
            # TODO: Execute actual scanning logic here
            # For now, just simulate completion
            await asyncio.sleep(10)  # Simulate scan execution
            
            # Update scan status to completed
            for scan_result_id in scan_results:
                result = await db.execute(
                    select(ScanResult).where(ScanResult.id == UUID(scan_result_id))
                )
                scan_result = result.scalar_one_or_none()
                if scan_result:
                    scan_result.status = ScanStatus.COMPLETED
                    scan_result.completed_at = datetime.now()
                    scan_result.duration_seconds = 10
                    scan_result.total_vulnerabilities = 0
            
            await db.commit()
            
            logger.info(f"Background scan execution completed for {len(scan_results)} scans")
            
        except Exception as e:
            logger.error(f"Background scan execution failed: {str(e)}")
            
            # Update scan status to failed
            for scan_result_id in scan_results:
                result = await db.execute(
                    select(ScanResult).where(ScanResult.id == UUID(scan_result_id))
                )
                scan_result = result.scalar_one_or_none()
                if scan_result:
                    scan_result.status = ScanStatus.FAILED
                    scan_result.completed_at = datetime.now()
                    scan_result.error_message = str(e)
            
            await db.commit()


# Export router
__all__ = ["router"] if router else []