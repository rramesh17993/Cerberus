"""
🐛 SecureScan Framework - Vulnerabilities API

This module provides vulnerability management endpoints including:
- Vulnerability CRUD operations
- Severity-based filtering and sorting
- Status management (open, resolved, false positive)
- Assignment and remediation tracking
- Bulk operations and exports

Features:
- Comprehensive vulnerability lifecycle management
- Risk assessment and prioritization
- False positive handling
- Assignment and due date tracking
- Bulk status updates
- Export capabilities (SARIF, CSV, JSON)

Author: SecureScan Team
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

try:
    from fastapi import APIRouter, Depends, HTTPException, status, Query
    from pydantic import BaseModel, validator
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select, and_, or_, func, update
    from sqlalchemy.orm import selectinload
except ImportError:
    # Graceful fallback for development
    APIRouter = Depends = HTTPException = status = Query = None
    BaseModel = validator = AsyncSession = None
    select = and_ = or_ = func = update = selectinload = None

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
    Project, Vulnerability, User, ScanResult,
    VulnerabilitySeverity, VulnerabilityStatus
)

logger = get_logger("securescan.api.vulnerabilities")

# Create router
router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"]) if APIRouter else None


# =============================================================================
# 📋 REQUEST/RESPONSE MODELS
# =============================================================================

class VulnerabilityUpdateRequest(BaseModel):
    """Vulnerability update request model"""
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution_comment: Optional[str] = None
    is_false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = None
    
    @validator('status')
    def validate_status(cls, v):
        if v is not None:
            valid_statuses = [
                "open", "in_progress", "resolved", 
                "false_positive", "accepted_risk", "duplicate"
            ]
            if v not in valid_statuses:
                raise ValueError(f'Invalid status: {v}')
        return v


class BulkUpdateRequest(BaseModel):
    """Bulk vulnerability update request"""
    vulnerability_ids: List[str]
    action: str
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    comment: Optional[str] = None
    
    @validator('action')
    def validate_action(cls, v):
        valid_actions = [
            "update_status", "assign", "mark_false_positive", 
            "resolve", "reopen", "duplicate"
        ]
        if v not in valid_actions:
            raise ValueError(f'Invalid action: {v}')
        return v


class VulnerabilityResponse(BaseModel):
    """Detailed vulnerability response model"""
    id: str
    project_id: str
    scan_result_id: str
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
    subcategory: Optional[str]
    tags: List[str]
    status: str
    assigned_to: Optional[str]
    assigned_user: Optional[Dict[str, str]] = None
    due_date: Optional[str]
    resolved_at: Optional[str]
    resolved_by: Optional[str]
    resolution_comment: Optional[str]
    is_false_positive: bool
    false_positive_reason: Optional[str]
    exploitability: Optional[str]
    impact: Optional[str]
    risk_score: Optional[float]
    first_seen: str
    last_seen: str
    occurrence_count: int
    created_at: str
    updated_at: str
    
    class Config:
        from_attributes = True


class VulnerabilityListResponse(BaseModel):
    """Paginated vulnerability list response"""
    items: List[VulnerabilityResponse]
    total: int
    page: int
    size: int
    pages: int


class VulnerabilityStatsResponse(BaseModel):
    """Vulnerability statistics response"""
    total: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_category: Dict[str, int]
    open_vulnerabilities: int
    resolved_vulnerabilities: int
    false_positives: int
    high_risk_count: int
    avg_resolution_days: Optional[float]


# =============================================================================
# 🔍 VULNERABILITY QUERY ENDPOINTS
# =============================================================================

if router:
    
    @router.get("/", response_model=VulnerabilityListResponse)
    async def list_vulnerabilities(
        current_user: User = Depends(get_current_active_user),
        pagination: PaginationParams = Depends(get_pagination_params),
        filters: FilterParams = Depends(get_filter_params),
        db: AsyncSession = Depends(get_database_session),
        project_id: Optional[str] = Query(None, description="Filter by project"),
        severity: Optional[str] = Query(None, description="Filter by severity"),
        status_filter: Optional[str] = Query(None, description="Filter by status"),
        assigned_to: Optional[str] = Query(None, description="Filter by assignee"),
        category: Optional[str] = Query(None, description="Filter by category"),
        file_path: Optional[str] = Query(None, description="Filter by file path"),
        _: None = Depends(log_request)
    ):
        """
        List vulnerabilities accessible to the current user
        
        Returns paginated list of vulnerabilities from projects the user has access to.
        Supports extensive filtering and sorting options.
        """
        try:
            # Build base query - vulnerabilities from accessible projects
            base_query = select(Vulnerability).join(Project).where(
                or_(
                    Project.owner_id == current_user.id,
                    Project.is_public == True,
                    # TODO: Add member-based access
                )
            )
            
            # Apply filters
            if project_id:
                base_query = base_query.where(Vulnerability.project_id == UUID(project_id))
            
            if severity:
                base_query = base_query.where(Vulnerability.severity == severity)
            
            if status_filter:
                base_query = base_query.where(Vulnerability.status == status_filter)
            
            if assigned_to:
                if assigned_to == "unassigned":
                    base_query = base_query.where(Vulnerability.assigned_to.is_(None))
                else:
                    base_query = base_query.where(Vulnerability.assigned_to == UUID(assigned_to))
            
            if category:
                base_query = base_query.where(Vulnerability.category == category)
            
            if file_path:
                base_query = base_query.where(Vulnerability.file_path.ilike(f"%{file_path}%"))
            
            if filters.search:
                base_query = base_query.where(
                    or_(
                        Vulnerability.title.ilike(f"%{filters.search}%"),
                        Vulnerability.description.ilike(f"%{filters.search}%"),
                        Vulnerability.rule_id.ilike(f"%{filters.search}%")
                    )
                )
            
            if filters.created_after:
                base_query = base_query.where(Vulnerability.created_at >= filters.created_after)
            
            if filters.created_before:
                base_query = base_query.where(Vulnerability.created_at <= filters.created_before)
            
            if filters.tags:
                for tag in filters.tags:
                    base_query = base_query.where(Vulnerability.tags.contains([tag]))
            
            # Apply sorting
            if pagination.sort_by:
                sort_column = getattr(Vulnerability, pagination.sort_by, None)
                if sort_column:
                    if pagination.sort_order == "desc":
                        base_query = base_query.order_by(sort_column.desc())
                    else:
                        base_query = base_query.order_by(sort_column.asc())
            else:
                # Default sorting: severity (desc), then created_at (desc)
                base_query = base_query.order_by(
                    Vulnerability.severity.desc(),
                    Vulnerability.created_at.desc()
                )
            
            # Get total count
            count_query = select(func.count()).select_from(base_query.subquery())
            total_result = await db.execute(count_query)
            total = total_result.scalar()
            
            # Apply pagination
            vulns_query = base_query.offset(pagination.offset).limit(pagination.limit)
            result = await db.execute(vulns_query)
            vulnerabilities = result.scalars().all()
            
            # Convert to response models
            items = []
            for vuln in vulnerabilities:
                # Get assigned user info if available
                assigned_user = None
                if vuln.assigned_to:
                    user_result = await db.execute(
                        select(User).where(User.id == vuln.assigned_to)
                    )
                    user = user_result.scalar_one_or_none()
                    if user:
                        assigned_user = {
                            "id": str(user.id),
                            "email": user.email,
                            "username": user.username,
                            "full_name": user.full_name
                        }
                
                vuln_data = {
                    "id": str(vuln.id),
                    "project_id": str(vuln.project_id),
                    "scan_result_id": str(vuln.scan_result_id),
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
                    "subcategory": vuln.subcategory,
                    "tags": vuln.tags or [],
                    "status": vuln.status.value,
                    "assigned_to": str(vuln.assigned_to) if vuln.assigned_to else None,
                    "assigned_user": assigned_user,
                    "due_date": vuln.due_date.isoformat() if vuln.due_date else None,
                    "resolved_at": vuln.resolved_at.isoformat() if vuln.resolved_at else None,
                    "resolved_by": str(vuln.resolved_by) if vuln.resolved_by else None,
                    "resolution_comment": vuln.resolution_comment,
                    "is_false_positive": vuln.is_false_positive,
                    "false_positive_reason": vuln.false_positive_reason,
                    "exploitability": vuln.exploitability,
                    "impact": vuln.impact,
                    "risk_score": vuln.risk_score,
                    "first_seen": vuln.first_seen.isoformat(),
                    "last_seen": vuln.last_seen.isoformat(),
                    "occurrence_count": vuln.occurrence_count,
                    "created_at": vuln.created_at.isoformat(),
                    "updated_at": vuln.updated_at.isoformat()
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
            
        except Exception as e:
            logger.error(f"Failed to list vulnerabilities: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list vulnerabilities"
            )
    
    
    @router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
    async def get_vulnerability(
        vulnerability_id: str,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Get vulnerability details by ID
        
        Returns detailed vulnerability information including SARIF data and history.
        """
        try:
            # Get vulnerability with project access check
            result = await db.execute(
                select(Vulnerability)
                .join(Project)
                .where(Vulnerability.id == UUID(vulnerability_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                        # TODO: Add member-based access
                    )
                )
            )
            
            vuln = result.scalar_one_or_none()
            if not vuln:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Vulnerability not found or access denied"
                )
            
            # Get assigned user info if available
            assigned_user = None
            if vuln.assigned_to:
                user_result = await db.execute(
                    select(User).where(User.id == vuln.assigned_to)
                )
                user = user_result.scalar_one_or_none()
                if user:
                    assigned_user = {
                        "id": str(user.id),
                        "email": user.email,
                        "username": user.username,
                        "full_name": user.full_name
                    }
            
            vuln_data = {
                "id": str(vuln.id),
                "project_id": str(vuln.project_id),
                "scan_result_id": str(vuln.scan_result_id),
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
                "subcategory": vuln.subcategory,
                "tags": vuln.tags or [],
                "status": vuln.status.value,
                "assigned_to": str(vuln.assigned_to) if vuln.assigned_to else None,
                "assigned_user": assigned_user,
                "due_date": vuln.due_date.isoformat() if vuln.due_date else None,
                "resolved_at": vuln.resolved_at.isoformat() if vuln.resolved_at else None,
                "resolved_by": str(vuln.resolved_by) if vuln.resolved_by else None,
                "resolution_comment": vuln.resolution_comment,
                "is_false_positive": vuln.is_false_positive,
                "false_positive_reason": vuln.false_positive_reason,
                "exploitability": vuln.exploitability,
                "impact": vuln.impact,
                "risk_score": vuln.risk_score,
                "first_seen": vuln.first_seen.isoformat(),
                "last_seen": vuln.last_seen.isoformat(),
                "occurrence_count": vuln.occurrence_count,
                "created_at": vuln.created_at.isoformat(),
                "updated_at": vuln.updated_at.isoformat()
            }
            
            return vuln_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get vulnerability: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get vulnerability"
            )


# =============================================================================
# ✏️ VULNERABILITY MANAGEMENT ENDPOINTS
# =============================================================================

if router:
    
    @router.put("/{vulnerability_id}", response_model=VulnerabilityResponse)
    async def update_vulnerability(
        vulnerability_id: str,
        request: VulnerabilityUpdateRequest,
        current_user: User = Depends(require_developer),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Update vulnerability information
        
        Updates vulnerability status, assignment, and other metadata.
        Only developers and above can update vulnerabilities.
        """
        try:
            # Get vulnerability with project access check
            result = await db.execute(
                select(Vulnerability)
                .join(Project)
                .where(Vulnerability.id == UUID(vulnerability_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        # TODO: Add member-based access for developers
                    )
                )
            )
            
            vuln = result.scalar_one_or_none()
            if not vuln:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Vulnerability not found or access denied"
                )
            
            # Update fields
            update_data = request.dict(exclude_unset=True)
            
            for field, value in update_data.items():
                if field == "status" and value:
                    vuln.status = VulnerabilityStatus(value)
                    if value in ["resolved", "false_positive"]:
                        vuln.resolved_at = datetime.now()
                        vuln.resolved_by = current_user.id
                elif field == "assigned_to" and value:
                    vuln.assigned_to = UUID(value) if value != "unassigned" else None
                elif hasattr(vuln, field):
                    setattr(vuln, field, value)
            
            await db.commit()
            await db.refresh(vuln)
            
            logger.info(f"Vulnerability updated: {vuln.id} by user {current_user.email}")
            
            # Return updated vulnerability
            return await get_vulnerability(vulnerability_id, current_user, db)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to update vulnerability: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update vulnerability"
            )
    
    
    @router.post("/bulk-update")
    async def bulk_update_vulnerabilities(
        request: BulkUpdateRequest,
        current_user: User = Depends(require_developer),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Bulk update multiple vulnerabilities
        
        Performs bulk operations on multiple vulnerabilities such as
        status updates, assignments, or marking as false positives.
        """
        try:
            # Verify access to all vulnerabilities
            vuln_ids = [UUID(vid) for vid in request.vulnerability_ids]
            
            access_query = select(Vulnerability).join(Project).where(
                and_(
                    Vulnerability.id.in_(vuln_ids),
                    or_(
                        Project.owner_id == current_user.id,
                        # TODO: Add member-based access for developers
                    )
                )
            )
            
            result = await db.execute(access_query)
            accessible_vulns = result.scalars().all()
            
            if len(accessible_vulns) != len(vuln_ids):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to some vulnerabilities"
                )
            
            # Perform bulk update based on action
            update_data = {}
            
            if request.action == "update_status" and request.status:
                update_data["status"] = VulnerabilityStatus(request.status)
                if request.status in ["resolved", "false_positive"]:
                    update_data["resolved_at"] = datetime.now()
                    update_data["resolved_by"] = current_user.id
            
            elif request.action == "assign" and request.assigned_to:
                update_data["assigned_to"] = UUID(request.assigned_to) if request.assigned_to != "unassigned" else None
            
            elif request.action == "mark_false_positive":
                update_data["is_false_positive"] = True
                update_data["status"] = VulnerabilityStatus.FALSE_POSITIVE
                update_data["resolved_at"] = datetime.now()
                update_data["resolved_by"] = current_user.id
                if request.comment:
                    update_data["false_positive_reason"] = request.comment
            
            elif request.action == "resolve":
                update_data["status"] = VulnerabilityStatus.RESOLVED
                update_data["resolved_at"] = datetime.now()
                update_data["resolved_by"] = current_user.id
                if request.comment:
                    update_data["resolution_comment"] = request.comment
            
            elif request.action == "reopen":
                update_data["status"] = VulnerabilityStatus.OPEN
                update_data["resolved_at"] = None
                update_data["resolved_by"] = None
            
            if update_data:
                # Execute bulk update
                await db.execute(
                    update(Vulnerability)
                    .where(Vulnerability.id.in_(vuln_ids))
                    .values(**update_data)
                )
                
                await db.commit()
                
                logger.info(
                    f"Bulk update performed on {len(vuln_ids)} vulnerabilities "
                    f"by user {current_user.email}: {request.action}"
                )
            
            return {
                "message": f"Successfully updated {len(vuln_ids)} vulnerabilities",
                "action": request.action,
                "updated_count": len(vuln_ids)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Bulk update failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to perform bulk update"
            )


# =============================================================================
# 📊 VULNERABILITY STATISTICS ENDPOINTS
# =============================================================================

if router:
    
    @router.get("/stats/summary", response_model=VulnerabilityStatsResponse)
    async def get_vulnerability_stats(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        project_id: Optional[str] = Query(None, description="Filter by project"),
        _: None = Depends(log_request)
    ):
        """
        Get vulnerability statistics and metrics
        
        Returns comprehensive statistics about vulnerabilities including
        severity distribution, status breakdown, and trends.
        """
        try:
            # Build base query for accessible vulnerabilities
            base_query = select(Vulnerability).join(Project).where(
                or_(
                    Project.owner_id == current_user.id,
                    Project.is_public == True,
                    # TODO: Add member-based access
                )
            )
            
            if project_id:
                base_query = base_query.where(Vulnerability.project_id == UUID(project_id))
            
            # Get all vulnerabilities for stats calculation
            result = await db.execute(base_query)
            vulnerabilities = result.scalars().all()
            
            # Calculate statistics
            total = len(vulnerabilities)
            
            # By severity
            by_severity = {}
            for severity in VulnerabilitySeverity:
                count = sum(1 for v in vulnerabilities if v.severity == severity)
                by_severity[severity.value] = count
            
            # By status
            by_status = {}
            for status_val in VulnerabilityStatus:
                count = sum(1 for v in vulnerabilities if v.status == status_val)
                by_status[status_val.value] = count
            
            # By category
            by_category = {}
            for vuln in vulnerabilities:
                if vuln.category:
                    by_category[vuln.category] = by_category.get(vuln.category, 0) + 1
            
            # Additional metrics
            open_vulnerabilities = sum(1 for v in vulnerabilities if v.status == VulnerabilityStatus.OPEN)
            resolved_vulnerabilities = sum(1 for v in vulnerabilities if v.status == VulnerabilityStatus.RESOLVED)
            false_positives = sum(1 for v in vulnerabilities if v.is_false_positive)
            high_risk_count = sum(1 for v in vulnerabilities if v.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH])
            
            # Calculate average resolution time
            resolved_vulns = [v for v in vulnerabilities if v.resolved_at and v.created_at]
            avg_resolution_days = None
            if resolved_vulns:
                total_days = sum((v.resolved_at - v.created_at).days for v in resolved_vulns)
                avg_resolution_days = total_days / len(resolved_vulns)
            
            return {
                "total": total,
                "by_severity": by_severity,
                "by_status": by_status,
                "by_category": by_category,
                "open_vulnerabilities": open_vulnerabilities,
                "resolved_vulnerabilities": resolved_vulnerabilities,
                "false_positives": false_positives,
                "high_risk_count": high_risk_count,
                "avg_resolution_days": avg_resolution_days
            }
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability stats: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get vulnerability statistics"
            )


# Export router
__all__ = ["router"] if router else []