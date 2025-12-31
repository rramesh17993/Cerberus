"""
📁 SecureScan Framework - Projects API

This module provides project management endpoints including:
- Project CRUD operations
- Member management and access control
- Project settings and configuration
- Repository integration
- Scan scheduling and automation

Features:
- Project-based access control
- Member invitation and role management
- Repository integration (Git, SVN)
- Automated scan scheduling
- Project templates and settings
- Compliance and governance features

Author: SecureScan Team
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

try:
    from fastapi import APIRouter, Depends, HTTPException, status, Query
    from pydantic import BaseModel, validator
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select, and_, or_, func
    from sqlalchemy.orm import selectinload
except ImportError:
    # Graceful fallback for development
    APIRouter = Depends = HTTPException = status = Query = None
    BaseModel = validator = AsyncSession = None
    select = and_ = or_ = func = selectinload = None

from app.api.dependencies import (
    get_database_session,
    get_current_active_user,
    require_manager,
    get_pagination_params,
    get_filter_params,
    PaginationParams,
    FilterParams,
    log_request
)
from app.core.logging import get_logger
from app.models import Project, User, Organization, UserRole, ProjectStatus

logger = get_logger("securescan.api.projects")

# Create router
router = APIRouter(prefix="/projects", tags=["Projects"]) if APIRouter else None


# =============================================================================
# 📋 REQUEST/RESPONSE MODELS
# =============================================================================

class ProjectCreateRequest(BaseModel):
    """Project creation request model"""
    name: str
    slug: str
    description: Optional[str] = None
    organization_id: Optional[str] = None
    repository_url: Optional[str] = None
    repository_branch: str = "main"
    repository_type: str = "git"
    is_public: bool = False
    auto_scan_enabled: bool = False
    scan_schedule: Optional[str] = None
    default_scan_types: List[str] = []
    settings: Dict[str, Any] = {}
    
    @validator('name')
    def validate_name(cls, v):
        if len(v) < 3 or len(v) > 100:
            raise ValueError('Project name must be between 3 and 100 characters')
        return v
    
    @validator('slug')
    def validate_slug(cls, v):
        import re
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError('Slug can only contain lowercase letters, numbers, and hyphens')
        if len(v) < 3 or len(v) > 100:
            raise ValueError('Slug must be between 3 and 100 characters')
        return v


class ProjectUpdateRequest(BaseModel):
    """Project update request model"""
    name: Optional[str] = None
    description: Optional[str] = None
    repository_url: Optional[str] = None
    repository_branch: Optional[str] = None
    is_public: Optional[bool] = None
    auto_scan_enabled: Optional[bool] = None
    scan_schedule: Optional[str] = None
    default_scan_types: Optional[List[str]] = None
    settings: Optional[Dict[str, Any]] = None
    status: Optional[str] = None


class ProjectMemberRequest(BaseModel):
    """Project member invitation request"""
    email: str
    role: str = "viewer"
    
    @validator('role')
    def validate_role(cls, v):
        valid_roles = ['viewer', 'developer', 'manager']
        if v not in valid_roles:
            raise ValueError(f'Role must be one of: {", ".join(valid_roles)}')
        return v


class ProjectResponse(BaseModel):
    """Project response model"""
    id: str
    name: str
    slug: str
    description: Optional[str]
    organization_id: Optional[str]
    owner_id: str
    repository_url: Optional[str]
    repository_branch: str
    repository_type: str
    status: str
    is_public: bool
    auto_scan_enabled: bool
    scan_schedule: Optional[str]
    default_scan_types: List[str]
    settings: Dict[str, Any]
    created_at: str
    updated_at: str
    
    # Statistics
    total_scans: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    last_scan_at: Optional[str] = None
    
    class Config:
        from_attributes = True


class ProjectMemberResponse(BaseModel):
    """Project member response model"""
    user_id: str
    email: str
    username: str
    full_name: str
    role: str
    joined_at: str
    
    class Config:
        from_attributes = True


class ProjectListResponse(BaseModel):
    """Paginated project list response"""
    items: List[ProjectResponse]
    total: int
    page: int
    size: int
    pages: int


# =============================================================================
# 📁 PROJECT CRUD ENDPOINTS
# =============================================================================

if router:
    
    @router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
    async def create_project(
        request: ProjectCreateRequest,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Create a new project
        
        Creates a new project with the current user as the owner.
        Projects can be associated with an organization for team collaboration.
        """
        try:
            # Check if project slug already exists for the organization/user
            existing_project = await db.execute(
                select(Project).where(
                    and_(
                        Project.slug == request.slug,
                        or_(
                            Project.organization_id == request.organization_id,
                            Project.owner_id == current_user.id
                        )
                    )
                )
            )
            
            if existing_project.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Project with this slug already exists"
                )
            
            # Validate organization access if specified
            if request.organization_id:
                # TODO: Check if user has access to the organization
                pass
            
            # Create new project
            new_project = Project(
                name=request.name,
                slug=request.slug,
                description=request.description,
                organization_id=UUID(request.organization_id) if request.organization_id else None,
                owner_id=current_user.id,
                repository_url=request.repository_url,
                repository_branch=request.repository_branch,
                repository_type=request.repository_type,
                status=ProjectStatus.ACTIVE,
                is_public=request.is_public,
                auto_scan_enabled=request.auto_scan_enabled,
                scan_schedule=request.scan_schedule,
                default_scan_types=request.default_scan_types,
                settings=request.settings
            )
            
            db.add(new_project)
            await db.commit()
            await db.refresh(new_project)
            
            logger.info(f"Project created: {new_project.name} by user {current_user.email}")
            
            # Convert to response model
            response_data = {
                "id": str(new_project.id),
                "name": new_project.name,
                "slug": new_project.slug,
                "description": new_project.description,
                "organization_id": str(new_project.organization_id) if new_project.organization_id else None,
                "owner_id": str(new_project.owner_id),
                "repository_url": new_project.repository_url,
                "repository_branch": new_project.repository_branch,
                "repository_type": new_project.repository_type,
                "status": new_project.status.value,
                "is_public": new_project.is_public,
                "auto_scan_enabled": new_project.auto_scan_enabled,
                "scan_schedule": new_project.scan_schedule,
                "default_scan_types": new_project.default_scan_types,
                "settings": new_project.settings,
                "created_at": new_project.created_at.isoformat(),
                "updated_at": new_project.updated_at.isoformat()
            }
            
            return response_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Project creation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create project"
            )
    
    
    @router.get("/", response_model=ProjectListResponse)
    async def list_projects(
        current_user: User = Depends(get_current_active_user),
        pagination: PaginationParams = Depends(get_pagination_params),
        filters: FilterParams = Depends(get_filter_params),
        db: AsyncSession = Depends(get_database_session),
        organization_id: Optional[str] = Query(None, description="Filter by organization"),
        status_filter: Optional[str] = Query(None, description="Filter by status"),
        _: None = Depends(log_request)
    ):
        """
        List projects accessible to the current user
        
        Returns paginated list of projects the user has access to,
        either as owner, member, or through organization membership.
        """
        try:
            # Build base query - projects user has access to
            base_query = select(Project).where(
                or_(
                    Project.owner_id == current_user.id,  # Owned by user
                    Project.is_public == True,            # Public projects
                    # TODO: Add member-based access through user_projects table
                )
            )
            
            # Apply filters
            if organization_id:
                base_query = base_query.where(Project.organization_id == UUID(organization_id))
            
            if status_filter:
                base_query = base_query.where(Project.status == status_filter)
            
            if filters.search:
                base_query = base_query.where(
                    or_(
                        Project.name.ilike(f"%{filters.search}%"),
                        Project.description.ilike(f"%{filters.search}%")
                    )
                )
            
            if filters.created_after:
                base_query = base_query.where(Project.created_at >= filters.created_after)
            
            if filters.created_before:
                base_query = base_query.where(Project.created_at <= filters.created_before)
            
            # Apply sorting
            if pagination.sort_by:
                sort_column = getattr(Project, pagination.sort_by, None)
                if sort_column:
                    if pagination.sort_order == "desc":
                        base_query = base_query.order_by(sort_column.desc())
                    else:
                        base_query = base_query.order_by(sort_column.asc())
            else:
                base_query = base_query.order_by(Project.created_at.desc())
            
            # Get total count
            count_query = select(func.count()).select_from(base_query.subquery())
            total_result = await db.execute(count_query)
            total = total_result.scalar()
            
            # Apply pagination
            projects_query = base_query.offset(pagination.offset).limit(pagination.limit)
            result = await db.execute(projects_query)
            projects = result.scalars().all()
            
            # Convert to response models
            items = []
            for project in projects:
                # TODO: Calculate statistics (total_scans, vulnerabilities, etc.)
                project_data = {
                    "id": str(project.id),
                    "name": project.name,
                    "slug": project.slug,
                    "description": project.description,
                    "organization_id": str(project.organization_id) if project.organization_id else None,
                    "owner_id": str(project.owner_id),
                    "repository_url": project.repository_url,
                    "repository_branch": project.repository_branch,
                    "repository_type": project.repository_type,
                    "status": project.status.value,
                    "is_public": project.is_public,
                    "auto_scan_enabled": project.auto_scan_enabled,
                    "scan_schedule": project.scan_schedule,
                    "default_scan_types": project.default_scan_types,
                    "settings": project.settings,
                    "created_at": project.created_at.isoformat(),
                    "updated_at": project.updated_at.isoformat(),
                    "total_scans": 0,
                    "total_vulnerabilities": 0,
                    "critical_vulnerabilities": 0,
                    "last_scan_at": None
                }
                items.append(project_data)
            
            pages = (total + pagination.size - 1) // pagination.size
            
            return {
                "items": items,
                "total": total,
                "page": pagination.page,
                "size": pagination.size,
                "pages": pages
            }
            
        except Exception as e:
            logger.error(f"Failed to list projects: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list projects"
            )
    
    
    @router.get("/{project_id}", response_model=ProjectResponse)
    async def get_project(
        project_id: str,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Get project by ID
        
        Returns detailed project information if the user has access.
        """
        try:
            # Get project with access check
            result = await db.execute(
                select(Project)
                .where(Project.id == UUID(project_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                        # TODO: Add member-based access
                    )
                )
            )
            
            project = result.scalar_one_or_none()
            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found or access denied"
                )
            
            # TODO: Calculate statistics
            project_data = {
                "id": str(project.id),
                "name": project.name,
                "slug": project.slug,
                "description": project.description,
                "organization_id": str(project.organization_id) if project.organization_id else None,
                "owner_id": str(project.owner_id),
                "repository_url": project.repository_url,
                "repository_branch": project.repository_branch,
                "repository_type": project.repository_type,
                "status": project.status.value,
                "is_public": project.is_public,
                "auto_scan_enabled": project.auto_scan_enabled,
                "scan_schedule": project.scan_schedule,
                "default_scan_types": project.default_scan_types,
                "settings": project.settings,
                "created_at": project.created_at.isoformat(),
                "updated_at": project.updated_at.isoformat(),
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "last_scan_at": None
            }
            
            return project_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get project: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get project"
            )
    
    
    @router.put("/{project_id}", response_model=ProjectResponse)
    async def update_project(
        project_id: str,
        request: ProjectUpdateRequest,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Update project
        
        Updates project information. Only project owner or managers can update.
        """
        try:
            # Get project with ownership check
            result = await db.execute(
                select(Project)
                .where(Project.id == UUID(project_id))
                .where(Project.owner_id == current_user.id)  # Only owner can update
            )
            
            project = result.scalar_one_or_none()
            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found or insufficient permissions"
                )
            
            # Update fields
            update_data = request.dict(exclude_unset=True)
            for field, value in update_data.items():
                if hasattr(project, field):
                    setattr(project, field, value)
            
            await db.commit()
            await db.refresh(project)
            
            logger.info(f"Project updated: {project.name} by user {current_user.email}")
            
            # Convert to response
            project_data = {
                "id": str(project.id),
                "name": project.name,
                "slug": project.slug,
                "description": project.description,
                "organization_id": str(project.organization_id) if project.organization_id else None,
                "owner_id": str(project.owner_id),
                "repository_url": project.repository_url,
                "repository_branch": project.repository_branch,
                "repository_type": project.repository_type,
                "status": project.status.value,
                "is_public": project.is_public,
                "auto_scan_enabled": project.auto_scan_enabled,
                "scan_schedule": project.scan_schedule,
                "default_scan_types": project.default_scan_types,
                "settings": project.settings,
                "created_at": project.created_at.isoformat(),
                "updated_at": project.updated_at.isoformat(),
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "last_scan_at": None
            }
            
            return project_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to update project: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update project"
            )
    
    
    @router.delete("/{project_id}")
    async def delete_project(
        project_id: str,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """
        Delete project
        
        Permanently deletes a project and all associated data.
        Only project owner can delete projects.
        """
        try:
            # Get project with ownership check
            result = await db.execute(
                select(Project)
                .where(Project.id == UUID(project_id))
                .where(Project.owner_id == current_user.id)
            )
            
            project = result.scalar_one_or_none()
            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found or insufficient permissions"
                )
            
            # Delete project (cascade will handle related records)
            await db.delete(project)
            await db.commit()
            
            logger.info(f"Project deleted: {project.name} by user {current_user.email}")
            
            return {"message": "Project deleted successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete project: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete project"
            )


# =============================================================================
# 👥 PROJECT MEMBER MANAGEMENT ENDPOINTS
# =============================================================================

if router:
    
    @router.get("/{project_id}/members")
    async def list_project_members(
        project_id: str,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_database_session),
        _: None = Depends(log_request)
    ):
        """List all members of a project"""
        try:
            # Check project access
            project_result = await db.execute(
                select(Project)
                .where(Project.id == UUID(project_id))
                .where(
                    or_(
                        Project.owner_id == current_user.id,
                        Project.is_public == True,
                        # TODO: Add member-based access
                    )
                )
            )
            
            project = project_result.scalar_one_or_none()
            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found or access denied"
                )
            
            # TODO: Get project members from user_projects table
            # For now, return owner only
            owner_result = await db.execute(
                select(User).where(User.id == project.owner_id)
            )
            owner = owner_result.scalar_one()
            
            members = [{
                "user_id": str(owner.id),
                "email": owner.email,
                "username": owner.username,
                "full_name": owner.full_name,
                "role": "owner",
                "joined_at": project.created_at.isoformat()
            }]
            
            return members
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to list project members: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to list project members"
            )


# Export router
__all__ = ["router"] if router else []