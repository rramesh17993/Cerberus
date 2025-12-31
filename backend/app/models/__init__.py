"""
📊 SecureScan Framework - Database Models

This module defines all SQLAlchemy database models for the SecureScan Framework:
- User management and authentication
- Project and organization management
- Scan execution and results
- Vulnerability tracking and remediation
- API key and permission management

Features:
- Comprehensive user and role management
- Project-based access control
- Detailed scan execution tracking
- Vulnerability lifecycle management
- Audit trails and compliance tracking
- Flexible metadata storage

Author: SecureScan Team
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from enum import Enum as PyEnum

try:
    from sqlalchemy import (
        Column, String, Integer, DateTime, Boolean, Text, JSON, 
        ForeignKey, Table, Index, UniqueConstraint, CheckConstraint,
        Enum, Float, LargeBinary
    )
    from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
    from sqlalchemy.orm import relationship, validates
    from sqlalchemy.sql import func
    from sqlalchemy.ext.hybrid import hybrid_property
except ImportError:
    # Graceful fallback for development
    Column = String = Integer = DateTime = Boolean = Text = JSON = None
    ForeignKey = Table = Index = UniqueConstraint = CheckConstraint = None
    Enum = Float = LargeBinary = UUID = ARRAY = JSONB = None
    relationship = validates = func = hybrid_property = None

from app.core.database import Base


# =============================================================================
# 🔢 ENUMS AND CONSTANTS
# =============================================================================

class UserRole(PyEnum):
    """User roles in the system"""
    ADMIN = "admin"
    MANAGER = "manager"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class UserStatus(PyEnum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class ProjectStatus(PyEnum):
    """Project status"""
    ACTIVE = "active"
    ARCHIVED = "archived"
    MAINTENANCE = "maintenance"


class ScanType(PyEnum):
    """Types of security scans"""
    SAST = "sast"  # Static Application Security Testing
    DAST = "dast"  # Dynamic Application Security Testing
    SCA = "sca"    # Software Composition Analysis
    SECRETS = "secrets"  # Secret Detection
    IAC = "iac"    # Infrastructure as Code
    CONTAINER = "container"  # Container Security
    FULL = "full"  # All scan types


class ScanStatus(PyEnum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class VulnerabilitySeverity(PyEnum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(PyEnum):
    """Vulnerability remediation status"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    DUPLICATE = "duplicate"


# =============================================================================
# 🔗 ASSOCIATION TABLES
# =============================================================================

# Many-to-many relationship between users and projects
user_projects = Table(
    'user_projects',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('project_id', UUID(as_uuid=True), ForeignKey('projects.id'), primary_key=True),
    Column('role', Enum(UserRole), nullable=False, default=UserRole.VIEWER),
    Column('created_at', DateTime(timezone=True), server_default=func.now()),
) if Column else None

# Many-to-many relationship between projects and scan configurations
project_scan_configs = Table(
    'project_scan_configs',
    Base.metadata,
    Column('project_id', UUID(as_uuid=True), ForeignKey('projects.id'), primary_key=True),
    Column('scan_config_id', UUID(as_uuid=True), ForeignKey('scan_configurations.id'), primary_key=True),
    Column('is_default', Boolean, default=False),
    Column('created_at', DateTime(timezone=True), server_default=func.now()),
) if Column else None


# =============================================================================
# 👤 USER MANAGEMENT MODELS
# =============================================================================

class User(Base):
    """User account model with authentication and authorization"""
    
    __tablename__ = 'users'
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    
    # Authentication
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Profile information
    first_name = Column(String(100))
    last_name = Column(String(100))
    avatar_url = Column(String(500))
    timezone = Column(String(50), default='UTC')
    
    # Authorization
    role = Column(Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    status = Column(Enum(UserStatus), nullable=False, default=UserStatus.PENDING)
    
    # Security
    last_login = Column(DateTime(timezone=True))
    login_count = Column(Integer, default=0)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
    password_changed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    
    # Preferences and settings
    preferences = Column(JSONB, default=dict)
    
    # Relationships
    created_projects = relationship("Project", back_populates="owner", foreign_keys="Project.owner_id")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="created_by_user")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    # Many-to-many relationships
    projects = relationship(
        "Project",
        secondary=user_projects,
        back_populates="members"
    ) if relationship else None
    
    # Constraints and indexes
    __table_args__ = (
        Index('idx_user_email_status', 'email', 'status'),
        Index('idx_user_role_active', 'role', 'is_active'),
        CheckConstraint('email ~ \'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$\'', name='valid_email'),
    ) if Index else tuple()
    
    @hybrid_property
    def full_name(self) -> str:
        """Get user's full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format"""
        import re
        if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
            raise ValueError("Invalid email format")
        return email.lower()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary"""
        return {
            'id': str(self.id),
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'role': self.role.value if self.role else None,
            'status': self.status.value if self.status else None,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }


class APIKey(Base):
    """API key for programmatic access"""
    
    __tablename__ = 'api_keys'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Key information
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    prefix = Column(String(10), nullable=False)  # First few characters for identification
    
    # Access control
    scopes = Column(ARRAY(String), default=[])  # List of permitted scopes
    is_active = Column(Boolean, default=True)
    
    # Usage tracking
    last_used = Column(DateTime(timezone=True))
    usage_count = Column(Integer, default=0)
    
    # Expiration
    expires_at = Column(DateTime(timezone=True))
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    __table_args__ = (
        Index('idx_api_key_user_active', 'user_id', 'is_active'),
        Index('idx_api_key_prefix', 'prefix'),
    ) if Index else tuple()


# =============================================================================
# 📁 PROJECT MANAGEMENT MODELS
# =============================================================================

class Organization(Base):
    """Organization model for multi-tenancy"""
    
    __tablename__ = 'organizations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    
    # Configuration
    settings = Column(JSONB, default=dict)
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    projects = relationship("Project", back_populates="organization")


class Project(Base):
    """Project model for organizing scans and vulnerabilities"""
    
    __tablename__ = 'projects'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Organization
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'))
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Repository information
    repository_url = Column(String(500))
    repository_branch = Column(String(100), default='main')
    repository_type = Column(String(50))  # git, svn, etc.
    
    # Project configuration
    status = Column(Enum(ProjectStatus), default=ProjectStatus.ACTIVE)
    is_public = Column(Boolean, default=False)
    
    # Scan configuration
    auto_scan_enabled = Column(Boolean, default=False)
    scan_schedule = Column(String(100))  # Cron expression
    default_scan_types = Column(ARRAY(String), default=[])
    
    # Settings and metadata
    settings = Column(JSONB, default=dict)
    metadata = Column(JSONB, default=dict)
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="projects")
    owner = relationship("User", back_populates="created_projects", foreign_keys=[owner_id])
    scan_results = relationship("ScanResult", back_populates="project", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="project", cascade="all, delete-orphan")
    
    # Many-to-many relationships
    members = relationship(
        "User",
        secondary=user_projects,
        back_populates="projects"
    ) if relationship else None
    
    scan_configurations = relationship(
        "ScanConfiguration",
        secondary=project_scan_configs,
        back_populates="projects"
    ) if relationship else None
    
    __table_args__ = (
        UniqueConstraint('organization_id', 'slug', name='uq_project_org_slug'),
        Index('idx_project_owner_status', 'owner_id', 'status'),
        Index('idx_project_org_status', 'organization_id', 'status'),
    ) if UniqueConstraint else tuple()


# =============================================================================
# 🔍 SCAN EXECUTION MODELS
# =============================================================================

class ScanConfiguration(Base):
    """Scan configuration templates"""
    
    __tablename__ = 'scan_configurations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Configuration details
    scan_types = Column(ARRAY(String), nullable=False)  # List of ScanType values
    scanner_configs = Column(JSONB, default=dict)  # Scanner-specific configurations
    
    # Scheduling
    is_template = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    projects = relationship(
        "Project",
        secondary=project_scan_configs,
        back_populates="scan_configurations"
    ) if relationship else None


class ScanResult(Base):
    """Scan execution results and metadata"""
    
    __tablename__ = 'scan_results'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey('projects.id'), nullable=False)
    
    # Scan metadata
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    
    # Execution details
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    
    # Scanner information
    scanner_name = Column(String(100))
    scanner_version = Column(String(50))
    scanner_config = Column(JSONB, default=dict)
    
    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Files and artifacts
    sarif_report = Column(JSONB)  # SARIF format results
    raw_output = Column(Text)  # Raw scanner output
    log_output = Column(Text)  # Execution logs
    
    # Git information
    commit_hash = Column(String(40))
    branch = Column(String(100))
    commit_message = Column(Text)
    
    # Triggering information
    trigger_type = Column(String(50))  # manual, scheduled, webhook, api
    triggered_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    
    # Error handling
    error_message = Column(Text)
    exit_code = Column(Integer)
    
    # Metadata
    metadata = Column(JSONB, default=dict)
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project", back_populates="scan_results")
    created_by_user = relationship("User", back_populates="scan_results")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_result", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_scan_result_project_status', 'project_id', 'status'),
        Index('idx_scan_result_project_type', 'project_id', 'scan_type'),
        Index('idx_scan_result_created', 'created_at'),
    ) if Index else tuple()


# =============================================================================
# 🐛 VULNERABILITY MANAGEMENT MODELS
# =============================================================================

class Vulnerability(Base):
    """Individual vulnerability findings"""
    
    __tablename__ = 'vulnerabilities'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey('projects.id'), nullable=False)
    scan_result_id = Column(UUID(as_uuid=True), ForeignKey('scan_results.id'), nullable=False)
    
    # Vulnerability identification
    rule_id = Column(String(200))  # Scanner-specific rule ID
    cwe_id = Column(String(20))   # Common Weakness Enumeration ID
    cve_id = Column(String(30))   # Common Vulnerabilities and Exposures ID
    
    # Vulnerability details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(VulnerabilitySeverity), nullable=False)
    confidence = Column(String(20))  # high, medium, low
    
    # Location information
    file_path = Column(String(1000))
    line_number = Column(Integer)
    column_number = Column(Integer)
    code_snippet = Column(Text)
    
    # Classification
    category = Column(String(100))  # OWASP category, etc.
    subcategory = Column(String(100))
    tags = Column(ARRAY(String), default=[])
    
    # Remediation
    status = Column(Enum(VulnerabilityStatus), default=VulnerabilityStatus.OPEN)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    due_date = Column(DateTime(timezone=True))
    
    # Resolution tracking
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    resolution_comment = Column(Text)
    
    # False positive handling
    is_false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(Text)
    
    # Risk assessment
    exploitability = Column(String(20))  # high, medium, low
    impact = Column(String(20))         # high, medium, low
    risk_score = Column(Float)          # Calculated risk score
    
    # SARIF compliance
    sarif_result = Column(JSONB)  # Full SARIF result object
    
    # Metadata and tracking
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    occurrence_count = Column(Integer, default=1)
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("Project", back_populates="vulnerabilities")
    scan_result = relationship("ScanResult", back_populates="vulnerabilities")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    resolved_user = relationship("User", foreign_keys=[resolved_by])
    
    __table_args__ = (
        Index('idx_vulnerability_project_status', 'project_id', 'status'),
        Index('idx_vulnerability_severity_status', 'severity', 'status'),
        Index('idx_vulnerability_assigned', 'assigned_to'),
        Index('idx_vulnerability_scan_result', 'scan_result_id'),
        Index('idx_vulnerability_cwe', 'cwe_id'),
        Index('idx_vulnerability_cve', 'cve_id'),
    ) if Index else tuple()


# =============================================================================
# 📊 AUDIT AND COMPLIANCE MODELS
# =============================================================================

class AuditLog(Base):
    """Audit trail for all system actions"""
    
    __tablename__ = 'audit_logs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Event details
    event_type = Column(String(100), nullable=False)  # login, scan_start, vulnerability_update, etc.
    event_category = Column(String(50), nullable=False)  # auth, scan, vulnerability, system
    description = Column(Text)
    
    # Actor information
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    user_email = Column(String(255))  # Denormalized for deleted users
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(String(1000))
    
    # Target information
    resource_type = Column(String(100))  # project, vulnerability, user, etc.
    resource_id = Column(String(100))    # ID of the affected resource
    
    # Request details
    http_method = Column(String(10))
    endpoint = Column(String(500))
    request_data = Column(JSONB)  # Sanitized request data
    
    # Response details
    status_code = Column(Integer)
    success = Column(Boolean)
    
    # Additional metadata
    metadata = Column(JSONB, default=dict)
    
    # Timing
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    __table_args__ = (
        Index('idx_audit_log_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_audit_log_event_timestamp', 'event_type', 'timestamp'),
        Index('idx_audit_log_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_log_timestamp', 'timestamp'),
    ) if Index else tuple()


# =============================================================================
# ⚙️ SYSTEM CONFIGURATION MODELS
# =============================================================================

class SystemConfiguration(Base):
    """System-wide configuration settings"""
    
    __tablename__ = 'system_configurations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Configuration details
    key = Column(String(200), unique=True, nullable=False)
    value = Column(JSONB)
    description = Column(Text)
    
    # Metadata
    category = Column(String(100))  # security, scanning, notifications, etc.
    is_sensitive = Column(Boolean, default=False)  # Whether value should be encrypted
    is_system = Column(Boolean, default=False)     # System vs user configurable
    
    # Validation
    value_type = Column(String(50))  # string, integer, boolean, json, etc.
    validation_rules = Column(JSONB)  # Validation rules for the value
    
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    
    __table_args__ = (
        Index('idx_system_config_category', 'category'),
        Index('idx_system_config_system', 'is_system'),
    ) if Index else tuple()


# Export all models
if Base:
    __all__ = [
        "Base",
        "User", "APIKey",
        "Organization", "Project",
        "ScanConfiguration", "ScanResult",
        "Vulnerability",
        "AuditLog", "SystemConfiguration",
        "UserRole", "UserStatus", "ProjectStatus",
        "ScanType", "ScanStatus",
        "VulnerabilitySeverity", "VulnerabilityStatus"
    ]
else:
    __all__ = [
        "UserRole", "UserStatus", "ProjectStatus",
        "ScanType", "ScanStatus",
        "VulnerabilitySeverity", "VulnerabilityStatus"
    ]