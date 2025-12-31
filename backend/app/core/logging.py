"""
📊 SecureScan Framework - Structured Logging Configuration

This module sets up structured logging for the entire application using structlog.
It provides consistent, searchable, and analyzable logs for debugging, monitoring,
and audit purposes.

Features:
- Structured JSON logging for production
- Human-readable colored logs for development
- Request correlation IDs
- Performance metrics
- Security event logging
- Integration with external log aggregators

Author: SecureScan Team
"""

import logging
import logging.config
import sys
from typing import Any, Dict

import structlog
from structlog.types import EventDict

from app.core.config import get_settings


def add_correlation_id(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add correlation ID to log events for request tracing
    
    Args:
        logger: The logger instance
        method_name: The method name being called
        event_dict: The event dictionary
        
    Returns:
        EventDict: Updated event dictionary with correlation ID
    """
    # Try to get correlation ID from context (set by middleware)
    import contextvars
    
    correlation_id = getattr(contextvars, 'correlation_id', None)
    if correlation_id:
        event_dict['correlation_id'] = correlation_id.get()
    
    return event_dict


def add_severity_level(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add severity level mapping for better log analysis
    
    Args:
        logger: The logger instance
        method_name: The method name being called
        event_dict: The event dictionary
        
    Returns:
        EventDict: Updated event dictionary with severity
    """
    level_map = {
        'debug': 'DEBUG',
        'info': 'INFO',
        'warning': 'WARN',
        'error': 'ERROR',
        'critical': 'FATAL'
    }
    
    level = event_dict.get('level', 'info')
    event_dict['severity'] = level_map.get(level, 'INFO')
    
    return event_dict


def add_app_context(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add application context to all log events
    
    Args:
        logger: The logger instance
        method_name: The method name being called
        event_dict: The event dictionary
        
    Returns:
        EventDict: Updated event dictionary with app context
    """
    settings = get_settings()
    
    event_dict.update({
        'app': settings.APP_NAME,
        'version': settings.APP_VERSION,
        'environment': settings.ENVIRONMENT,
        'service': 'securescan-backend'
    })
    
    return event_dict


def setup_logging() -> None:
    """
    Configure structured logging for the application
    
    This function sets up:
    - JSON logging for production environments
    - Colored console logging for development
    - Appropriate log levels
    - Request correlation
    - Performance tracking
    """
    
    settings = get_settings()
    
    # Determine if we're in development mode
    is_development = settings.is_development()
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        add_correlation_id,
        add_severity_level,
        add_app_context,
    ]
    
    if is_development:
        # Development: Pretty console output with colors
        processors.extend([
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=True)
        ])
    else:
        # Production: JSON output for log aggregation
        processors.extend([
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ])
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
            'json': {
                'format': '%(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': settings.LOG_LEVEL,
                'class': 'logging.StreamHandler',
                'formatter': 'json' if not is_development else 'standard',
                'stream': sys.stdout
            }
        },
        'loggers': {
            '': {  # Root logger
                'handlers': ['console'],
                'level': settings.LOG_LEVEL,
                'propagate': False
            },
            'uvicorn': {
                'handlers': ['console'],
                'level': 'INFO',
                'propagate': False
            },
            'uvicorn.access': {
                'handlers': ['console'],
                'level': 'INFO' if is_development else 'WARNING',
                'propagate': False
            },
            'sqlalchemy.engine': {
                'handlers': ['console'],
                'level': 'WARNING',  # Reduce SQL query noise
                'propagate': False
            },
            'celery': {
                'handlers': ['console'],
                'level': 'INFO',
                'propagate': False
            },
            'docker': {
                'handlers': ['console'],
                'level': 'WARNING',  # Reduce Docker API noise
                'propagate': False
            }
        }
    }
    
    # Add file handler if specified
    if settings.LOG_FILE:
        logging_config['handlers']['file'] = {
            'level': settings.LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': settings.LOG_FILE,
            'maxBytes': 10 * 1024 * 1024,  # 10MB
            'backupCount': 5,
            'formatter': 'json'
        }
        
        # Add file handler to all loggers
        for logger_config in logging_config['loggers'].values():
            logger_config['handlers'].append('file')
    
    # Apply logging configuration
    logging.config.dictConfig(logging_config)
    
    # Create application logger
    logger = structlog.get_logger("securescan.setup")
    logger.info(
        "Logging configured",
        level=settings.LOG_LEVEL,
        format=settings.LOG_FORMAT,
        environment=settings.ENVIRONMENT,
        file_logging=bool(settings.LOG_FILE)
    )


def get_logger(name: str = "securescan") -> structlog.BoundLogger:
    """
    Get a structured logger instance
    
    Args:
        name: Logger name (usually module name)
        
    Returns:
        structlog.BoundLogger: Configured logger instance
    """
    return structlog.get_logger(name)


# =============================================================================
# 🛡️ SECURITY LOGGING HELPERS
# =============================================================================

def log_security_event(
    event_type: str,
    user_id: str = None,
    ip_address: str = None,
    user_agent: str = None,
    details: Dict[str, Any] = None,
    severity: str = "info"
) -> None:
    """
    Log security-related events for audit purposes
    
    Args:
        event_type: Type of security event (login, logout, scan_start, etc.)
        user_id: User ID associated with the event
        ip_address: Client IP address
        user_agent: Client user agent
        details: Additional event details
        severity: Log severity level
    """
    logger = get_logger("securescan.security")
    
    event_data = {
        "event_type": event_type,
        "security_event": True,
        "timestamp": structlog.processors.TimeStamper(fmt="iso")
    }
    
    if user_id:
        event_data["user_id"] = user_id
    if ip_address:
        event_data["ip_address"] = ip_address
    if user_agent:
        event_data["user_agent"] = user_agent
    if details:
        event_data["details"] = details
    
    # Log at appropriate level
    log_func = getattr(logger, severity.lower(), logger.info)
    log_func("Security event", **event_data)


def log_scan_event(
    scan_id: str,
    project_id: str,
    event_type: str,
    scanner_type: str = None,
    duration: float = None,
    vulnerability_count: int = None,
    status: str = None,
    error: str = None
) -> None:
    """
    Log scan-related events for monitoring and analytics
    
    Args:
        scan_id: Unique scan identifier
        project_id: Project identifier
        event_type: Type of scan event (started, completed, failed, etc.)
        scanner_type: Type of scanner used
        duration: Scan duration in seconds
        vulnerability_count: Number of vulnerabilities found
        status: Scan status
        error: Error message if scan failed
    """
    logger = get_logger("securescan.scans")
    
    event_data = {
        "scan_id": scan_id,
        "project_id": project_id,
        "event_type": event_type,
        "scan_event": True
    }
    
    if scanner_type:
        event_data["scanner_type"] = scanner_type
    if duration is not None:
        event_data["duration_seconds"] = duration
    if vulnerability_count is not None:
        event_data["vulnerability_count"] = vulnerability_count
    if status:
        event_data["status"] = status
    if error:
        event_data["error"] = error
        logger.error("Scan event", **event_data)
    else:
        logger.info("Scan event", **event_data)


def log_performance_metric(
    operation: str,
    duration: float,
    metadata: Dict[str, Any] = None
) -> None:
    """
    Log performance metrics for monitoring
    
    Args:
        operation: Name of the operation
        duration: Operation duration in seconds
        metadata: Additional metadata about the operation
    """
    logger = get_logger("securescan.performance")
    
    event_data = {
        "operation": operation,
        "duration_seconds": duration,
        "performance_metric": True
    }
    
    if metadata:
        event_data.update(metadata)
    
    logger.info("Performance metric", **event_data)


# Export logging functions
__all__ = [
    "setup_logging",
    "get_logger", 
    "log_security_event",
    "log_scan_event",
    "log_performance_metric"
]