"""
❤️ SecureScan Framework - Health Check System

This module provides comprehensive health checking for all application components
including database, Redis, Elasticsearch, external scanners, and system resources.

Features:
- Database connectivity checks
- Redis connection validation
- Elasticsearch cluster health
- Scanner availability verification
- System resource monitoring
- Dependency status tracking
- Graceful degradation handling

Author: SecureScan Team
"""

import asyncio
import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import asyncpg
import redis
import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("securescan.health")


class HealthCheckResult:
    """Represents the result of a single health check"""
    
    def __init__(
        self,
        name: str,
        status: str,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None
    ):
        self.name = name
        self.status = status  # "healthy", "unhealthy", "degraded"
        self.message = message
        self.details = details or {}
        self.duration_ms = duration_ms
        self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp
        }
    
    @property
    def is_healthy(self) -> bool:
        """Check if this component is healthy"""
        return self.status == "healthy"


class HealthChecker:
    """Comprehensive health checking system"""
    
    def __init__(self):
        self.settings = get_settings()
        self.timeout = self.settings.HEALTH_CHECK_TIMEOUT
    
    async def check_all(self) -> Dict[str, Any]:
        """
        Perform all health checks and return comprehensive status
        
        Returns:
            Dict containing overall status and individual check results
        """
        start_time = time.time()
        
        # Perform all checks concurrently
        checks = await asyncio.gather(
            self.check_database(),
            self.check_redis(),
            self.check_elasticsearch(),
            self.check_scanners(),
            self.check_system_resources(),
            return_exceptions=True
        )
        
        # Process results
        results = []
        healthy_count = 0
        
        for check in checks:
            if isinstance(check, Exception):
                # Handle check that raised an exception
                results.append(HealthCheckResult(
                    name="unknown",
                    status="unhealthy",
                    message=f"Health check failed: {str(check)}"
                ))
            else:
                results.append(check)
                if check.is_healthy:
                    healthy_count += 1
        
        # Determine overall status
        total_checks = len(results)
        if healthy_count == total_checks:
            overall_status = "healthy"
        elif healthy_count > 0:
            overall_status = "degraded"
        else:
            overall_status = "unhealthy"
        
        # Calculate total duration
        total_duration = (time.time() - start_time) * 1000
        
        return {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": total_duration,
            "checks": [result.to_dict() for result in results],
            "summary": {
                "total": total_checks,
                "healthy": healthy_count,
                "unhealthy": total_checks - healthy_count,
                "uptime_seconds": self._get_uptime()
            }
        }
    
    async def check_database(self) -> HealthCheckResult:
        """Check PostgreSQL database connectivity and performance"""
        start_time = time.time()
        
        try:
            # Create async engine for health check
            engine = create_async_engine(
                self.settings.get_database_url().replace("postgresql://", "postgresql+asyncpg://"),
                pool_timeout=5,
                pool_recycle=300
            )
            
            async with engine.begin() as conn:
                # Test basic connectivity
                result = await conn.execute(text("SELECT 1"))
                assert result.scalar() == 1
                
                # Test database-specific queries
                version_result = await conn.execute(text("SELECT version()"))
                version = version_result.scalar()
                
                # Check table existence
                tables_result = await conn.execute(text("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """))
                table_count = tables_result.scalar()
            
            await engine.dispose()
            
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                name="database",
                status="healthy",
                message="Database connection successful",
                details={
                    "version": version.split()[1] if version else "unknown",
                    "tables": table_count,
                    "connection_pool": "active"
                },
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Database health check failed", error=str(e))
            
            return HealthCheckResult(
                name="database",
                status="unhealthy",
                message=f"Database connection failed: {str(e)}",
                duration_ms=duration_ms
            )
    
    async def check_redis(self) -> HealthCheckResult:
        """Check Redis connectivity and performance"""
        start_time = time.time()
        
        try:
            # Parse Redis URL
            redis_url = self.settings.REDIS_URL
            redis_client = redis.from_url(redis_url, socket_timeout=5)
            
            # Test basic operations
            await asyncio.get_event_loop().run_in_executor(
                None, redis_client.ping
            )
            
            # Test set/get operations
            test_key = "health_check_test"
            test_value = str(int(time.time()))
            
            await asyncio.get_event_loop().run_in_executor(
                None, redis_client.set, test_key, test_value, 10  # 10 second TTL
            )
            
            stored_value = await asyncio.get_event_loop().run_in_executor(
                None, redis_client.get, test_key
            )
            
            assert stored_value.decode() == test_value
            
            # Get Redis info
            info = await asyncio.get_event_loop().run_in_executor(
                None, redis_client.info
            )
            
            redis_client.close()
            
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                name="redis",
                status="healthy",
                message="Redis connection successful",
                details={
                    "version": info.get("redis_version", "unknown"),
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory_human": info.get("used_memory_human", "unknown"),
                    "uptime_in_seconds": info.get("uptime_in_seconds", 0)
                },
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Redis health check failed", error=str(e))
            
            return HealthCheckResult(
                name="redis",
                status="unhealthy",
                message=f"Redis connection failed: {str(e)}",
                duration_ms=duration_ms
            )
    
    async def check_elasticsearch(self) -> HealthCheckResult:
        """Check Elasticsearch cluster health"""
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Check cluster health
                health_response = await client.get(
                    f"{self.settings.ELASTICSEARCH_URL}/_cluster/health"
                )
                health_response.raise_for_status()
                health_data = health_response.json()
                
                # Get cluster info
                info_response = await client.get(
                    f"{self.settings.ELASTICSEARCH_URL}/"
                )
                info_response.raise_for_status()
                info_data = info_response.json()
            
            duration_ms = (time.time() - start_time) * 1000
            
            es_status = health_data.get("status", "red")
            is_healthy = es_status in ["green", "yellow"]
            
            return HealthCheckResult(
                name="elasticsearch",
                status="healthy" if is_healthy else "unhealthy",
                message=f"Elasticsearch cluster status: {es_status}",
                details={
                    "cluster_name": health_data.get("cluster_name", "unknown"),
                    "status": es_status,
                    "number_of_nodes": health_data.get("number_of_nodes", 0),
                    "number_of_data_nodes": health_data.get("number_of_data_nodes", 0),
                    "version": info_data.get("version", {}).get("number", "unknown")
                },
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Elasticsearch health check failed", error=str(e))
            
            return HealthCheckResult(
                name="elasticsearch",
                status="unhealthy",
                message=f"Elasticsearch connection failed: {str(e)}",
                duration_ms=duration_ms
            )
    
    async def check_scanners(self) -> HealthCheckResult:
        """Check availability of security scanners"""
        start_time = time.time()
        
        try:
            from app.scanners.manager import ScannerManager
            
            scanner_manager = ScannerManager()
            scanner_status = await scanner_manager.check_scanner_health()
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Count available scanners
            available_scanners = sum(1 for status in scanner_status.values() if status.get("available", False))
            total_scanners = len(scanner_status)
            
            if available_scanners == total_scanners:
                status = "healthy"
                message = f"All {total_scanners} scanners available"
            elif available_scanners > 0:
                status = "degraded"
                message = f"{available_scanners}/{total_scanners} scanners available"
            else:
                status = "unhealthy"
                message = "No scanners available"
            
            return HealthCheckResult(
                name="scanners",
                status=status,
                message=message,
                details={
                    "available": available_scanners,
                    "total": total_scanners,
                    "scanners": scanner_status
                },
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Scanner health check failed", error=str(e))
            
            return HealthCheckResult(
                name="scanners",
                status="unhealthy",
                message=f"Scanner check failed: {str(e)}",
                duration_ms=duration_ms
            )
    
    async def check_system_resources(self) -> HealthCheckResult:
        """Check system resource availability"""
        start_time = time.time()
        
        try:
            import psutil
            
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Get disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Get network stats (if available)
            try:
                network = psutil.net_io_counters()
                network_stats = {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv
                }
            except:
                network_stats = {}
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Determine status based on resource usage
            critical_threshold = 90
            warning_threshold = 80
            
            if cpu_percent > critical_threshold or memory_percent > critical_threshold or disk_percent > critical_threshold:
                status = "unhealthy"
                message = "Critical resource usage detected"
            elif cpu_percent > warning_threshold or memory_percent > warning_threshold or disk_percent > warning_threshold:
                status = "degraded"
                message = "High resource usage detected"
            else:
                status = "healthy"
                message = "System resources normal"
            
            return HealthCheckResult(
                name="system_resources",
                status=status,
                message=message,
                details={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_percent,
                    "memory_total_gb": round(memory.total / (1024**3), 2),
                    "memory_available_gb": round(memory.available / (1024**3), 2),
                    "disk_percent": disk_percent,
                    "disk_total_gb": round(disk.total / (1024**3), 2),
                    "disk_free_gb": round(disk.free / (1024**3), 2),
                    "network": network_stats
                },
                duration_ms=duration_ms
            )
            
        except ImportError:
            # psutil not available - basic check
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                name="system_resources",
                status="degraded",
                message="Limited system monitoring (psutil not available)",
                duration_ms=duration_ms
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("System resource check failed", error=str(e))
            
            return HealthCheckResult(
                name="system_resources",
                status="unhealthy",
                message=f"System resource check failed: {str(e)}",
                duration_ms=duration_ms
            )
    
    def _get_uptime(self) -> float:
        """Get application uptime in seconds"""
        try:
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            return time.time() - process.create_time()
        except:
            # Fallback to a simple timestamp if psutil is not available
            if not hasattr(self, '_start_time'):
                self._start_time = time.time()
            return time.time() - self._start_time


# =============================================================================
# 🔧 HEALTH CHECK UTILITIES
# =============================================================================

async def is_service_healthy(service_name: str) -> bool:
    """
    Quick check if a specific service is healthy
    
    Args:
        service_name: Name of the service to check
        
    Returns:
        bool: True if service is healthy
    """
    health_checker = HealthChecker()
    
    check_methods = {
        "database": health_checker.check_database,
        "redis": health_checker.check_redis,
        "elasticsearch": health_checker.check_elasticsearch,
        "scanners": health_checker.check_scanners,
        "system": health_checker.check_system_resources
    }
    
    check_method = check_methods.get(service_name)
    if not check_method:
        return False
    
    try:
        result = await check_method()
        return result.is_healthy
    except Exception:
        return False


async def wait_for_service(service_name: str, timeout: int = 60, interval: int = 5) -> bool:
    """
    Wait for a service to become healthy
    
    Args:
        service_name: Name of the service to wait for
        timeout: Maximum time to wait in seconds
        interval: Check interval in seconds
        
    Returns:
        bool: True if service became healthy within timeout
    """
    logger.info(f"Waiting for {service_name} to become healthy...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        if await is_service_healthy(service_name):
            logger.info(f"{service_name} is healthy")
            return True
        
        await asyncio.sleep(interval)
    
    logger.error(f"{service_name} did not become healthy within {timeout} seconds")
    return False


# Export health checking components
__all__ = [
    "HealthChecker",
    "HealthCheckResult",
    "is_service_healthy",
    "wait_for_service"
]