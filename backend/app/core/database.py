"""
🗄️ SecureScan Framework - Database Module

This module provides comprehensive database management including:
- SQLAlchemy async setup and configuration
- Database connection pooling and health monitoring
- Migration utilities and schema management
- Connection lifecycle management
- Performance monitoring and optimization

Features:
- Async PostgreSQL connectivity with connection pooling
- Automatic reconnection and error handling
- Database health monitoring
- Migration support with Alembic
- Performance metrics and query logging
- Connection context managers

Author: SecureScan Team
"""

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy import event, pool
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("securescan.database")


# =============================================================================
# 📊 DATABASE BASE MODEL
# =============================================================================

class Base(DeclarativeBase):
    """Base class for all database models"""
    pass


# =============================================================================
# 🔌 DATABASE CONNECTION MANAGER
# =============================================================================

class DatabaseManager:
    """
    Manages database connections, sessions, and health monitoring
    
    Features:
    - Connection pooling with configurable parameters
    - Automatic reconnection on connection failures
    - Health monitoring and metrics collection
    - Session lifecycle management
    - Migration utilities
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker] = None
        self._connection_metrics = {
            "total_connections": 0,
            "active_connections": 0,
            "failed_connections": 0,
            "total_queries": 0,
            "failed_queries": 0,
            "avg_query_time_ms": 0.0
        }
    
    async def initialize(self) -> None:
        """Initialize database engine and connection pool"""
        try:
            # Create async engine with connection pooling
            database_url = self.settings.get_database_url()
            
            # Convert psycopg2 URL to asyncpg URL
            if database_url.startswith("postgresql://"):
                database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
            
            # Configure connection pool
            pool_class = QueuePool if self.settings.DATABASE_POOL_SIZE > 0 else NullPool
            
            self.engine = create_async_engine(
                database_url,
                poolclass=pool_class,
                pool_size=self.settings.DATABASE_POOL_SIZE,
                max_overflow=self.settings.DATABASE_MAX_OVERFLOW,
                pool_timeout=self.settings.DATABASE_POOL_TIMEOUT,
                pool_recycle=self.settings.DATABASE_POOL_RECYCLE,
                pool_pre_ping=True,  # Validate connections before use
                echo=self.settings.DATABASE_ECHO,  # Log SQL queries in debug mode
                echo_pool=self.settings.DEBUG,  # Log pool events in debug mode
            )
            
            # Create session factory
            self.session_factory = async_sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autocommit=False,
                autoflush=False
            )
            
            # Set up event listeners for monitoring
            self._setup_event_listeners()
            
            # Test connection
            await self.test_connection()
            
            logger.info(
                "Database initialized successfully",
                pool_size=self.settings.DATABASE_POOL_SIZE,
                max_overflow=self.settings.DATABASE_MAX_OVERFLOW
            )
            
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
            raise
    
    async def close(self) -> None:
        """Close database engine and all connections"""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connections closed")
    
    async def test_connection(self) -> bool:
        """Test database connectivity"""
        try:
            async with self.engine.begin() as conn:
                result = await conn.execute("SELECT 1")
                assert result.scalar() == 1
            
            logger.info("Database connection test successful")
            return True
            
        except Exception as e:
            logger.error("Database connection test failed", error=str(e))
            return False
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get a database session with automatic cleanup
        
        Usage:
            async with db_manager.get_session() as session:
                # Use session here
                pass
        """
        if not self.session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        session = self.session_factory()
        try:
            self._connection_metrics["active_connections"] += 1
            yield session
            await session.commit()
            
        except Exception as e:
            await session.rollback()
            logger.error("Database session error", error=str(e))
            raise
            
        finally:
            await session.close()
            self._connection_metrics["active_connections"] -= 1
    
    async def get_session_direct(self) -> AsyncSession:
        """
        Get a database session without context manager
        
        Note: Caller is responsible for closing the session
        """
        if not self.session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        return self.session_factory()
    
    def _setup_event_listeners(self) -> None:
        """Set up SQLAlchemy event listeners for monitoring"""
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Handle new database connections"""
            self._connection_metrics["total_connections"] += 1
            logger.debug("New database connection established")
        
        @event.listens_for(self.engine.sync_engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            """Handle connection checkout from pool"""
            connection_record.info['checkout_time'] = time.time()
        
        @event.listens_for(self.engine.sync_engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            """Handle connection checkin to pool"""
            if 'checkout_time' in connection_record.info:
                duration = time.time() - connection_record.info['checkout_time']
                logger.debug(f"Connection used for {duration:.2f} seconds")
        
        @event.listens_for(self.engine.sync_engine, "invalidate")
        def on_invalidate(dbapi_connection, connection_record, exception):
            """Handle connection invalidation"""
            self._connection_metrics["failed_connections"] += 1
            logger.warning(
                "Database connection invalidated",
                error=str(exception) if exception else "Unknown"
            )
    
    def get_metrics(self) -> dict:
        """Get database connection metrics"""
        return self._connection_metrics.copy()
    
    async def health_check(self) -> dict:
        """Comprehensive database health check"""
        start_time = time.time()
        
        try:
            # Test basic connectivity
            connection_test = await self.test_connection()
            
            # Get pool status
            pool = self.engine.pool
            pool_status = {
                "size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "invalid": pool.invalid()
            }
            
            # Test query performance
            query_start = time.time()
            async with self.get_session() as session:
                result = await session.execute("SELECT COUNT(*) FROM information_schema.tables")
                table_count = result.scalar()
            query_duration = (time.time() - query_start) * 1000
            
            duration_ms = (time.time() - start_time) * 1000
            
            return {
                "status": "healthy" if connection_test else "unhealthy",
                "connection_test": connection_test,
                "pool_status": pool_status,
                "metrics": self.get_metrics(),
                "query_performance_ms": query_duration,
                "table_count": table_count,
                "duration_ms": duration_ms
            }
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return {
                "status": "unhealthy",
                "error": str(e),
                "duration_ms": duration_ms
            }


# =============================================================================
# 🔄 MIGRATION UTILITIES
# =============================================================================

class MigrationManager:
    """Database migration management utilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.logger = get_logger("securescan.migrations")
    
    async def create_tables(self) -> None:
        """Create all database tables"""
        try:
            # Import all models to ensure they're registered
            from app.models import *  # noqa: F401, F403
            
            async with self.db_manager.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            self.logger.info("Database tables created successfully")
            
        except Exception as e:
            self.logger.error("Failed to create database tables", error=str(e))
            raise
    
    async def drop_tables(self) -> None:
        """Drop all database tables"""
        try:
            async with self.db_manager.engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            
            self.logger.info("Database tables dropped successfully")
            
        except Exception as e:
            self.logger.error("Failed to drop database tables", error=str(e))
            raise
    
    async def check_migration_needed(self) -> bool:
        """Check if database migration is needed"""
        try:
            async with self.db_manager.get_session() as session:
                # Try to query a known table to check if schema exists
                result = await session.execute(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'users'"
                )
                table_exists = result.scalar() > 0
                
                if not table_exists:
                    return True
                
                # Additional checks can be added here for schema version
                return False
                
        except Exception:
            # If we can't check, assume migration is needed
            return True


# =============================================================================
# 🌐 GLOBAL DATABASE INSTANCE
# =============================================================================

# Global database manager instance
db_manager = DatabaseManager()


async def init_database() -> None:
    """Initialize the global database manager"""
    await db_manager.initialize()


async def close_database() -> None:
    """Close the global database manager"""
    await db_manager.close()


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session from the global manager"""
    async with db_manager.get_session() as session:
        yield session


def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance"""
    return db_manager


# =============================================================================
# 🧪 DATABASE UTILITIES
# =============================================================================

async def execute_raw_sql(sql: str, params: dict = None) -> any:
    """
    Execute raw SQL query with parameters
    
    Args:
        sql: SQL query string
        params: Query parameters
        
    Returns:
        Query result
    """
    async with get_db_session() as session:
        result = await session.execute(sql, params or {})
        return result


async def check_table_exists(table_name: str) -> bool:
    """Check if a table exists in the database"""
    sql = """
        SELECT COUNT(*) 
        FROM information_schema.tables 
        WHERE table_name = :table_name AND table_schema = 'public'
    """
    
    async with get_db_session() as session:
        result = await session.execute(sql, {"table_name": table_name})
        return result.scalar() > 0


async def get_table_info(table_name: str) -> dict:
    """Get detailed information about a table"""
    sql = """
        SELECT 
            column_name,
            data_type,
            is_nullable,
            column_default
        FROM information_schema.columns 
        WHERE table_name = :table_name AND table_schema = 'public'
        ORDER BY ordinal_position
    """
    
    async with get_db_session() as session:
        result = await session.execute(sql, {"table_name": table_name})
        columns = []
        
        for row in result:
            columns.append({
                "name": row.column_name,
                "type": row.data_type,
                "nullable": row.is_nullable == "YES",
                "default": row.column_default
            })
        
        return {
            "table_name": table_name,
            "columns": columns
        }


# Export database components
__all__ = [
    "Base",
    "DatabaseManager",
    "MigrationManager",
    "db_manager",
    "init_database",
    "close_database",
    "get_db_session",
    "get_db_manager",
    "execute_raw_sql",
    "check_table_exists",
    "get_table_info"
]