import os
import secrets
from functools import lru_cache
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseSettings, validator, Field
from pydantic.networks import AnyHttpUrl, PostgresDsn, RedisDsn


class Settings(BaseSettings):
    """
    Application settings with validation.
    """
    
    APP_NAME: str = "SecureScan Framework"
    APP_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment: development, staging, production
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="DEBUG")
    
    @validator("DEBUG", pre=True)
    def parse_debug(cls, value: Union[bool, str]) -> bool:
        if isinstance(value, str):
            return value.lower() in ("true", "1", "on", "yes")
        return value
    
    # Security Configuration
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        env="SECRET_KEY"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    ALGORITHM: str = "HS256"
    
    PWD_CONTEXT_SCHEMES: List[str] = ["bcrypt"]
    PWD_CONTEXT_DEPRECATED: str = "auto"
    
    API_KEY_HEADER: str = "X-API-Key"
    API_KEY_LENGTH: int = 32
    
    # Network & CORS
    HOST: str = Field(default="0.0.0.0", env="HOST")
    PORT: int = Field(default=8000, env="PORT")
    
    CORS_ORIGINS: List[AnyHttpUrl] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3000",
        ],
        env="CORS_ORIGINS"
    )
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, value: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(value, str) and not value.startswith("["):
            return [i.strip() for i in value.split(",")]
        elif isinstance(value, (list, str)):
            return value
        raise ValueError(value)
    
    ALLOWED_HOSTS: List[str] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0"],
        env="ALLOWED_HOSTS"
    )
    
    @validator("ALLOWED_HOSTS", pre=True)
    def assemble_allowed_hosts(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [i.strip() for i in value.split(",")]
        return value
    
    # Database
    POSTGRES_SERVER: str = Field(default="localhost", env="POSTGRES_SERVER")
    POSTGRES_USER: str = Field(default="securescan", env="POSTGRES_USER")
    POSTGRES_PASSWORD: str = Field(default="securescan_dev_password", env="POSTGRES_PASSWORD")
    POSTGRES_DB: str = Field(default="securescan", env="POSTGRES_DB")
    POSTGRES_PORT: str = Field(default="5432", env="POSTGRES_PORT")
    
    DATABASE_URL: Optional[PostgresDsn] = Field(default=None, env="DATABASE_URL")
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_connection(cls, value: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(value, str) and value:
            return value
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_SERVER"),
            port=values.get("POSTGRES_PORT"),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )
    
    DB_POOL_SIZE: int = Field(default=5, env="DB_POOL_SIZE")
    DB_MAX_OVERFLOW: int = Field(default=10, env="DB_MAX_OVERFLOW")
    DB_POOL_TIMEOUT: int = Field(default=30, env="DB_POOL_TIMEOUT")
    
    # Redis
    REDIS_HOST: str = Field(default="localhost", env="REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, env="REDIS_PORT")
    REDIS_PASSWORD: Optional[str] = Field(default="securescan_redis_password", env="REDIS_PASSWORD")
    REDIS_DB: int = Field(default=0, env="REDIS_DB")
    
    REDIS_URL: Optional[RedisDsn] = Field(default=None, env="REDIS_URL")
    
    @validator("REDIS_URL", pre=True)
    def assemble_redis_connection(cls, value: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(value, str) and value:
            return value
        
        password = values.get("REDIS_PASSWORD")
        auth_part = f":{password}@" if password else ""
        
        return f"redis://{auth_part}{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB')}"
    
    CACHE_TTL: int = Field(default=300, env="CACHE_TTL")
    CACHE_MAX_CONNECTIONS: int = Field(default=10, env="CACHE_MAX_CONNECTIONS")
    
    # Elasticsearch
    ELASTICSEARCH_HOST: str = Field(default="localhost", env="ELASTICSEARCH_HOST")
    ELASTICSEARCH_PORT: int = Field(default=9200, env="ELASTICSEARCH_PORT")
    ELASTICSEARCH_URL: str = Field(default="http://localhost:9200", env="ELASTICSEARCH_URL")
    
    ES_INDEX_PREFIX: str = Field(default="securescan", env="ES_INDEX_PREFIX")
    ES_INDEX_REPLICAS: int = Field(default=0, env="ES_INDEX_REPLICAS")
    ES_INDEX_SHARDS: int = Field(default=1, env="ES_INDEX_SHARDS")
    
    # Celery
    CELERY_ENABLED: bool = Field(default=True, env="CELERY_ENABLED")
    CELERY_BROKER_URL: Optional[str] = Field(default=None, env="CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND: Optional[str] = Field(default=None, env="CELERY_RESULT_BACKEND")
    
    @validator("CELERY_BROKER_URL", pre=True)
    def assemble_celery_broker(cls, value: Optional[str], values: Dict[str, Any]) -> str:
        if value:
            return value
        return values.get("REDIS_URL", "redis://localhost:6379/0")
    
    @validator("CELERY_RESULT_BACKEND", pre=True)
    def assemble_celery_backend(cls, value: Optional[str], values: Dict[str, Any]) -> str:
        if value:
            return value
        return values.get("REDIS_URL", "redis://localhost:6379/0")
    
    CELERY_WORKER_CONCURRENCY: int = Field(default=4, env="CELERY_WORKER_CONCURRENCY")
    CELERY_TASK_TIME_LIMIT: int = Field(default=3600, env="CELERY_TASK_TIME_LIMIT")
    CELERY_TASK_SOFT_TIME_LIMIT: int = Field(default=3300, env="CELERY_TASK_SOFT_TIME_LIMIT")
    
    # Scanner Configuration
    SCANNER_TIMEOUT: int = Field(default=1800, env="SCANNER_TIMEOUT")
    SCANNER_MAX_CONCURRENT: int = Field(default=5, env="SCANNER_MAX_CONCURRENT")
    SCANNER_DOCKER_ENABLED: bool = Field(default=True, env="SCANNER_DOCKER_ENABLED")
    
    DOCKER_HOST: Optional[str] = Field(default=None, env="DOCKER_HOST")
    DOCKER_NETWORK: str = Field(default="securescan-network", env="DOCKER_NETWORK")
    SCANNER_CACHE_DIR: str = Field(default="/tmp/securescan/cache", env="SCANNER_CACHE_DIR")
    
    ENABLED_SCANNERS: List[str] = Field(
        default=["semgrep", "trivy", "bandit", "safety", "gitleaks"],
        env="ENABLED_SCANNERS"
    )
    
    @validator("ENABLED_SCANNERS", pre=True)
    def parse_enabled_scanners(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [scanner.strip() for scanner in value.split(",")]
        return value
    
    # Monitoring & Logging
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(default="json", env="LOG_FORMAT")
    LOG_FILE: Optional[str] = Field(default=None, env="LOG_FILE")
    
    METRICS_ENABLED: bool = Field(default=True, env="METRICS_ENABLED")
    PROMETHEUS_MULTIPROC_DIR: Optional[str] = Field(default=None, env="PROMETHEUS_MULTIPROC_DIR")
    
    HEALTH_CHECK_TIMEOUT: int = Field(default=30, env="HEALTH_CHECK_TIMEOUT")
    
    # Notifications
    SMTP_TLS: bool = Field(default=True, env="SMTP_TLS")
    SMTP_PORT: Optional[int] = Field(default=587, env="SMTP_PORT")
    SMTP_HOST: Optional[str] = Field(default=None, env="SMTP_HOST")
    SMTP_USER: Optional[str] = Field(default=None, env="SMTP_USER")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    
    NOTIFICATIONS_ENABLED: bool = Field(default=False, env="NOTIFICATIONS_ENABLED")
    NOTIFICATION_CHANNELS: List[str] = Field(default=["email"], env="NOTIFICATION_CHANNELS")
    
    @validator("NOTIFICATION_CHANNELS", pre=True)
    def parse_notification_channels(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            return [channel.strip() for channel in value.split(",")]
        return value
    
    SLACK_WEBHOOK_URL: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")
    SLACK_CHANNEL: str = Field(default="#security", env="SLACK_CHANNEL")
    
    # Storage
    MAX_UPLOAD_SIZE: int = Field(default=100 * 1024 * 1024, env="MAX_UPLOAD_SIZE")
    ALLOWED_FILE_TYPES: List[str] = Field(
        default=[".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h"],
        env="ALLOWED_FILE_TYPES"
    )
    
    STORAGE_TYPE: str = Field(default="local", env="STORAGE_TYPE")
    STORAGE_PATH: str = Field(default="/tmp/securescan/storage", env="STORAGE_PATH")
    
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    AWS_REGION: str = Field(default="us-east-1", env="AWS_REGION")
    S3_BUCKET: Optional[str] = Field(default=None, env="S3_BUCKET")
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    
    API_KEY_RATE_LIMIT_REQUESTS: int = Field(default=1000, env="API_KEY_RATE_LIMIT_REQUESTS")
    API_KEY_RATE_LIMIT_WINDOW: int = Field(default=60, env="API_KEY_RATE_LIMIT_WINDOW")
    
    # Testing
    TEST_DATABASE_URL: str = Field(default="sqlite:///./test_securescan.db", env="TEST_DATABASE_URL")
    TESTING: bool = Field(default=False, env="TESTING")
    
    # Feature Flags
    FEATURE_WEBSOCKETS: bool = Field(default=True, env="FEATURE_WEBSOCKETS")
    FEATURE_ANALYTICS: bool = Field(default=True, env="FEATURE_ANALYTICS")
    FEATURE_REPORTS: bool = Field(default=True, env="FEATURE_REPORTS")
    FEATURE_NOTIFICATIONS: bool = Field(default=True, env="FEATURE_NOTIFICATIONS")
    FEATURE_API_KEYS: bool = Field(default=True, env="FEATURE_API_KEYS")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
    
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == "development"
    
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"
    
    def is_testing(self) -> bool:
        return self.TESTING or self.ENVIRONMENT.lower() == "testing"
    
    def get_database_url(self) -> str:
        if self.is_testing():
            return self.TEST_DATABASE_URL
        return str(self.DATABASE_URL)
    
    def get_scanner_config(self) -> Dict[str, Any]:
        return {
            "timeout": self.SCANNER_TIMEOUT,
            "max_concurrent": self.SCANNER_MAX_CONCURRENT,
            "docker_enabled": self.SCANNER_DOCKER_ENABLED,
            "docker_network": self.DOCKER_NETWORK,
            "cache_dir": self.SCANNER_CACHE_DIR,
            "enabled_scanners": self.ENABLED_SCANNERS
        }
    
    def get_celery_config(self) -> Dict[str, Any]:
        return {
            "broker_url": self.CELERY_BROKER_URL,
            "result_backend": self.CELERY_RESULT_BACKEND,
            "task_time_limit": self.CELERY_TASK_TIME_LIMIT,
            "task_soft_time_limit": self.CELERY_TASK_SOFT_TIME_LIMIT,
            "worker_concurrency": self.CELERY_WORKER_CONCURRENCY,
            "include": ["app.workers.tasks"]
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        return {
            "level": self.LOG_LEVEL,
            "format": self.LOG_FORMAT,
            "file": self.LOG_FILE,
            "debug": self.DEBUG
        }


@lru_cache()
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]