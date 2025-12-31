"""
🔍 SecureScan Framework - Scanner Manager

This module provides comprehensive scanner orchestration including:
- Docker-based scanner execution
- SARIF report parsing and normalization
- Scanner health monitoring
- Configuration management
- Result aggregation and correlation

Supported Scanners:
- Semgrep (SAST) - Static Application Security Testing
- Trivy (SCA) - Software Composition Analysis & Container Security
- OWASP ZAP (DAST) - Dynamic Application Security Testing
- Gitleaks (Secrets) - Secret Detection
- Checkov (IaC) - Infrastructure as Code Security

Features:
- Unified scanner interface
- SARIF compliance for all results
- Configurable scanner parameters
- Parallel scanner execution
- Docker container isolation
- Result caching and deduplication

Author: SecureScan Team
"""

import asyncio
import json
import tempfile
import shutil
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from uuid import uuid4
import tarfile

try:
    import docker
    from docker.models.containers import Container
    from docker.errors import ContainerError, ImageNotFound, APIError
except ImportError:
    docker = None
    Container = None
    ContainerError = ImageNotFound = APIError = None

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import ScanType

logger = get_logger("securescan.scanners")


# =============================================================================
# 📊 SCANNER CONFIGURATIONS
# =============================================================================

class ScannerConfig:
    """Base configuration for security scanners"""
    
    def __init__(
        self,
        name: str,
        image: str,
        scan_types: List[ScanType],
        supported_languages: List[str] = None,
        timeout: int = 300,
        memory_limit: str = "1g",
        cpu_limit: float = 1.0
    ):
        self.name = name
        self.image = image
        self.scan_types = scan_types
        self.supported_languages = supported_languages or []
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit


# Scanner configurations
SCANNER_CONFIGS = {
    "semgrep": ScannerConfig(
        name="Semgrep",
        image="returntocorp/semgrep:latest",
        scan_types=[ScanType.SAST],
        supported_languages=[
            "python", "javascript", "typescript", "java", "go", "ruby", 
            "php", "c", "cpp", "csharp", "scala", "kotlin", "swift"
        ],
        timeout=600,  # 10 minutes
        memory_limit="2g"
    ),
    
    "trivy": ScannerConfig(
        name="Trivy",
        image="aquasec/trivy:latest",
        scan_types=[ScanType.SCA, ScanType.CONTAINER],
        supported_languages=["all"],  # Language agnostic
        timeout=300,  # 5 minutes
        memory_limit="1g"
    ),
    
    "zap": ScannerConfig(
        name="OWASP ZAP",
        image="owasp/zap2docker-stable:latest",
        scan_types=[ScanType.DAST],
        supported_languages=["web"],
        timeout=1800,  # 30 minutes
        memory_limit="2g"
    ),
    
    "gitleaks": ScannerConfig(
        name="Gitleaks",
        image="zricethezav/gitleaks:latest",
        scan_types=[ScanType.SECRETS],
        supported_languages=["all"],
        timeout=180,  # 3 minutes
        memory_limit="512m"
    ),
    
    "checkov": ScannerConfig(
        name="Checkov",
        image="bridgecrew/checkov:latest",
        scan_types=[ScanType.IAC],
        supported_languages=["terraform", "cloudformation", "kubernetes", "ansible"],
        timeout=300,  # 5 minutes
        memory_limit="1g"
    )
}


# =============================================================================
# 🔧 SCANNER RESULT MODELS
# =============================================================================

class ScannerResult:
    """Standardized scanner result"""
    
    def __init__(
        self,
        scanner_name: str,
        scan_type: ScanType,
        status: str,
        sarif_report: Optional[Dict] = None,
        raw_output: Optional[str] = None,
        error_message: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        exit_code: Optional[int] = None
    ):
        self.scanner_name = scanner_name
        self.scan_type = scan_type
        self.status = status
        self.sarif_report = sarif_report
        self.raw_output = raw_output
        self.error_message = error_message
        self.duration_seconds = duration_seconds
        self.exit_code = exit_code
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "scanner_name": self.scanner_name,
            "scan_type": self.scan_type.value,
            "status": self.status,
            "sarif_report": self.sarif_report,
            "raw_output": self.raw_output,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "timestamp": self.timestamp.isoformat()
        }


# =============================================================================
# 🐳 DOCKER SCANNER EXECUTOR
# =============================================================================

class DockerScannerExecutor:
    """Docker-based scanner execution engine"""
    
    def __init__(self):
        self.settings = get_settings()
        self.docker_client = None
        self._initialize_docker()
    
    def _initialize_docker(self):
        """Initialize Docker client"""
        if not docker:
            logger.warning("Docker not available - scanner execution disabled")
            return
        
        try:
            self.docker_client = docker.from_env()
            # Test Docker connection
            self.docker_client.ping()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {str(e)}")
            self.docker_client = None
    
    async def execute_scanner(
        self,
        scanner_name: str,
        source_path: str,
        config: Dict[str, Any] = None,
        scan_target: str = None
    ) -> ScannerResult:
        """
        Execute a scanner in Docker container
        
        Args:
            scanner_name: Name of the scanner to execute
            source_path: Path to source code to scan
            config: Scanner-specific configuration
            scan_target: Target URL for DAST scanners
            
        Returns:
            ScannerResult object with execution results
        """
        if not self.docker_client:
            return ScannerResult(
                scanner_name=scanner_name,
                scan_type=ScanType.SAST,
                status="failed",
                error_message="Docker not available"
            )
        
        scanner_config = SCANNER_CONFIGS.get(scanner_name.lower())
        if not scanner_config:
            return ScannerResult(
                scanner_name=scanner_name,
                scan_type=ScanType.SAST,
                status="failed",
                error_message=f"Unknown scanner: {scanner_name}"
            )
        
        start_time = datetime.now()
        
        try:
            # Prepare scanner execution
            if scanner_name.lower() == "semgrep":
                result = await self._execute_semgrep(scanner_config, source_path, config)
            elif scanner_name.lower() == "trivy":
                result = await self._execute_trivy(scanner_config, source_path, config)
            elif scanner_name.lower() == "zap":
                result = await self._execute_zap(scanner_config, scan_target, config)
            elif scanner_name.lower() == "gitleaks":
                result = await self._execute_gitleaks(scanner_config, source_path, config)
            elif scanner_name.lower() == "checkov":
                result = await self._execute_checkov(scanner_config, source_path, config)
            else:
                result = ScannerResult(
                    scanner_name=scanner_name,
                    scan_type=scanner_config.scan_types[0],
                    status="failed",
                    error_message=f"Scanner {scanner_name} not implemented"
                )
            
            # Calculate duration
            duration = (datetime.now() - start_time).total_seconds()
            result.duration_seconds = duration
            
            return result
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"Scanner execution failed: {scanner_name} - {str(e)}")
            
            return ScannerResult(
                scanner_name=scanner_name,
                scan_type=scanner_config.scan_types[0],
                status="failed",
                error_message=str(e),
                duration_seconds=duration
            )
    
    async def _execute_semgrep(
        self,
        config: ScannerConfig,
        source_path: str,
        scan_config: Dict[str, Any] = None
    ) -> ScannerResult:
        """Execute Semgrep SAST scanner"""
        scan_config = scan_config or {}
        
        # Prepare command
        cmd = [
            "semgrep",
            "--config=auto",  # Use Semgrep registry rules
            "--sarif",        # Output in SARIF format
            "--quiet",        # Reduce noise
            "/src"           # Scan source directory
        ]
        
        # Add custom rules if specified
        if scan_config.get("rules"):
            cmd.extend(["--config", scan_config["rules"]])
        
        # Add language-specific options
        if scan_config.get("languages"):
            for lang in scan_config["languages"]:
                cmd.extend(["--lang", lang])
        
        return await self._run_container(
            config=config,
            command=cmd,
            source_path=source_path,
            parse_sarif=True
        )
    
    async def _execute_trivy(
        self,
        config: ScannerConfig,
        source_path: str,
        scan_config: Dict[str, Any] = None
    ) -> ScannerResult:
        """Execute Trivy SCA scanner"""
        scan_config = scan_config or {}
        
        # Prepare command for filesystem scan
        cmd = [
            "trivy",
            "fs",
            "--format", "sarif",
            "--output", "/tmp/trivy-report.sarif",
            "/src"
        ]
        
        # Add severity filter
        if scan_config.get("severity"):
            cmd.extend(["--severity", ",".join(scan_config["severity"])])
        
        return await self._run_container(
            config=config,
            command=cmd,
            source_path=source_path,
            parse_sarif=True,
            sarif_file="/tmp/trivy-report.sarif"
        )
    
    async def _execute_zap(
        self,
        config: ScannerConfig,
        target_url: str,
        scan_config: Dict[str, Any] = None
    ) -> ScannerResult:
        """Execute OWASP ZAP DAST scanner"""
        if not target_url:
            return ScannerResult(
                scanner_name="zap",
                scan_type=ScanType.DAST,
                status="failed",
                error_message="Target URL required for DAST scanning"
            )
        
        scan_config = scan_config or {}
        
        # Prepare command for baseline scan
        cmd = [
            "zap-baseline.py",
            "-t", target_url,
            "-J", "/tmp/zap-report.json",  # JSON report
            "-w", "/tmp/zap-report.md"     # Markdown report
        ]
        
        # Add authentication if configured
        if scan_config.get("auth_script"):
            cmd.extend(["-z", scan_config["auth_script"]])
        
        return await self._run_container(
            config=config,
            command=cmd,
            parse_sarif=False,  # ZAP doesn't output SARIF natively
            result_file="/tmp/zap-report.json"
        )
    
    async def _execute_gitleaks(
        self,
        config: ScannerConfig,
        source_path: str,
        scan_config: Dict[str, Any] = None
    ) -> ScannerResult:
        """Execute Gitleaks secrets scanner"""
        scan_config = scan_config or {}
        
        # Prepare command
        cmd = [
            "gitleaks",
            "detect",
            "--source", "/src",
            "--format", "sarif",
            "--report-path", "/tmp/gitleaks-report.sarif"
        ]
        
        # Add custom config if specified
        if scan_config.get("config_file"):
            cmd.extend(["--config", scan_config["config_file"]])
        
        return await self._run_container(
            config=config,
            command=cmd,
            source_path=source_path,
            parse_sarif=True,
            sarif_file="/tmp/gitleaks-report.sarif"
        )
    
    async def _execute_checkov(
        self,
        config: ScannerConfig,
        source_path: str,
        scan_config: Dict[str, Any] = None
    ) -> ScannerResult:
        """Execute Checkov IaC scanner"""
        scan_config = scan_config or {}
        
        # Prepare command
        cmd = [
            "checkov",
            "--directory", "/src",
            "--output", "sarif",
            "--output-file-path", "/tmp/checkov-report.sarif"
        ]
        
        # Add framework-specific options
        if scan_config.get("frameworks"):
            cmd.extend(["--framework"] + scan_config["frameworks"])
        
        return await self._run_container(
            config=config,
            command=cmd,
            source_path=source_path,
            parse_sarif=True,
            sarif_file="/tmp/checkov-report.sarif"
        )
    
    async def _run_container(
        self,
        config: ScannerConfig,
        command: List[str],
        source_path: str = None,
        parse_sarif: bool = False,
        sarif_file: str = None,
        result_file: str = None
    ) -> ScannerResult:
        """Run scanner in Docker container"""
        container = None
        
        try:
            # Prepare volumes
            volumes = {}
            if source_path:
                volumes[source_path] = {"bind": "/src", "mode": "ro"}
            
            # Create temporary directory for outputs
            temp_dir = tempfile.mkdtemp()
            volumes[temp_dir] = {"bind": "/tmp", "mode": "rw"}
            
            # Pull image if not available
            try:
                self.docker_client.images.get(config.image)
            except ImageNotFound:
                logger.info(f"Pulling Docker image: {config.image}")
                self.docker_client.images.pull(config.image)
            
            # Run container
            container = self.docker_client.containers.run(
                image=config.image,
                command=command,
                volumes=volumes,
                working_dir="/src" if source_path else "/",
                detach=True,
                remove=False,  # Keep container for log extraction
                mem_limit=config.memory_limit,
                cpu_period=100000,  # 100ms
                cpu_quota=int(100000 * config.cpu_limit),
                network_mode="none",  # Isolated network unless DAST
                user="1000:1000"  # Non-root user
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=config.timeout)
                exit_code = result["StatusCode"]
            except asyncio.TimeoutError:
                container.kill()
                raise Exception(f"Scanner timeout after {config.timeout} seconds")
            
            # Get container logs
            logs = container.logs().decode("utf-8", errors="replace")
            
            # Read output files
            sarif_report = None
            raw_output = logs
            
            if parse_sarif and sarif_file:
                sarif_path = os.path.join(temp_dir, os.path.basename(sarif_file))
                if os.path.exists(sarif_path):
                    with open(sarif_path, 'r') as f:
                        sarif_report = json.load(f)
                else:
                    logger.warning(f"SARIF file not found: {sarif_path}")
            
            if result_file:
                result_path = os.path.join(temp_dir, os.path.basename(result_file))
                if os.path.exists(result_path):
                    with open(result_path, 'r') as f:
                        raw_output = f.read()
            
            # Cleanup
            container.remove()
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Determine status
            status = "completed" if exit_code == 0 else "failed"
            error_message = None if exit_code == 0 else f"Scanner exited with code {exit_code}"
            
            return ScannerResult(
                scanner_name=config.name,
                scan_type=config.scan_types[0],
                status=status,
                sarif_report=sarif_report,
                raw_output=raw_output,
                error_message=error_message,
                exit_code=exit_code
            )
            
        except Exception as e:
            # Cleanup on error
            if container:
                try:
                    container.remove(force=True)
                except:
                    pass
            
            raise e


# =============================================================================
# 🎯 SCANNER MANAGER
# =============================================================================

class ScannerManager:
    """Main scanner orchestration manager"""
    
    def __init__(self):
        self.settings = get_settings()
        self.executor = DockerScannerExecutor()
    
    async def execute_scan(
        self,
        scan_types: List[ScanType],
        source_path: str = None,
        target_url: str = None,
        config: Dict[str, Any] = None
    ) -> List[ScannerResult]:
        """
        Execute multiple scanners based on scan types
        
        Args:
            scan_types: List of scan types to execute
            source_path: Path to source code (for SAST, SCA, etc.)
            target_url: Target URL (for DAST)
            config: Global configuration dict
            
        Returns:
            List of scanner results
        """
        config = config or {}
        results = []
        
        # Map scan types to scanners
        scanner_mapping = {
            ScanType.SAST: ["semgrep"],
            ScanType.SCA: ["trivy"],
            ScanType.DAST: ["zap"],
            ScanType.SECRETS: ["gitleaks"],
            ScanType.IAC: ["checkov"],
            ScanType.CONTAINER: ["trivy"]
        }
        
        # Collect scanners to run
        scanners_to_run = set()
        for scan_type in scan_types:
            if scan_type in scanner_mapping:
                scanners_to_run.update(scanner_mapping[scan_type])
        
        # Execute scanners in parallel
        tasks = []
        for scanner_name in scanners_to_run:
            scanner_config = config.get(scanner_name, {})
            
            # Determine scan target
            if scanner_name == "zap":
                scan_target = target_url
                scan_source = None
            else:
                scan_target = None
                scan_source = source_path
            
            task = self.executor.execute_scanner(
                scanner_name=scanner_name,
                source_path=scan_source,
                config=scanner_config,
                scan_target=scan_target
            )
            tasks.append(task)
        
        # Wait for all scanners to complete
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Handle exceptions
            final_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    scanner_name = list(scanners_to_run)[i]
                    error_result = ScannerResult(
                        scanner_name=scanner_name,
                        scan_type=ScanType.SAST,  # Default
                        status="failed",
                        error_message=str(result)
                    )
                    final_results.append(error_result)
                else:
                    final_results.append(result)
            
            results = final_results
        
        logger.info(f"Scan completed: {len(results)} scanners executed")
        return results
    
    async def check_scanner_health(self) -> Dict[str, Dict[str, Any]]:
        """
        Check health and availability of all scanners
        
        Returns:
            Dictionary with scanner health information
        """
        health_status = {}
        
        for scanner_name, config in SCANNER_CONFIGS.items():
            try:
                if self.executor.docker_client:
                    # Try to pull/check image
                    try:
                        image = self.executor.docker_client.images.get(config.image)
                        health_status[scanner_name] = {
                            "available": True,
                            "image": config.image,
                            "image_id": image.id[:12],
                            "scan_types": [st.value for st in config.scan_types],
                            "supported_languages": config.supported_languages
                        }
                    except ImageNotFound:
                        health_status[scanner_name] = {
                            "available": False,
                            "image": config.image,
                            "error": "Image not found",
                            "scan_types": [st.value for st in config.scan_types]
                        }
                else:
                    health_status[scanner_name] = {
                        "available": False,
                        "error": "Docker not available",
                        "scan_types": [st.value for st in config.scan_types]
                    }
            except Exception as e:
                health_status[scanner_name] = {
                    "available": False,
                    "error": str(e),
                    "scan_types": [st.value for st in config.scan_types]
                }
        
        return health_status
    
    def get_supported_scan_types(self) -> List[str]:
        """Get list of all supported scan types"""
        scan_types = set()
        for config in SCANNER_CONFIGS.values():
            scan_types.update([st.value for st in config.scan_types])
        return sorted(list(scan_types))
    
    def get_scanner_info(self, scanner_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific scanner"""
        config = SCANNER_CONFIGS.get(scanner_name.lower())
        if not config:
            return None
        
        return {
            "name": config.name,
            "image": config.image,
            "scan_types": [st.value for st in config.scan_types],
            "supported_languages": config.supported_languages,
            "timeout": config.timeout,
            "memory_limit": config.memory_limit,
            "cpu_limit": config.cpu_limit
        }


# =============================================================================
# 📄 SARIF UTILITIES
# =============================================================================

class SARIFProcessor:
    """SARIF report processing and normalization"""
    
    @staticmethod
    def normalize_sarif(sarif_report: Dict) -> Dict:
        """
        Normalize SARIF report to ensure consistency
        
        Args:
            sarif_report: Raw SARIF report
            
        Returns:
            Normalized SARIF report
        """
        if not sarif_report:
            return {}
        
        # Ensure required SARIF structure
        normalized = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": sarif_report.get("runs", [])
        }
        
        return normalized
    
    @staticmethod
    def extract_vulnerabilities(sarif_report: Dict) -> List[Dict]:
        """
        Extract vulnerability information from SARIF report
        
        Args:
            sarif_report: SARIF report
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        if not sarif_report or "runs" not in sarif_report:
            return vulnerabilities
        
        for run in sarif_report["runs"]:
            results = run.get("results", [])
            tool = run.get("tool", {}).get("driver", {})
            tool_name = tool.get("name", "unknown")
            
            for result in results:
                vulnerability = {
                    "rule_id": result.get("ruleId", ""),
                    "message": result.get("message", {}).get("text", ""),
                    "level": result.get("level", "note"),
                    "locations": [],
                    "tool": tool_name
                }
                
                # Extract locations
                for location in result.get("locations", []):
                    physical_location = location.get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    region = physical_location.get("region", {})
                    
                    vulnerability["locations"].append({
                        "file_path": artifact_location.get("uri", ""),
                        "line_number": region.get("startLine", 0),
                        "column_number": region.get("startColumn", 0)
                    })
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities


# Export scanner components
__all__ = [
    "ScannerManager",
    "ScannerResult",
    "ScannerConfig",
    "SARIFProcessor",
    "SCANNER_CONFIGS"
]