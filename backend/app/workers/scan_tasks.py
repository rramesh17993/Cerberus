"""
🔍 Scan Tasks - Background scanning operations for SecureScan Framework
"""

from celery import current_task
from app.workers.celery_app import celery_app
from app.core.logging import get_logger
from app.scanners.manager import ScannerManager
from app.core.database import get_db_session
from app.models import ScanResult, ScanStatus

logger = get_logger(__name__)

# =============================================================================
# 🔍 SCANNING TASKS
# =============================================================================

@celery_app.task(bind=True, name="app.workers.scan_tasks.run_security_scan")
def run_security_scan(self, scan_id: str, project_id: str, scan_config: dict):
    """
    Execute a security scan in the background
    
    Args:
        scan_id: Unique scan identifier
        project_id: Project identifier
        scan_config: Scan configuration dictionary
    """
    try:
        logger.info(f"Starting security scan {scan_id} for project {project_id}")
        
        # Update task progress
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Initializing scanner", "progress": 0}
        )
        
        # Initialize scanner manager
        scanner_manager = ScannerManager()
        
        # Execute scan based on configuration
        scan_type = scan_config.get("scan_type")
        target = scan_config.get("target")
        options = scan_config.get("options", {})
        
        current_task.update_state(
            state="PROGRESS", 
            meta={"status": f"Running {scan_type} scan", "progress": 25}
        )
        
        # Run the actual scan
        results = scanner_manager.run_scan(
            scan_type=scan_type,
            target=target,
            options=options
        )
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Processing results", "progress": 75}
        )
        
        # Save results to database
        # NOTE: This would need async database handling in production
        # For now, just return the results
        
        current_task.update_state(
            state="PROGRESS",
            meta={"status": "Completed", "progress": 100}
        )
        
        logger.info(f"Completed security scan {scan_id}")
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "results": results,
            "vulnerabilities_found": len(results.get("vulnerabilities", [])),
            "scan_duration": results.get("duration", 0)
        }
        
    except Exception as e:
        logger.error(f"Error in security scan {scan_id}: {str(e)}")
        current_task.update_state(
            state="FAILURE",
            meta={"error": str(e), "scan_id": scan_id}
        )
        raise


@celery_app.task(name="app.workers.scan_tasks.process_scan_results")
def process_scan_results(scan_id: str, raw_results: dict):
    """
    Process and normalize scan results
    
    Args:
        scan_id: Scan identifier
        raw_results: Raw scan results from scanner
    """
    try:
        logger.info(f"Processing scan results for {scan_id}")
        
        # Normalize results to common format
        normalized_results = {
            "scan_id": scan_id,
            "vulnerabilities": [],
            "summary": {
                "total_issues": 0,
                "critical": 0,
                "high": 0, 
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        # Process vulnerabilities
        for vuln in raw_results.get("vulnerabilities", []):
            normalized_vuln = {
                "title": vuln.get("title", "Unknown"),
                "description": vuln.get("description", ""),
                "severity": vuln.get("severity", "unknown").lower(),
                "file_path": vuln.get("file_path"),
                "line_number": vuln.get("line_number"),
                "cwe_id": vuln.get("cwe_id"),
                "cvss_score": vuln.get("cvss_score"),
                "remediation": vuln.get("remediation", "")
            }
            
            normalized_results["vulnerabilities"].append(normalized_vuln)
            normalized_results["summary"]["total_issues"] += 1
            
            # Count by severity
            severity = normalized_vuln["severity"]
            if severity in normalized_results["summary"]:
                normalized_results["summary"][severity] += 1
        
        logger.info(f"Processed {len(normalized_results['vulnerabilities'])} vulnerabilities")
        
        return normalized_results
        
    except Exception as e:
        logger.error(f"Error processing scan results for {scan_id}: {str(e)}")
        raise


# Export tasks
__all__ = [
    "run_security_scan",
    "process_scan_results"
]