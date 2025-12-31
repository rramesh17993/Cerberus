"""
🧠 Cerberus Context Engine
-------------------------
The brain of the operation. This module correlates static findings with
runtime context to calculate a 'True Risk Score'.

Algorithms:
1. Environment Weighting: Production > Staging > Dev
2. Reachability Analysis: Imported functions > Dead code
3. Exposure Analysis: Public Internet > Internal VPC
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel

class EnvironmentType(Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    CI = "ci"

class ReachabilityStatus(Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"

class VulnerabilityContext(BaseModel):
    environment: EnvironmentType
    is_internet_facing: bool
    reachability: ReachabilityStatus
    asset_criticality: int  # 1-10 scale

class ContextEngine:
    """
    Analyzes vulnerability context to prioritize fixes.
    """
    
    def __init__(self):
        # Configuration weights
        self.env_weights = {
            EnvironmentType.PRODUCTION: 2.0,
            EnvironmentType.STAGING: 1.0,
            EnvironmentType.DEVELOPMENT: 0.5,
            EnvironmentType.CI: 0.1
        }

    def calculate_true_risk(self, base_severity: float, context: VulnerabilityContext) -> float:
        """
        Calculates the True Risk Score (TRS) 
        Formula: Base * EnvWeight * Exposure * Reachability
        """
        score = base_severity
        
        # 1. Apply Environment Context
        score *= self.env_weights.get(context.environment, 1.0)
        
        # 2. Apply Exposure Context
        if context.is_internet_facing:
            score *= 1.5  # Boost score if internet facing
        
        # 3. Apply Reachability Context
        if context.reachability == ReachabilityStatus.UNREACHABLE:
            score *= 0.1  # Drastically reduce if code is dead/unreachable
        elif context.reachability == ReachabilityStatus.REACHABLE:
            score *= 1.2  # Slight boost if definitely reachable
            
        return round(score, 2)

    def prioritize_findings(self, findings: List[Dict], context: VulnerabilityContext) -> List[Dict]:
        """
        Sorts findings by their calculated True Risk Score.
        """
        for finding in findings:
            base_score = finding.get('cvss_score', 0.0)
            finding['true_risk_score'] = self.calculate_true_risk(base_score, context)
            
        return sorted(findings, key=lambda x: x['true_risk_score'], reverse=True)

# Example Usage
if __name__ == "__main__":
    engine = ContextEngine()
    
    ctx_prod = VulnerabilityContext(
        environment=EnvironmentType.PRODUCTION,
        is_internet_facing=True,
        reachability=ReachabilityStatus.REACHABLE,
        asset_criticality=9
    )
    
    # Simulating a "Critical" bug (CVSS 9.0)
    # If in Prod + Reachable + Public -> Score explodes
    risk = engine.calculate_true_risk(9.0, ctx_prod)
    print(f"Production Risk Score: {risk}")  # Output: 32.4
    
    ctx_dev = VulnerabilityContext(
        environment=EnvironmentType.DEVELOPMENT,
        is_internet_facing=False,
        reachability=ReachabilityStatus.UNREACHABLE,
        asset_criticality=1
    )
    
    # Same bug in Dev + Unreachable -> Score drops
    risk_dev = engine.calculate_true_risk(9.0, ctx_dev)
    print(f"Dev/Dead Code Risk Score: {risk_dev}")  # Output: 0.45
