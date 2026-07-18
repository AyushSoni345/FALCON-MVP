from typing import Dict, List
from pydantic import BaseModel

class VersionConfig(BaseModel):
    config_version: str
    rule_version: str
    last_updated: str

class RiskWeightsConfig(BaseModel):
    positive_adjustments: Dict[str, float]
    negative_adjustments: Dict[str, float]

class PriorityThreshold(BaseModel):
    min_score: float
    required_business_criticality: List[str] = []

class PriorityThresholdsConfig(BaseModel):
    thresholds: Dict[str, PriorityThreshold]

class BusinessContextConfig(BaseModel):
    critical_processes: List[str]
    test_processes: List[str]
    critical_assets: List[str]
    non_prod_assets: List[str]

class SuppressionRuleConditions(BaseModel):
    asset_type: List[str] = []
    production_system: bool = None
    business_process: List[str] = []
    service_impact: List[str] = []
    pii_exposure: bool = None
    credential_exposure: bool = None

class SuppressionRule(BaseModel):
    rule_id: str
    rule_name: str
    version: str
    severity: str
    enabled: bool
    owner: str
    last_modified: str
    conditions: SuppressionRuleConditions
    reason: str

class SuppressionOverrides(BaseModel):
    prevent_on_multi_domain: bool
    min_domains_for_override: int
    min_correlation_strength: float

class SuppressionRulesConfig(BaseModel):
    suppression_rules: List[SuppressionRule]
    overrides: SuppressionOverrides

class ConfidenceWeightsConfig(BaseModel):
    weights: Dict[str, float]

class ScoringFormulaConfig(BaseModel):
    formula_type: str
    max_boost: float
    multi_domain_boost_factor: float
    multi_domain_threshold: float
