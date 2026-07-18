import os
import yaml
from typing import Dict, Any
from .schemas import (
    VersionConfig,
    RiskWeightsConfig,
    PriorityThresholdsConfig,
    BusinessContextConfig,
    SuppressionRulesConfig,
    ConfidenceWeightsConfig,
    ScoringFormulaConfig,
)
from module6.exceptions.configuration import ConfigurationException

class ConfigurationManager:
    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.cache: Dict[str, Any] = {}
        self.config_version: str = ""
        self.rule_version: str = ""
        
    def _load_yaml(self, filename: str) -> dict:
        filepath = os.path.join(self.config_dir, filename)
        if not os.path.exists(filepath):
            raise ConfigurationException(f"Configuration file not found: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ConfigurationException(f"Failed to parse YAML file {filepath}: {str(e)}")
            
    def load_and_validate_configs(self) -> None:
        try:
            # Load and validate Version
            version_data = self._load_yaml("version.yaml")
            version_cfg = VersionConfig(**version_data)
            self.config_version = version_cfg.config_version
            self.rule_version = version_cfg.rule_version
            self.cache["version"] = version_cfg
            
            # Load and validate Risk Weights
            risk_weights_data = self._load_yaml("risk_weights.yaml")
            self.cache["risk_weights"] = RiskWeightsConfig(**risk_weights_data)
            
            # Load and validate Priority Thresholds
            priority_thresholds_data = self._load_yaml("priority_thresholds.yaml")
            self.cache["priority_thresholds"] = PriorityThresholdsConfig(**priority_thresholds_data)
            
            # Load and validate Business Context
            business_context_data = self._load_yaml("business_context.yaml")
            self.cache["business_context"] = BusinessContextConfig(**business_context_data)
            
            # Load and validate Suppression Rules
            suppression_rules_data = self._load_yaml("suppression_rules.yaml")
            self.cache["suppression_rules"] = SuppressionRulesConfig(**suppression_rules_data)
            
            # Load and validate Confidence Weights
            confidence_weights_data = self._load_yaml("confidence_weights.yaml")
            self.cache["confidence_weights"] = ConfidenceWeightsConfig(**confidence_weights_data)
            
            # Load and validate Scoring Formula
            scoring_formula_data = self._load_yaml("scoring_formula.yaml")
            self.cache["scoring_formula"] = ScoringFormulaConfig(**scoring_formula_data)
            
            self._validate_dependencies()
        except Exception as e:
            raise ConfigurationException(f"Configuration validation failed: {str(e)}")
            
    def _validate_dependencies(self) -> None:
        # Check that confidence weights sum to 1.0
        conf_weights = self.cache["confidence_weights"].weights
        if abs(sum(conf_weights.values()) - 1.0) > 0.001:
            raise ConfigurationException("Confidence weights must sum to exactly 1.0")

    def get_config(self, key: str) -> Any:
        if not self.cache:
            self.load_and_validate_configs()
        if key not in self.cache:
            raise ConfigurationException(f"Configuration key '{key}' not found in cache.")
        return self.cache.get(key)
        
    def reload(self) -> None:
        self.cache.clear()
        self.load_and_validate_configs()
