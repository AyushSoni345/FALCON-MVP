import os
from pydantic import BaseModel, Field

class Settings(BaseModel):
    # API settings
    API_TITLE: str = Field(default="FALCON Module 5 - Multi-Domain AI Analytics Layer")
    API_VERSION: str = Field(default="1.0.0")

    # Engine threshold settings (default risk & confidence thresholds)
    BEHAVIOUR_RISK_THRESHOLD: float = Field(default=20.0, description="Minimum risk score to activate Behaviour Engine")
    FRAUD_RISK_THRESHOLD: float = Field(default=20.0, description="Minimum risk score to activate Fraud Engine")
    CYBER_RISK_THRESHOLD: float = Field(default=20.0, description="Minimum risk score to activate Cyber Engine")
    QUANTUM_RISK_THRESHOLD: float = Field(default=20.0, description="Minimum risk score to activate Quantum Engine")

    # General confidence threshold
    DEFAULT_CONFIDENCE_THRESHOLD: float = Field(default=0.5)

    # Logging settings
    LOG_LEVEL: str = Field(default="INFO")
    STRUCTURED_JSON_LOGGING: bool = Field(default=True)

# Instantiate settings with environment variables support
settings = Settings(
    BEHAVIOUR_RISK_THRESHOLD=float(os.getenv("FALCON_M5_BEHAVIOUR_RISK_THRESHOLD", "20.0")),
    FRAUD_RISK_THRESHOLD=float(os.getenv("FALCON_M5_FRAUD_RISK_THRESHOLD", "20.0")),
    CYBER_RISK_THRESHOLD=float(os.getenv("FALCON_M5_CYBER_RISK_THRESHOLD", "20.0")),
    QUANTUM_RISK_THRESHOLD=float(os.getenv("FALCON_M5_QUANTUM_RISK_THRESHOLD", "20.0")),
    DEFAULT_CONFIDENCE_THRESHOLD=float(os.getenv("FALCON_M5_DEFAULT_CONFIDENCE_THRESHOLD", "0.5")),
    LOG_LEVEL=os.getenv("FALCON_M5_LOG_LEVEL", "INFO"),
    STRUCTURED_JSON_LOGGING=os.getenv("FALCON_M5_STRUCTURED_JSON_LOGGING", "True").lower() in ("true", "1", "yes")
)
