import os
from pydantic import BaseModel, Field

class Settings(BaseModel):
    # API settings
    API_TITLE: str = Field(default="FALCON Module 4 - AI-Driven Correlation & Reasoning Engine")
    API_VERSION: str = Field(default="1.0.0")
    
    # Engine parameters
    IMMEDIATE_CORRELATION_WINDOW_SECONDS: float = Field(default=60.0)
    SHORT_DURATION_WINDOW_SECONDS: float = Field(default=300.0)
    MEDIUM_DURATION_WINDOW_SECONDS: float = Field(default=1800.0)
    LONG_RUNNING_ATTACK_WINDOW_SECONDS: float = Field(default=86400.0)  # 24 hours
    
    # Confidence and evidence thresholds
    MIN_CORRELATION_CONFIDENCE: float = Field(default=0.3)
    DEFAULT_CONFIDENCE_THRESHOLD: float = Field(default=0.5)
    
    # Feature toggles
    PREDICTIVE_REASONING_ENABLED: bool = Field(default=False)
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO")
    STRUCTURED_JSON_LOGGING: bool = Field(default=True)

# Instantiate settings with environment overrides
settings = Settings(
    IMMEDIATE_CORRELATION_WINDOW_SECONDS=float(os.getenv("FALCON_M4_IMMEDIATE_CORRELATION_WINDOW_SECONDS", "60.0")),
    SHORT_DURATION_WINDOW_SECONDS=float(os.getenv("FALCON_M4_SHORT_DURATION_WINDOW_SECONDS", "300.0")),
    MEDIUM_DURATION_WINDOW_SECONDS=float(os.getenv("FALCON_M4_MEDIUM_DURATION_WINDOW_SECONDS", "1800.0")),
    LONG_RUNNING_ATTACK_WINDOW_SECONDS=float(os.getenv("FALCON_M4_LONG_RUNNING_ATTACK_WINDOW_SECONDS", "86400.0")),
    MIN_CORRELATION_CONFIDENCE=float(os.getenv("FALCON_M4_MIN_CORRELATION_CONFIDENCE", "0.3")),
    DEFAULT_CONFIDENCE_THRESHOLD=float(os.getenv("FALCON_M4_DEFAULT_CONFIDENCE_THRESHOLD", "0.5")),
    PREDICTIVE_REASONING_ENABLED=os.getenv("FALCON_M4_PREDICTIVE_REASONING_ENABLED", "False").lower() in ("true", "1", "yes"),
    LOG_LEVEL=os.getenv("FALCON_M4_LOG_LEVEL", "INFO"),
    STRUCTURED_JSON_LOGGING=os.getenv("FALCON_M4_STRUCTURED_JSON_LOGGING", "True").lower() in ("true", "1", "yes")
)
