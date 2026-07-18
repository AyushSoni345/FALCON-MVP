import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FALCON_M2_", env_file=".env", env_file_encoding="utf-8")

    api_title: str = "FALCON Normalization & Enrichment Layer"
    env: str = "development"
    host: str = "0.0.0.0"
    port: int = int(os.environ.get("NORMALIZATION_PORT", 8002))
    log_level: str = "INFO"
    
    # Stateful fraud settings
    impossible_travel_threshold_kph: float = 800.0  # Max travel speed in km/h
    dormancy_days_threshold: int = 90
    rapid_transaction_seconds_threshold: float = 5.0
    high_value_transaction_threshold: float = 500000.0  # ₹5,00,000 threshold

settings = Settings()
