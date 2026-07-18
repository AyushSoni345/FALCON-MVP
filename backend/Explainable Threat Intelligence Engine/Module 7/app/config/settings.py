import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FALCON_M7_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    api_title: str = "FALCON Module 7 - Explainable Threat Intelligence Engine"
    api_version: str = "1.0.0"
    env: str = "development"
    log_level: str = "INFO"
    structured_json_logging: bool = True

settings = Settings()
