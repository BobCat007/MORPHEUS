import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_name: str = "MORPHEUS"
    environment: str = os.getenv("MORPHEUS_ENV", "development")
    debug: bool = os.getenv("MORPHEUS_DEBUG", "false").lower() == "true"


settings = Settings()
