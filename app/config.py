import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str = Field(default="sqlite:///./incident_agent.db")
    MODEL_API_KEY: str = Field(default="")
    MODEL_BASE_URL: str = Field(default="https://api.openai.com/v1")
    MODEL_NAME: str = Field(default="gemini-3.8-flash")
    PORT: int = Field(default=8000)
    ENVIRONMENT: str = Field(default="production")

    @property
    def normalized_database_url(self) -> str:
        url = self.DATABASE_URL.strip()
        # Render sometimes provides postgres:// which SQLAlchemy 2 does not support directly
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return url


settings = Settings()
