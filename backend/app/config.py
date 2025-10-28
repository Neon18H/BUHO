from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Buh Vulnerability Platform"
    backend_host: str = Field(default="0.0.0.0")
    backend_port: int = Field(default=8000)
    database_url: str = Field(
        default="postgresql+psycopg2://buh:buh@db:5432/buh"
    )
    redis_url: str = Field(default="redis://redis:6379/0")
    ai_model: str = Field(default="distilbert-base-uncased")
    enable_tool_containers: bool = Field(default=True)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()  # type: ignore[call-arg]
