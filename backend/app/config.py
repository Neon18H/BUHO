from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", env_nested_delimiter="__")

    app_name: str = "Buho API"
    api_prefix: str = "/api"
    database_url: str = "postgresql+asyncpg://postgres:postgres@db:5432/buho"
    sync_database_url: str = "postgresql+psycopg://postgres:postgres@db:5432/buho"
    redis_url: str = "redis://redis:6379/0"
    secret_key: str = "super-secret-key-change"
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 60 * 24 * 7
    allowed_hosts: List[str] = ["*"]
    cors_origins: List[str] = ["http://localhost:5173", "http://frontend:5173"]
    rate_limit_per_minute: int = 120
    demo_mode: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
