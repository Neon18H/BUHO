import asyncio
from datetime import datetime
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("SYNC_DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from app.auth.security import TokenPayload, get_current_user  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db.models import Base as ScanBase  # noqa: E402
from app.db.user_models import Base as UserBase  # noqa: E402
from app.main import app  # noqa: E402

get_settings.cache_clear()
settings = get_settings()
app.dependency_overrides[get_current_user] = lambda: TokenPayload("admin", datetime.utcnow(), "admin")


def pytest_sessionstart(session):  # noqa: D401
    """Create database tables for tests."""
    async def init_models():
        async_engine = create_async_engine(settings.database_url, echo=False)
        async with async_engine.begin() as conn:
            await conn.run_sync(ScanBase.metadata.create_all)
            await conn.run_sync(UserBase.metadata.create_all)

    asyncio.run(init_models())


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def cleanup_tables():
    yield

    async def reset_models():
        async_engine = create_async_engine(settings.database_url, echo=False)
        async with async_engine.begin() as conn:
            await conn.run_sync(ScanBase.metadata.drop_all)
            await conn.run_sync(UserBase.metadata.drop_all)
            await conn.run_sync(UserBase.metadata.create_all)
            await conn.run_sync(ScanBase.metadata.create_all)

    asyncio.run(reset_models())
