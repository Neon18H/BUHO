#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHONPATH=backend python <<'PYCODE'
import asyncio
from app.config import settings
from app.db.session import AsyncSessionLocal
from app.db.user_models import User
from app.auth.security import get_password_hash

async def main():
    async with AsyncSessionLocal() as session:
        user = User(username="admin", hashed_password=get_password_hash("admin"), role="admin")
        session.add(user)
        await session.commit()

asyncio.run(main())
PYCODE
