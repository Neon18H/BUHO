from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.scan import router as scan_router
from app.auth.security import create_access_token, get_password_hash, require_role, verify_password
from app.config import settings
from app.db.session import get_session

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.EventRenamer("message"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
logger = structlog.get_logger()

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):  # pragma: no cover - instrumentation only
    logger.info("request.start", method=request.method, url=str(request.url))
    response = await call_next(request)
    logger.info("request.end", status_code=response.status_code)
    return response


@app.get("/health")
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/login")
async def login(data: Dict[str, str]) -> Dict[str, Any]:
    username = data.get("username")
    password = data.get("password")
    if username != "admin" or not verify_password(password or "", get_password_hash("admin")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access = create_access_token(username, role="admin")
    refresh = create_access_token(username, role="admin", expires_delta=timedelta(minutes=settings.refresh_token_expire_minutes))
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


app.include_router(scan_router, prefix=settings.api_prefix)


@app.get("/legal-disclaimer")
async def legal_disclaimer() -> Dict[str, str]:
    return {
        "message": "Solo escanear sistemas con permiso explícito y por escrito. El autor no se responsabiliza por uso malicioso.",
    }
