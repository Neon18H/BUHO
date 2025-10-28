from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import Base, get_engine
from .routers import scans

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event() -> None:
    engine = get_engine()
    Base.metadata.create_all(bind=engine)


app.include_router(scans.router)


@app.get("/health", tags=["system"])
def healthcheck():
    return {"status": "ok", "app": settings.app_name}
