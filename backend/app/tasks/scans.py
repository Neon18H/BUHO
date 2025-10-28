import asyncio
from typing import Dict

from celery import shared_task
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Scan
from ..services.scanner import ScannerOrchestrator
from ..services.tooling import TOOL_REGISTRY, ToolRunner


def get_tool_runner(name: str) -> ToolRunner:
    if name not in TOOL_REGISTRY:
        raise ValueError(f"Tool '{name}' is not registered")
    return TOOL_REGISTRY[name]


async def run_scan_async(scan: Scan, db: Session) -> None:
    orchestrator = ScannerOrchestrator(db)
    await orchestrator.run_scan(scan)


@shared_task
def execute_scan(scan_id: str) -> Dict[str, str]:
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).one_or_none()
    if not scan:
        return {"status": "not_found"}

    asyncio.run(run_scan_async(scan, db))
    return {"status": "completed", "scan_id": scan_id}
