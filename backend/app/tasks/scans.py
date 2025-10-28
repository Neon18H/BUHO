import asyncio
from typing import Dict

from celery import shared_task
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Scan


async def run_scan_async(scan: Scan, db: Session) -> None:
    from ..services.scanner import ScannerOrchestrator

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
