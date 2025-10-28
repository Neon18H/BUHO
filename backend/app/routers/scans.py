from datetime import datetime
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.scanner import ScannerOrchestrator

router = APIRouter(prefix="/scans", tags=["scans"])


def get_orchestrator(db: Session = Depends(get_db)) -> ScannerOrchestrator:
    return ScannerOrchestrator(db=db)


@router.post("/", response_model=schemas.ScanRead, status_code=201)
def create_scan(
    payload: schemas.ScanCreate,
    db: Session = Depends(get_db),
    orchestrator: ScannerOrchestrator = Depends(get_orchestrator),
):
    target = (
        db.query(models.Target)
        .filter(models.Target.url == str(payload.target))
        .one_or_none()
    )
    if not target:
        target = models.Target(url=str(payload.target))
        db.add(target)
        db.flush()

    scan = models.Scan(
        target=target,
        status=models.ScanStatus.pending,
        requested_tools=payload.tools,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    orchestrator.enqueue_scan(scan)
    return schemas.ScanRead(
        id=scan.id,
        status=scan.status,
        target=payload.target,
        requested_tools=scan.requested_tools,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        findings=[],
    )


@router.get("/", response_model=List[schemas.ScanRead])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(models.Scan).all()
    return [
        schemas.ScanRead(
            id=scan.id,
            status=scan.status,
            target=scan.target.url,
            requested_tools=scan.requested_tools,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            findings=scan.findings,
        )
        for scan in scans
    ]


@router.get("/{scan_id}", response_model=schemas.ScanRead)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return schemas.ScanRead(
        id=scan.id,
        status=scan.status,
        target=scan.target.url,
        requested_tools=scan.requested_tools,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        findings=scan.findings,
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: UUID, db: Session = Depends(get_db)) -> None:
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()
