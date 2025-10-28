from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zipfile import ZipFile

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import TokenPayload, get_current_user, require_role
from app.db.models import Scan, VulnerabilityORM
from app.db.session import get_session
from app.enrichment import enrich_vulnerability_async
from app.models import Vulnerability
from app.services.prioritization import compute_priority, label_from_score
from app.services.vulnerabilities import get_vulnerability, list_vulnerabilities
from app.tasks.worker import gather_and_normalize
from app.utils.validators import sanitize_target

router = APIRouter()


@router.post("/scan")
async def start_scan(
    payload: Dict[str, Any],
    session: AsyncSession = Depends(get_session),
    token: TokenPayload = Depends(get_current_user),
) -> Dict[str, Any]:
    await require_role("operator", token)
    targets: List[str] = [sanitize_target(t) for t in payload.get("targets", [])]
    tools = payload.get("tools", ["wapiti", "nikto"])
    allowed_tools = {"wapiti", "nikto", "sqlmap", "gobuster"}
    if not targets:
        raise HTTPException(status_code=400, detail="At least one target required")
    if not set(tools).issubset(allowed_tools):
        raise HTTPException(status_code=400, detail="Unsupported tool provided")
    try:
        concurrency = min(int(payload.get("concurrency", 5)), 5)
        gobuster_threads = min(int(payload.get("gobuster_threads", 10)), 50)
        max_requests = min(int(payload.get("max_requests", 1000)), 1000)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid limits provided") from exc
    scan_id = str(uuid.uuid4())
    for target in targets:
        for tool in tools:
            scan = Scan(id=f"{scan_id}-{tool}", target=target, tool=tool, status="scheduled", created_at=datetime.utcnow())
            session.add(scan)
    await session.commit()
    return {
        "scan_id": scan_id,
        "status": "scheduled",
        "targets": targets,
        "tools": tools,
        "limits": {"concurrency": concurrency, "gobuster_threads": gobuster_threads, "max_requests": max_requests},
    }


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)) -> Dict[str, Any]:
    stmt = select(Scan).where(Scan.id.like(f"{scan_id}%"))
    result = await session.execute(stmt)
    scans = result.scalars().all()
    if not scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "items": [
            {
                "id": scan.id,
                "tool": scan.tool,
                "target": scan.target,
                "status": scan.status,
                "logs": scan.logs,
            }
            for scan in scans
        ],
    }


@router.get("/vulns")
async def list_vulns(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    items = await list_vulnerabilities(session, limit=limit, offset=offset, severity=severity)
    return {
        "items": [
            {
                "id": vuln.id,
                "id_local": vuln.id_local,
                "scan_id": vuln.scan_id,
                "tool": vuln.tool,
                "title": vuln.title,
                "severity": vuln.severity,
                "priority_score": vuln.priority_score,
                "priority_label": label_from_score(vuln.priority_score or 0.0) if vuln.priority_score is not None else None,
                "timestamp": vuln.timestamp,
            }
            for vuln in items
        ]
    }


@router.get("/vulns/{vuln_id}")
async def get_vuln(vuln_id: int, session: AsyncSession = Depends(get_session)) -> Dict[str, Any]:
    vuln = await get_vulnerability(session, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {
        "id": vuln.id,
        "id_local": vuln.id_local,
        "scan_id": vuln.scan_id,
        "tool": vuln.tool,
        "target": vuln.target,
        "path": vuln.path,
        "parameter": vuln.parameter,
        "title": vuln.title,
        "description": vuln.description,
        "severity": vuln.severity,
        "cvss_v3": vuln.cvss_v3,
        "cve": vuln.cve,
        "confidence": vuln.confidence,
        "evidence": vuln.evidence,
        "references": vuln.references,
        "timestamp": vuln.timestamp,
        "priority_score": vuln.priority_score,
        "priority_label": label_from_score(vuln.priority_score or 0.0) if vuln.priority_score is not None else None,
        "exploitability_notes": vuln.exploitability_notes,
    }


@router.post("/vulns/{vuln_id}/remediate")
async def remediate_vuln(
    vuln_id: int,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    vuln = await get_vulnerability(session, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    prompt_path = Path(__file__).resolve().parents[3] / "prompts" / "ia_remediation_prompt.txt"
    template = prompt_path.read_text(encoding="utf-8")
    payload = template.replace("{vuln_json}", json.dumps({
        "title": vuln.title,
        "description": vuln.description,
        "severity": vuln.severity,
        "cvss_v3": vuln.cvss_v3,
        "cve": vuln.cve,
        "confidence": vuln.confidence,
        "evidence": vuln.evidence,
        "references": vuln.references,
    }))
    # In MVP we simulate AI response
    return {
        "prompt": payload,
        "remediation": {
            "remediation_short": "Aplicar parche disponible",
            "remediation_steps": ["Identificar versión", "Aplicar parche", "Verificar"],
            "mitigation_timeline": {
                "immediate": "Bloquear acceso temporal",
                "short_term": "Aplicar parche",
                "long_term": "Implementar WAF",
            },
            "exploitability": "Un atacante enviaría payload malicioso para explotación.",
            "related_cve": [{"cve": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"} for cve in (vuln.cve or [])],
            "verification_commands": ["curl -I https://example.com/login"],
            "risk_explanation": "Basado en CVSS y evidencia capturada.",
        },
    }


@router.post("/admin/import")
async def import_scan_zip(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    token: TokenPayload = Depends(get_current_user),
) -> Dict[str, Any]:
    await require_role("admin", token)
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files supported")
    content = await file.read()
    buffer = io.BytesIO(content)
    vulns: List[Vulnerability] = []
    with ZipFile(buffer) as zf:
        for name in zf.namelist():
            tool = None
            lower_name = name.lower()
            if "wapiti" in lower_name:
                tool = "wapiti"
            elif "nikto" in lower_name:
                tool = "nikto"
            elif "sqlmap" in lower_name:
                tool = "sqlmap"
            elif "gobuster" in lower_name:
                tool = "gobuster"
            if not tool:
                continue
            with zf.open(name) as member:
                temp_path = Path("/tmp") / name.split("/")[-1]
                temp_path.write_bytes(member.read())
                parsed = await gather_and_normalize(tool, temp_path)
                for item in parsed:
                    enriched = await enrich_vulnerability_async(item.dict())
                    vuln = Vulnerability(**enriched)
                    score, _ = compute_priority(vuln)
                    vuln.priority_score = score
                    vulns.append(vuln)
    if not vulns:
        raise HTTPException(status_code=400, detail="No vulnerabilities found in archive")

    scan = Scan(id=str(uuid.uuid4()), target=vulns[0].target, tool="import", status="completed", created_at=datetime.utcnow())
    session.add(scan)
    await session.flush()
    stored: List[VulnerabilityORM] = []
    for vuln in vulns:
        record = VulnerabilityORM(**vuln.dict())
        record.scan_id = scan.id
        session.add(record)
        stored.append(record)
    await session.commit()
    return {"imported": len(stored), "scan_id": scan.id}


@router.get("/vulns/export/csv")
async def export_vulns_csv(session: AsyncSession = Depends(get_session)) -> JSONResponse:
    stmt = select(VulnerabilityORM)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "tool", "target", "title", "severity", "priority_score"])
    for row in rows:
        writer.writerow([row.id, row.tool, row.target, row.title, row.severity, row.priority_score])
    return JSONResponse(content={"data": buffer.getvalue()})
