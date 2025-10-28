from typing import Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Scan, VulnerabilityORM
from app.models import Vulnerability


async def list_vulnerabilities(session: AsyncSession, limit: int = 100, offset: int = 0, severity: Optional[str] = None) -> List[VulnerabilityORM]:
    stmt = select(VulnerabilityORM).order_by(VulnerabilityORM.priority_score.desc()).offset(offset).limit(limit)
    if severity:
        stmt = stmt.where(VulnerabilityORM.severity == severity)
    result = await session.execute(stmt)
    return result.scalars().all()


async def get_vulnerability(session: AsyncSession, vuln_id: int) -> Optional[VulnerabilityORM]:
    stmt = select(VulnerabilityORM).where(VulnerabilityORM.id == vuln_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def upsert_vulnerabilities(session: AsyncSession, scan: Scan, vulns: Iterable[Vulnerability]) -> List[VulnerabilityORM]:
    stored: List[VulnerabilityORM] = []
    for vuln in vulns:
        stmt = select(VulnerabilityORM).where(VulnerabilityORM.id_local == vuln.id_local)
        existing = await session.execute(stmt)
        record = existing.scalar_one_or_none()
        if record:
            for field, value in vuln.dict().items():
                setattr(record, field, value)
        else:
            record = VulnerabilityORM(**vuln.dict())
            record.scan_id = scan.id
            session.add(record)
        stored.append(record)
    await session.commit()
    for record in stored:
        await session.refresh(record)
    return stored
