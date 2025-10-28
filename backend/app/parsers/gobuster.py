from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

from app.models import Vulnerability
from app.services.prioritization import compute_priority
from .base import load_json


def parse_gobuster(path: Path) -> Iterable[Dict]:
    data = load_json(path)
    findings: List[Dict] = []
    for item in data.get("entries", []):
        vuln = Vulnerability(
            id_local=item.get("id_local"),
            scan_id=item.get("scan_id"),
            tool="gobuster",
            target=item.get("target", ""),
            path=item.get("path"),
            parameter=item.get("parameter"),
            title=item.get("title", "Gobuster finding"),
            description=item.get("description", ""),
            severity=item.get("severity"),
            cvss_v3=item.get("cvss_v3"),
            cve=item.get("cve", []),
            confidence=item.get("confidence"),
            evidence=item.get("evidence", {}),
            references=item.get("references", []),
            timestamp=datetime.fromisoformat(item.get("timestamp").replace("Z", "+00:00")),
            priority_score=item.get("priority_score"),
            exploitability_notes=item.get("exploitability_notes"),
        )
        score, _ = compute_priority(vuln)
        vuln.priority_score = score
        findings.append(vuln.dict())
    return findings
