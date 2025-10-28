from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel


class Vulnerability(BaseModel):
    id_local: str
    scan_id: str
    tool: Literal['wapiti','nikto','sqlmap','gobuster']
    target: str
    path: Optional[str]
    parameter: Optional[str]
    title: str
    description: str
    severity: Optional[str]  # low, medium, high, critical
    cvss_v3: Optional[float]
    cve: List[str]
    confidence: Optional[str]  # low/medium/high
    evidence: Dict[str, Any]  # request/response snippets
    references: List[str]
    timestamp: datetime
    priority_score: Optional[float]
    exploitability_notes: Optional[str]


class VulnerabilityResponse(Vulnerability):
    id: int


class VulnerabilityCreate(Vulnerability):
    pass
