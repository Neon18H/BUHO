from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from .models import ScanStatus, Severity


class FindingBase(BaseModel):
    tool: str
    title: str
    description: str
    severity: Severity
    cve: Optional[str] = None
    remediation: Optional[str] = None
    exploitation: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingCreate(FindingBase):
    pass


class FindingRead(FindingBase):
    id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanBase(BaseModel):
    target: HttpUrl
    tools: List[str] = Field(
        default_factory=lambda: ["wapiti", "nikto", "sqlmap", "gobuster"]
    )


class ScanCreate(ScanBase):
    pass


class ScanRead(BaseModel):
    id: UUID
    status: ScanStatus
    target: HttpUrl
    requested_tools: List[str]
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    findings: List[FindingRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class TargetRead(BaseModel):
    id: UUID
    url: HttpUrl
    created_at: datetime
    scans: List[ScanRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
