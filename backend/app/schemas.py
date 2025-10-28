from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from .models import ScanStatus, Severity
from .services.tooling import TOOL_REGISTRY


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

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, value: List[str]) -> List[str]:
        normalized = [tool.lower() for tool in value]
        unknown = sorted({tool for tool in normalized if tool not in TOOL_REGISTRY})
        if unknown:
            available = ", ".join(sorted(TOOL_REGISTRY.keys()))
            raise ValueError(
                "Herramientas no soportadas: "
                + ", ".join(unknown)
                + f". Opciones válidas: {available}."
            )

        deduped: List[str] = []
        seen: set[str] = set()
        for tool in normalized:
            if tool in seen:
                continue
            seen.add(tool)
            deduped.append(tool)
        return deduped


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
