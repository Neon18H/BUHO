from datetime import datetime
from sqlalchemy import Column, DateTime, Enum, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
import uuid

from .db import Base


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "informational"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(String(2048), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)
    requested_tools = Column(JSON, default=list)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    findings = relationship("Finding", back_populates="scan", cascade="all,delete-orphan")
    target = relationship("Target", back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    tool = Column(String(50), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict)
    severity = Column(Enum(Severity), default=Severity.info)
    cve = Column(String(50), nullable=True)
    remediation = Column(Text, nullable=True)
    exploitation = Column(Text, nullable=True)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
