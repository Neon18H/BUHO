from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.session import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)
    target = Column(String, nullable=False)
    tool = Column(String, nullable=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    logs = Column(Text, default="")

    vulnerabilities = relationship("VulnerabilityORM", back_populates="scan", cascade="all, delete-orphan")


class VulnerabilityORM(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    id_local = Column(String, unique=True, nullable=False)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String, nullable=False)
    target = Column(String, nullable=False)
    path = Column(String, nullable=True)
    parameter = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=True)
    cvss_v3 = Column(Float, nullable=True)
    cve = Column(JSON, default=list)
    confidence = Column(String, nullable=True)
    evidence = Column(JSON, nullable=False, default=dict)
    references = Column(JSON, default=list)
    timestamp = Column(DateTime, default=datetime.utcnow)
    priority_score = Column(Float, nullable=True)
    exploitability_notes = Column(Text, nullable=True)
    enrichment_metadata = Column(JSON, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")
