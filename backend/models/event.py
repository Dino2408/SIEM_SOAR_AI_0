from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, JSON, Enum
from sqlalchemy.dialects.postgresql import JSONB, ARRAY as PG_ARRAY
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum
from core.database import Base

class SeverityEnum(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class StatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String)
    event_type = Column(String, index=True)
    severity = Column(Enum(SeverityEnum))
    raw_log = Column(String)
    parsed_data = Column(JSONB)
    tags = Column(PG_ARRAY(String))
    mitre_technique = Column(String)
    confidence_score = Column(Float)
    status = Column(String)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    event_ids = Column(PG_ARRAY(Integer))
    title = Column(String)
    description = Column(String)
    severity = Column(Enum(SeverityEnum))
    status = Column(Enum(StatusEnum), default=StatusEnum.OPEN)
    assigned_to = Column(String, nullable=True)
    ai_analysis = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    alert_ids = Column(PG_ARRAY(Integer))
    title = Column(String)
    severity = Column(Enum(SeverityEnum))
    status = Column(Enum(StatusEnum), default=StatusEnum.OPEN)
    timeline = Column(JSONB)
    response_actions = Column(JSONB)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    playbook = relationship("Playbook")

class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    steps = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"))
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    status = Column(String)
    results = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

