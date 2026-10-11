import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from database import Base
import sqlalchemy.types as types

class StringUUID(types.TypeDecorator):
    impl = types.String
    cache_ok = True
    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(types.String())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(value)
        return str(value)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(StringUUID, primary_key=True, default=lambda: str(uuid.uuid4()))
    pid = Column(Integer, index=True)
    create_time = Column(Float, index=True)
    process_name = Column(String)
    cmdline = Column(JSON)
    start_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="Monitoring")
    max_score = Column(Float, default=0.0)
    contained_after_ms = Column(Integer, nullable=True)
    affected_count = Column(Integer, default=0)
    restored_count = Column(Integer, default=0)

class Event(Base):
    __tablename__ = "events"
    id = Column(StringUUID, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(StringUUID, ForeignKey("incidents.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    write_rate = Column(Float, default=0.0)
    rename_rate = Column(Float, default=0.0)
    entropy = Column(Float, default=0.0)
    score = Column(Float, default=0.0)
    tier = Column(Integer, default=0)
    canary_touched = Column(Boolean, default=False)
    signal_contributions = Column(JSON)

class AlertReason(Base):
    __tablename__ = "alert_reasons"
    id = Column(StringUUID, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(StringUUID, ForeignKey("incidents.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    reason = Column(String)
    signal_name = Column(String)
    contribution_score = Column(Float)

class Action(Base):
    __tablename__ = "actions"
    id = Column(StringUUID, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(StringUUID, ForeignKey("incidents.id"))
    type = Column(String)
    status = Column(String, default="pending")  # pending, delivered, complete, failed
    created_time = Column(DateTime, default=datetime.utcnow)
    delivered_time = Column(DateTime, nullable=True)
    retry_count = Column(Integer, default=0)
    failure_reason = Column(String, nullable=True)
    payload = Column(JSON)
    result = Column(JSON)
