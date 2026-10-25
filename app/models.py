import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database import Base


class RunRecord(Base):
    __tablename__ = "incident_runs"

    run_id = Column(String(128), primary_key=True, index=True)
    canonical_fingerprint = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="waiting")  # waiting, completed, failed
    agent_name = Column(String(128), nullable=False, default="incident-response")
    public_marker = Column(String(128), nullable=False)
    
    # Trace context
    trace_id = Column(String(32), nullable=False)
    server_span_id = Column(String(16), nullable=False)
    parent_span_id = Column(String(16), nullable=True)
    tracestate = Column(String(256), nullable=True)
    agent_span_id = Column(String(16), nullable=False)
    plan_span_id = Column(String(16), nullable=False)
    join_span_id = Column(String(16), nullable=True)
    approval_gate_span_id = Column(String(16), nullable=True)
    model_name = Column(String(128), nullable=False)

    # Diagnosis and Policy
    diagnosis_root_cause = Column(String(256), nullable=False)
    diagnosis_evidence_json = Column(Text, nullable=False)  # JSON list
    policy_json = Column(Text, nullable=False)  # JSON dict
    tool_catalog_json = Column(Text, nullable=False)  # JSON list

    # Plan Effect Strategy
    planned_effect_tool = Column(String(128), nullable=True)
    planned_effect_arguments_json = Column(Text, nullable=True)
    chosen_effect = Column(String(128), nullable=True)
    suppressed_json = Column(Text, nullable=False, default="[]")  # JSON list
    current_stage = Column(String(64), nullable=False, default="diagnostics")

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    dispatches = relationship("DispatchRecord", back_populates="run", cascade="all, delete-orphan", order_by="DispatchRecord.issuance_order")
    receipts = relationship("ReceiptRecord", back_populates="run", cascade="all, delete-orphan", order_by="ReceiptRecord.id")
    approvals = relationship("ApprovalRecord", back_populates="run", cascade="all, delete-orphan")


class DispatchRecord(Base):
    __tablename__ = "incident_dispatches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(128), ForeignKey("incident_runs.run_id"), nullable=False, index=True)
    action_id = Column(String(128), nullable=False, index=True)
    call_id = Column(String(128), nullable=False)
    phase = Column(String(32), nullable=False)  # diagnostic, effect
    tool_name = Column(String(128), nullable=False)
    arguments_json = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=False)  # JSON list
    attempt = Column(Integer, nullable=False, default=1)
    client_span_id = Column(String(16), nullable=False)
    traceparent = Column(String(128), nullable=False)
    approval_id = Column(String(128), nullable=True)
    approval_nonce = Column(String(128), nullable=True)
    issuance_order = Column(Integer, nullable=False, default=0)
    status = Column(String(32), nullable=False, default="pending")  # pending, completed, retried, failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    run = relationship("RunRecord", back_populates="dispatches")


class ReceiptRecord(Base):
    __tablename__ = "incident_receipts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(128), ForeignKey("incident_runs.run_id"), nullable=False, index=True)
    receipt_id = Column(String(128), nullable=False, index=True)
    canonical_fingerprint = Column(String(64), nullable=False)
    receipt_type = Column(String(32), nullable=False)  # outcome, approval

    # Outcome fields
    action_id = Column(String(128), nullable=True)
    call_id = Column(String(128), nullable=True)
    attempt = Column(Integer, nullable=True)
    status = Column(Integer, nullable=True)
    result_class = Column(String(128), nullable=True)
    nonce = Column(String(128), nullable=False)
    error_type = Column(String(128), nullable=True)

    # Approval fields
    approval_id = Column(String(128), nullable=True)
    decision = Column(String(32), nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    run = relationship("RunRecord", back_populates="receipts")


class ApprovalRecord(Base):
    __tablename__ = "incident_approvals"

    approval_id = Column(String(128), primary_key=True, index=True)
    run_id = Column(String(128), ForeignKey("incident_runs.run_id"), nullable=False, index=True)
    action_id = Column(String(128), nullable=False)
    tool_name = Column(String(128), nullable=False)
    arguments_digest = Column(String(64), nullable=False)
    arguments_json = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="pending")  # pending, approved, rejected
    nonce = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    run = relationship("RunRecord", back_populates="approvals")


class IncidentAudit(Base):
    __tablename__ = "incident_audits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(128), index=True)
    incident_id = Column(String(128), nullable=True)
    title = Column(String(256), nullable=True)
    service = Column(String(128), nullable=True)
    severity = Column(String(32), nullable=True)
    allowed_causes_json = Column(Text, nullable=True)
    transcript = Column(Text, nullable=True)
    tool_catalog_json = Column(Text, nullable=True)
    policy_json = Column(Text, nullable=True)
    response_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

