from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, field_validator


class IncidentData(BaseModel):
    incidentId: str
    title: str
    service: str
    severity: str
    transcript: str
    allowedRootCauses: List[str]


class ToolCatalogItem(BaseModel):
    name: str
    description: str
    inputSchema: Optional[Dict[str, Any]] = None


class PolicyData(BaseModel):
    maximumDiagnostics: int = Field(default=3, ge=1, le=10)
    effectTools: List[str] = Field(default_factory=list)
    approvalRequiredFor: List[str] = Field(default_factory=list)
    doNotExport: List[str] = Field(default_factory=list)


class IncidentRequest(BaseModel):
    profile: str
    runId: str
    agentName: str
    publicMarker: str
    sensitive: Optional[Dict[str, Any]] = None
    incident: IncidentData
    toolCatalog: List[ToolCatalogItem]
    policy: PolicyData

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        if v != "ga5-incident-agent/v2":
            raise ValueError(f"Unsupported profile: {v}")
        return v

    @field_validator("runId")
    @classmethod
    def validate_run_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("runId must be a nonempty string")
        return v.strip()


class DiagnosisData(BaseModel):
    rootCause: str
    evidence: List[str]


class DispatchItem(BaseModel):
    actionId: str
    callId: str
    phase: Literal["diagnostic", "effect"]
    toolName: str
    arguments: Dict[str, Any]
    evidence: List[str]
    attempt: int
    traceparent: str
    approvalId: Optional[str] = None
    approvalNonce: Optional[str] = None


class ApprovalItem(BaseModel):
    approvalId: str
    actionId: str
    toolName: str
    argumentsDigest: str


class ReceiptOutcome(BaseModel):
    actionId: str
    callId: str
    attempt: int
    status: int
    resultClass: Optional[str] = None
    nonce: str
    errorType: Optional[str] = None


class ApprovalDecision(BaseModel):
    approvalId: str
    decision: str
    nonce: str


class ReceiptRequest(BaseModel):
    receiptId: str
    outcomes: Optional[List[ReceiptOutcome]] = None
    approvals: Optional[List[ApprovalDecision]] = None

    @field_validator("receiptId")
    @classmethod
    def validate_receipt_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("receiptId must be a nonempty string")
        return v.strip()


class WaitingResponse(BaseModel):
    runId: str
    status: Literal["waiting"] = "waiting"
    diagnosis: DiagnosisData
    dispatches: List[DispatchItem] = Field(default_factory=list)
    approvals: List[ApprovalItem] = Field(default_factory=list)


class TerminalResponse(BaseModel):
    runId: str
    status: Literal["completed", "failed"]
    diagnosis: DiagnosisData
    chosenEffect: Optional[str] = None
    suppressed: List[str] = Field(default_factory=list)
    actionLog: List[Dict[str, Any]] = Field(default_factory=list)
    receiptLog: List[Dict[str, Any]] = Field(default_factory=list)
    otlp: Dict[str, Any]
    dispatches: List[DispatchItem] = Field(default_factory=list)
    approvals: List[ApprovalItem] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    version: str = "2.0.9"
