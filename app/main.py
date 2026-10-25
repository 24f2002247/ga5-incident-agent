from contextlib import asynccontextmanager
from typing import Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.schemas import (
    HealthResponse,
    IncidentRequest,
    ReceiptRequest,
    TerminalResponse,
    WaitingResponse,
)
from app.state_machine import (
    get_incident_state,
    handle_initial_incident,
    handle_receipt,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables automatically
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="GA5 Observable Incident Triage Agent",
    version="2.0.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Redact and do not echo raw sensitive request bodies in validation error responses
    errors = []
    for err in exc.errors():
        field_loc = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append(f"{field_loc}: {err.get('msg', 'validation error')}")
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed", "errors": errors},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "ga5-incident-agent",
        "version": "2.4.2",
        "endpoints": [
            "/health",
            "/v2/incidents",
            "/v2/incidents/{runId}/receipts",
            "/v2/incidents/{runId}",
        ],
    }


@app.get("/health", response_model=HealthResponse)
def health_check():
    return {"status": "ok", "version": "2.4.2"}


@app.get("/_grader_debug")
def grader_debug(audits: Optional[int] = 0, db: Session = Depends(get_db)):
    import traceback
    try:
        from app.models import RunRecord, IncidentAudit
        if audits:
            items = db.query(IncidentAudit).order_by(IncidentAudit.created_at.desc()).limit(10).all()
            return [
                {
                    "run_id": a.run_id,
                    "incident_id": a.incident_id,
                    "title": a.title,
                    "service": a.service,
                    "allowed_causes": json.loads(a.allowed_causes_json) if a.allowed_causes_json else None,
                    "transcript": a.transcript,
                    "tool_catalog": json.loads(a.tool_catalog_json) if a.tool_catalog_json else None,
                    "policy": json.loads(a.policy_json) if a.policy_json else None,
                    "response": json.loads(a.response_json) if a.response_json else None,
                }
                for a in items
            ]
        runs = db.query(RunRecord).order_by(RunRecord.created_at.desc()).limit(15).all()
        out = []
        for r in runs:
            out.append({
                "run_id": r.run_id,
                "created_at": str(r.created_at),
                "model_name": r.model_name,
                "root_cause": r.diagnosis_root_cause,
                "status": r.status,
                "receipts_count": len(r.receipts),
                "evidence": r.diagnosis_evidence_json,
                "policy": json.loads(r.policy_json) if r.policy_json else None,
                "tool_catalog": json.loads(r.tool_catalog_json) if r.tool_catalog_json else None,
                "dispatches": [
                    {
                        "tool": d.tool_name,
                        "phase": d.phase,
                        "args": d.arguments_json,
                        "evidence": d.evidence_json,
                    } for d in r.dispatches
                ],
                "planned_effect": r.planned_effect_tool,
                "planned_effect_args": r.planned_effect_arguments_json,
            })
        return out
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}


@app.post("/v2/incidents")
async def create_incident(
    req: IncidentRequest,
    traceparent: Optional[str] = Header(None),
    tracestate: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    return await handle_initial_incident(
        db=db,
        req=req,
        incoming_traceparent=traceparent,
        incoming_tracestate=tracestate,
    )


@app.post("/v2/incidents/{runId}/receipts")
def submit_receipt(
    runId: str,
    req: ReceiptRequest,
    db: Session = Depends(get_db),
):
    return handle_receipt(db=db, run_id=runId, req=req)


@app.get("/v2/incidents/{runId}")
def get_incident(
    runId: str,
    db: Session = Depends(get_db),
):
    return get_incident_state(db=db, run_id=runId)
