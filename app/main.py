from contextlib import asynccontextmanager
from typing import Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session

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


@app.get("/health", response_model=HealthResponse)
def health_check():
    return {"status": "ok", "version": "2.0.0"}


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
