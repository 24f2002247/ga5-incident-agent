import json
import logging
import secrets
from typing import Any, Dict, List, Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.canonical import (
    canonical_json,
    compute_arguments_digest,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    parse_traceparent,
    sha256_hex,
)
from app.models import ApprovalRecord, DispatchRecord, ReceiptRecord, RunRecord
from app.planner import ModelPlanResult, plan_incident
from app.schemas import (
    ApprovalDecision,
    ApprovalItem,
    DiagnosisData,
    DispatchItem,
    IncidentRequest,
    ReceiptOutcome,
    ReceiptRequest,
    TerminalResponse,
    WaitingResponse,
)
from app.trace_builder import build_otlp_trace

logger = logging.getLogger("app.state_machine")


def build_action_log(dispatches: List[DispatchRecord], tracestate: Optional[str] = None) -> List[Dict[str, Any]]:
    """Builds the exact actionLog array of dispatches as originally issued."""
    log = []
    for d in sorted(dispatches, key=lambda x: x.issuance_order):
        item = {
            "actionId": d.action_id,
            "callId": d.call_id,
            "phase": d.phase,
            "toolName": d.tool_name,
            "arguments": json.loads(d.arguments_json),
            "evidence": json.loads(d.evidence_json),
            "attempt": d.attempt,
            "traceparent": d.traceparent,
        }
        if tracestate:
            item["tracestate"] = tracestate
        if d.approval_id:
            item["approvalId"] = d.approval_id
        if d.approval_nonce:
            item["approvalNonce"] = d.approval_nonce
        log.append(item)
    return log


def build_receipt_log(receipts: List[ReceiptRecord]) -> List[Dict[str, Any]]:
    """Builds the exact receiptLog array of accepted receipts."""
    log = []
    for r in sorted(receipts, key=lambda x: x.id):
        if r.receipt_type == "outcome":
            item = {
                "receiptId": r.receipt_id,
                "actionId": r.action_id,
                "callId": r.call_id,
                "attempt": r.attempt,
                "status": r.status,
                "nonce": r.nonce,
            }
            if r.result_class is not None:
                item["resultClass"] = r.result_class
            if r.error_type is not None:
                item["errorType"] = r.error_type
            log.append(item)
        elif r.receipt_type == "approval":
            item = {
                "receiptId": r.receipt_id,
                "approvalId": r.approval_id,
                "decision": r.decision,
                "nonce": r.nonce,
            }
            log.append(item)
    return log


def format_run_response(run: RunRecord) -> Dict[str, Any]:
    """Formats either waiting or terminal response based on run status."""
    evidence_list = json.loads(run.diagnosis_evidence_json)
    diagnosis = {
        "rootCause": run.diagnosis_root_cause,
        "evidence": evidence_list,
    }
    action_log = build_action_log(run.dispatches, tracestate=run.tracestate)
    receipt_log = build_receipt_log(run.receipts)

    if run.status in ("completed", "failed"):
        otlp = build_otlp_trace(run, run.dispatches, run.receipts, run.approvals)
        suppressed = json.loads(run.suppressed_json)

        return {
            "runId": run.run_id,
            "status": run.status,
            "diagnosis": diagnosis,
            "chosenEffect": run.chosen_effect,
            "suppressed": suppressed,
            "actionLog": action_log,
            "receiptLog": receipt_log,
            "otlp": otlp,
            "dispatches": [],
            "approvals": [],
        }

    # If run.status == "waiting"
    # Find pending dispatches
    pending_dispatches = [d for d in run.dispatches if d.status == "pending"]
    dispatches_data = []
    for d in sorted(pending_dispatches, key=lambda x: x.issuance_order):
        item = {
            "actionId": d.action_id,
            "callId": d.call_id,
            "phase": d.phase,
            "toolName": d.tool_name,
            "arguments": json.loads(d.arguments_json),
            "evidence": json.loads(d.evidence_json),
            "attempt": d.attempt,
            "traceparent": d.traceparent,
        }
        if run.tracestate:
            item["tracestate"] = run.tracestate
        if d.approval_id:
            item["approvalId"] = d.approval_id
        if d.approval_nonce:
            item["approvalNonce"] = d.approval_nonce
        dispatches_data.append(item)

    # Find pending approvals
    pending_approvals = [a for a in run.approvals if a.status == "pending"]
    approvals_data = []
    for a in pending_approvals:
        approvals_data.append({
            "approvalId": a.approval_id,
            "actionId": a.action_id,
            "toolName": a.tool_name,
            "argumentsDigest": a.arguments_digest,
        })

    return {
        "runId": run.run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": dispatches_data,
        "approvals": approvals_data,
        "actionLog": action_log,
        "receiptLog": receipt_log,
    }


async def handle_initial_incident(
    db: Session,
    req: IncidentRequest,
    incoming_traceparent: Optional[str] = None,
    incoming_tracestate: Optional[str] = None,
) -> Dict[str, Any]:
    """Handles POST /v2/incidents."""
    current_fingerprint = sha256_hex(canonical_json(req.model_dump()))

    # Check for existing run
    existing_run = db.query(RunRecord).filter(RunRecord.run_id == req.runId).first()
    if existing_run:
        if existing_run.canonical_fingerprint == current_fingerprint:
            # Replay of identical initial request
            return format_run_response(existing_run)
        else:
            # Changed content conflict
            raise HTTPException(status_code=409, detail="Run ID already exists with different request content.")

    # Commit read transaction to release connection back to pool while awaiting external model
    db.commit()

    # Call AI incident planner
    try:
        plan: ModelPlanResult = await plan_incident(req)
    except RuntimeError as e:
        # Controlled model configuration / availability error
        logger.error("Planner error: %s", str(e))
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error("Unexpected planner failure: %s", str(e))
        raise HTTPException(status_code=502, detail="Model planning failed")

    # Trace context setup
    parsed_tp = parse_traceparent(incoming_traceparent)
    if parsed_tp:
        trace_id, parent_span_id, _ = parsed_tp
        tracestate = incoming_tracestate
    else:
        trace_id = generate_trace_id()
        parent_span_id = None
        tracestate = None

    server_span_id = generate_span_id()
    agent_span_id = generate_span_id()
    plan_span_id = generate_span_id()

    join_span_id = generate_span_id() if len(plan.diagnostics) > 1 else None

    # Create run record
    new_run = RunRecord(
        run_id=req.runId,
        canonical_fingerprint=current_fingerprint,
        status="waiting",
        agent_name=req.agentName,
        public_marker=req.publicMarker,
        trace_id=trace_id,
        server_span_id=server_span_id,
        parent_span_id=parent_span_id,
        tracestate=tracestate,
        agent_span_id=agent_span_id,
        plan_span_id=plan_span_id,
        join_span_id=join_span_id,
        model_name=plan.model_name,
        diagnosis_root_cause=plan.root_cause,
        diagnosis_evidence_json=json.dumps(plan.evidence),
        policy_json=canonical_json(req.policy.model_dump()),
        tool_catalog_json=canonical_json([t.model_dump() for t in req.toolCatalog]),
        planned_effect_tool=plan.planned_effect_tool,
        planned_effect_arguments_json=canonical_json(plan.planned_effect_arguments),
        chosen_effect=None,
        suppressed_json="[]",
        current_stage="diagnostics",
    )
    db.add(new_run)
    db.flush()

    # Create initial dispatches for diagnostics
    order_idx = 1
    for diag in plan.diagnostics:
        action_id = f"act_{secrets.token_hex(6)}"
        call_id = f"call_{secrets.token_hex(6)}"
        client_span_id = generate_span_id()
        tp = format_traceparent(trace_id, client_span_id)

        dispatch = DispatchRecord(
            run_id=req.runId,
            action_id=action_id,
            call_id=call_id,
            phase="diagnostic",
            tool_name=diag["toolName"],
            arguments_json=canonical_json(diag["arguments"]),
            evidence_json=json.dumps(diag["evidence"]),
            attempt=1,
            client_span_id=client_span_id,
            traceparent=tp,
            issuance_order=order_idx,
            status="pending",
        )
        db.add(dispatch)
        order_idx += 1

    db.commit()
    db.refresh(new_run)

    resp = format_run_response(new_run)
    try:
        from app.models import IncidentAudit
        audit_record = IncidentAudit(
            run_id=req.runId,
            incident_id=req.incident.incidentId,
            title=req.incident.title,
            service=req.incident.service,
            severity=req.incident.severity,
            allowed_causes_json=json.dumps(req.incident.allowedRootCauses),
            transcript=req.incident.transcript,
            tool_catalog_json=canonical_json([t.model_dump() for t in req.toolCatalog]),
            policy_json=canonical_json(req.policy.model_dump()),
            response_json=canonical_json(resp),
        )
        db.add(audit_record)
        db.commit()
    except Exception as e:
        logger.warning("Audit record insert skipped: %s", str(e))

    return resp


def handle_receipt(db: Session, run_id: str, req: ReceiptRequest) -> Dict[str, Any]:
    """Handles POST /v2/incidents/{runId}/receipts."""
    run = db.query(RunRecord).filter(RunRecord.run_id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    receipt_fingerprint = sha256_hex(canonical_json(req.model_dump()))

    # Idempotency check for receipt
    existing_receipt = db.query(ReceiptRecord).filter(
        ReceiptRecord.run_id == run_id,
        ReceiptRecord.receipt_id == req.receiptId,
    ).first()

    if existing_receipt:
        if existing_receipt.canonical_fingerprint == receipt_fingerprint:
            # Replay of identical receipt
            return format_run_response(run)
        else:
            raise HTTPException(status_code=409, detail="Receipt ID already exists with different content")

    # Policy details
    policy_data = json.loads(run.policy_json)
    approval_required_tools = set(policy_data.get("approvalRequiredFor", []))

    # Case 1: Tool outcomes
    if req.outcomes is not None:
        if not req.outcomes:
            raise HTTPException(status_code=422, detail="Outcomes list cannot be empty")

        for outcome in req.outcomes:
            # Validate against pending dispatches
            dispatch = db.query(DispatchRecord).filter(
                DispatchRecord.run_id == run_id,
                DispatchRecord.action_id == outcome.actionId,
                DispatchRecord.attempt == outcome.attempt,
            ).first()

            if not dispatch:
                raise HTTPException(
                    status_code=422,
                    detail=f"No matching dispatch for action {outcome.actionId} attempt {outcome.attempt}",
                )

            if dispatch.call_id != outcome.callId:
                raise HTTPException(
                    status_code=422,
                    detail=f"Mismatched callId {outcome.callId} for action {outcome.actionId}",
                )

            if dispatch.status != "pending":
                raise HTTPException(
                    status_code=422,
                    detail=f"Dispatch {outcome.actionId} attempt {outcome.attempt} is not pending (status: {dispatch.status})",
                )

            # Record accepted receipt
            rec = ReceiptRecord(
                run_id=run_id,
                receipt_id=req.receiptId,
                canonical_fingerprint=receipt_fingerprint,
                receipt_type="outcome",
                action_id=outcome.actionId,
                call_id=outcome.callId,
                attempt=outcome.attempt,
                status=outcome.status,
                result_class=outcome.resultClass,
                nonce=outcome.nonce,
                error_type=outcome.errorType,
            )
            db.add(rec)

            # Handle 503 Retry
            if outcome.status == 503:
                if outcome.attempt == 1:
                    # Exactly one retry permitted
                    dispatch.status = "retried"
                    new_client_span_id = generate_span_id()
                    new_tp = format_traceparent(run.trace_id, new_client_span_id)

                    max_order = (
                        db.query(DispatchRecord.issuance_order)
                        .filter(DispatchRecord.run_id == run_id)
                        .order_by(DispatchRecord.issuance_order.desc())
                        .first()
                    )[0]

                    retry_dispatch = DispatchRecord(
                        run_id=run_id,
                        action_id=outcome.actionId,
                        call_id=outcome.callId,
                        phase=dispatch.phase,
                        tool_name=dispatch.tool_name,
                        arguments_json=dispatch.arguments_json,
                        evidence_json=dispatch.evidence_json,
                        attempt=2,
                        client_span_id=new_client_span_id,
                        traceparent=new_tp,
                        issuance_order=max_order + 1,
                        status="pending",
                    )
                    db.add(retry_dispatch)
                    db.commit()
                    db.refresh(run)
                    return format_run_response(run)
                else:
                    # Second 503 fails the run and suppresses dependent effect
                    dispatch.status = "failed"
                    run.status = "failed"
                    suppressed_list = [run.planned_effect_tool] if run.planned_effect_tool else []
                    run.suppressed_json = json.dumps(suppressed_list)
                    run.chosen_effect = None
                    db.commit()
                    db.refresh(run)
                    return format_run_response(run)

            # Handle Timeout (status: 0, errorType: "timeout")
            elif outcome.status == 0 or (outcome.errorType and outcome.errorType.lower() == "timeout"):
                dispatch.status = "failed"
                run.status = "failed"
                suppressed_list = [run.planned_effect_tool] if run.planned_effect_tool else []
                run.suppressed_json = json.dumps(suppressed_list)
                run.chosen_effect = None
                db.commit()
                db.refresh(run)
                return format_run_response(run)

            # Handle Success (200)
            elif outcome.status == 200:
                dispatch.status = "completed"

                if dispatch.phase == "effect":
                    # Effect succeeded, complete run
                    run.status = "completed"
                    run.chosen_effect = dispatch.tool_name
                    db.commit()
                    db.refresh(run)
                    return format_run_response(run)

        # Flush receipts and dispatch updates
        db.flush()

        # Check diagnostic completion
        # If any pending diagnostics remain, continue waiting
        pending_diags = (
            db.query(DispatchRecord)
            .filter(
                DispatchRecord.run_id == run_id,
                DispatchRecord.phase == "diagnostic",
                DispatchRecord.status == "pending",
            )
            .count()
        )
        if pending_diags > 0:
            db.commit()
            db.refresh(run)
            return format_run_response(run)

        # All diagnostics completed! Now evaluate effect
        planned_effect_tool = run.planned_effect_tool
        if not planned_effect_tool:
            run.status = "completed"
            db.commit()
            db.refresh(run)
            return format_run_response(run)

        planned_effect_args = json.loads(run.planned_effect_arguments_json or "{}")

        # Check scaling limit rule: "When a service is already at its permitted scaling limit, page the owner instead of scaling."
        all_receipts = db.query(ReceiptRecord).filter(ReceiptRecord.run_id == run_id).all()
        diagnostic_scaling_limit = any(
            (r.result_class and any(term in r.result_class.lower() for term in ["limit", "max", "capacity", "scaling_limit"]))
            or (r.error_type and any(term in r.error_type.lower() for term in ["limit", "max", "capacity"]))
            for r in all_receipts
        )

        catalog_tools = json.loads(run.tool_catalog_json or "[]")
        catalog_names = [t["name"] if isinstance(t, dict) else t for t in catalog_tools]
        available_effects = policy_data.get("effectTools") or catalog_names

        if diagnostic_scaling_limit and planned_effect_tool in ["scale_service", "scale_up", "autoscale"]:
            for candidate in ["page_service_owner", "page_owner", "alert_owner", "escalate_to_owner"]:
                if candidate in available_effects:
                    planned_effect_tool = candidate
                    # Extract service name from previous args or agent_name
                    svc = planned_effect_args.get("service") or run.agent_name
                    planned_effect_args = {"service": svc, "reason": "Scaling limit reached"}
                    run.planned_effect_tool = candidate
                    run.planned_effect_arguments_json = canonical_json(planned_effect_args)
                    break

        # Check if effect requires approval
        if planned_effect_tool in approval_required_tools:
            # Approval Gate
            approval_id = f"app_{secrets.token_hex(6)}"
            reserved_action_id = f"act_{secrets.token_hex(6)}"
            args_digest = compute_arguments_digest(planned_effect_args)

            approval_rec = ApprovalRecord(
                approval_id=approval_id,
                run_id=run_id,
                action_id=reserved_action_id,
                tool_name=planned_effect_tool,
                arguments_digest=args_digest,
                arguments_json=canonical_json(planned_effect_args),
                status="pending",
            )
            db.add(approval_rec)
            run.approval_gate_span_id = generate_span_id()
            run.current_stage = "waiting_approval"
            db.commit()
            db.refresh(run)
            return format_run_response(run)
        else:
            # Non-destructive effect (e.g. scale_service)
            action_id = f"act_{secrets.token_hex(6)}"
            call_id = f"call_{secrets.token_hex(6)}"
            client_span_id = generate_span_id()
            tp = format_traceparent(run.trace_id, client_span_id)

            max_order = (
                db.query(DispatchRecord.issuance_order)
                .filter(DispatchRecord.run_id == run_id)
                .order_by(DispatchRecord.issuance_order.desc())
                .first()
            )[0]

            effect_dispatch = DispatchRecord(
                run_id=run_id,
                action_id=action_id,
                call_id=call_id,
                phase="effect",
                tool_name=planned_effect_tool,
                arguments_json=canonical_json(planned_effect_args),
                evidence_json="[]",
                attempt=1,
                client_span_id=client_span_id,
                traceparent=tp,
                issuance_order=max_order + 1,
                status="pending",
            )
            db.add(effect_dispatch)
            run.chosen_effect = planned_effect_tool
            run.current_stage = "executing_effect"
            db.commit()
            db.refresh(run)
            return format_run_response(run)

    # Case 2: Approvals
    elif req.approvals is not None:
        if not req.approvals:
            raise HTTPException(status_code=422, detail="Approvals list cannot be empty")

        for app_decision in req.approvals:
            approval_rec = db.query(ApprovalRecord).filter(
                ApprovalRecord.run_id == run_id,
                ApprovalRecord.approval_id == app_decision.approvalId,
            ).first()

            if not approval_rec:
                raise HTTPException(
                    status_code=422,
                    detail=f"Approval ID {app_decision.approvalId} not found for run",
                )

            if approval_rec.status != "pending":
                raise HTTPException(
                    status_code=422,
                    detail=f"Approval {app_decision.approvalId} is already {approval_rec.status}",
                )

            if not app_decision.nonce or not app_decision.nonce.strip():
                raise HTTPException(status_code=422, detail="Approval nonce must be non-empty")

            # Record accepted receipt
            rec = ReceiptRecord(
                run_id=run_id,
                receipt_id=req.receiptId,
                canonical_fingerprint=receipt_fingerprint,
                receipt_type="approval",
                approval_id=app_decision.approvalId,
                decision=app_decision.decision,
                nonce=app_decision.nonce,
            )
            db.add(rec)

            if app_decision.decision.lower() == "approved":
                approval_rec.status = "approved"
                approval_rec.nonce = app_decision.nonce

                # Dispatch destructive effect using the reserved actionId
                call_id = f"call_{secrets.token_hex(6)}"
                client_span_id = generate_span_id()
                tp = format_traceparent(run.trace_id, client_span_id)

                max_order = (
                    db.query(DispatchRecord.issuance_order)
                    .filter(DispatchRecord.run_id == run_id)
                    .order_by(DispatchRecord.issuance_order.desc())
                    .first()
                )[0]

                destructive_dispatch = DispatchRecord(
                    run_id=run_id,
                    action_id=approval_rec.action_id,  # Use reserved actionId!
                    call_id=call_id,
                    phase="effect",
                    tool_name=approval_rec.tool_name,
                    arguments_json=approval_rec.arguments_json,
                    evidence_json="[]",
                    attempt=1,
                    client_span_id=client_span_id,
                    traceparent=tp,
                    approval_id=app_decision.approvalId,
                    approval_nonce=app_decision.nonce,
                    issuance_order=max_order + 1,
                    status="pending",
                )
                db.add(destructive_dispatch)
                run.chosen_effect = approval_rec.tool_name
                run.current_stage = "executing_effect"
                db.commit()
                db.refresh(run)
                return format_run_response(run)
            else:
                # Rejected approval
                approval_rec.status = "rejected"
                approval_rec.nonce = app_decision.nonce
                run.status = "failed"
                run.suppressed_json = json.dumps([approval_rec.tool_name])
                run.chosen_effect = None
                db.commit()
                db.refresh(run)
                return format_run_response(run)

    raise HTTPException(status_code=422, detail="Receipt must contain either outcomes or approvals")


def get_incident_state(db: Session, run_id: str) -> Dict[str, Any]:
    """Handles GET /v2/incidents/{runId}."""
    run = db.query(RunRecord).filter(RunRecord.run_id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return format_run_response(run)
