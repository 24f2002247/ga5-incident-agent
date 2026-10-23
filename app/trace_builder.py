import datetime
from typing import Any, Dict, List, Optional
from app.canonical import sha256_hex
from app.models import ApprovalRecord, DispatchRecord, ReceiptRecord, RunRecord


def make_attr(key: str, value: Any) -> Dict[str, Any]:
    """Formats an OTLP attribute value object."""
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    elif isinstance(value, int):
        return {"key": key, "value": {"intValue": value}}
    elif isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    else:
        return {"key": key, "value": {"stringValue": str(value)}}


def get_logical_tool_span_id(trace_id: str, action_id: str) -> str:
    """Deterministically generates a 16-hex span ID for an execute_tool logical span."""
    return sha256_hex(f"exec_tool:{trace_id}:{action_id}")[:16]


def build_otlp_trace(
    run: RunRecord,
    dispatches: List[DispatchRecord],
    receipts: List[ReceiptRecord],
    approvals: List[ApprovalRecord],
) -> Dict[str, Any]:
    """
    Deterministically builds an OTLP trace JSON matching all specification requirements.
    Never exports prompts, transcripts, sensitive values, tool arguments, or tool results.
    """
    trace_id = run.trace_id.lower()
    public_marker = run.public_marker
    run_id = run.run_id

    # Base timestamp from run.created_at
    base_ns = int(run.created_at.timestamp() * 1_000_000_000) if run.created_at else 1700000000000000000

    spans: List[Dict[str, Any]] = []

    # 1. SERVER span: POST /v2/incidents
    server_span_id = run.server_span_id.lower()
    server_attrs = [
        make_attr("ga5.run.id", run_id),
        make_attr("ga5.public.marker", public_marker),
        make_attr("http.request.method", "POST"),
        make_attr("http.route", "/v2/incidents"),
    ]
    server_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2,  # SERVER
        "startTimeUnixNano": str(base_ns),
        "endTimeUnixNano": str(base_ns + 1_000_000_000),
        "attributes": server_attrs,
        "status": {"code": 1},  # OK
    }
    if run.parent_span_id:
        server_span["parentSpanId"] = run.parent_span_id.lower()

    spans.append(server_span)

    # 2. INTERNAL span: invoke_agent incident-response
    agent_span_id = run.agent_span_id.lower()
    agent_attrs = [
        make_attr("ga5.run.id", run_id),
        make_attr("ga5.public.marker", public_marker),
    ]
    agent_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": f"invoke_agent {run.agent_name}",
        "kind": 1,  # INTERNAL
        "startTimeUnixNano": str(base_ns + 10_000_000),
        "endTimeUnixNano": str(base_ns + 990_000_000),
        "attributes": agent_attrs,
        "status": {"code": 1},  # OK
    }
    spans.append(agent_span)

    # 3. CLIENT span: chat incident-plan (exactly one per first-seen run)
    plan_span_id = run.plan_span_id.lower()
    plan_attrs = [
        make_attr("ga5.run.id", run_id),
        make_attr("ga5.public.marker", public_marker),
        make_attr("gen_ai.operation.name", "chat"),
        make_attr("gen_ai.request.model", run.model_name or "gpt-4o-mini"),
    ]
    plan_span: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": plan_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3,  # CLIENT
        "startTimeUnixNano": str(base_ns + 20_000_000),
        "endTimeUnixNano": str(base_ns + 200_000_000),
        "attributes": plan_attrs,
        "status": {"code": 1},  # OK
    }
    spans.append(plan_span)

    # Group dispatches by logical action_id
    # Every logical action has one INTERNAL execute_tool <toolName>
    # and each physical attempt has one CLIENT POST tool/<toolName>
    dispatches_by_action: Dict[str, List[DispatchRecord]] = {}
    for d in dispatches:
        dispatches_by_action.setdefault(d.action_id, []).append(d)

    # Map receipts by (action_id, attempt)
    receipts_by_action_attempt: Dict[tuple[str, int], ReceiptRecord] = {}
    for r in receipts:
        if r.receipt_type == "outcome" and r.action_id and r.attempt is not None:
            receipts_by_action_attempt[(r.action_id, r.attempt)] = r

    # Collect diagnostic execute_tool span IDs for incident.join links
    diagnostic_tool_span_ids: List[str] = []

    # Sort actions by their earliest dispatch issuance_order
    sorted_actions = sorted(
        dispatches_by_action.keys(),
        key=lambda act_id: min(d.issuance_order for d in dispatches_by_action[act_id]),
    )

    action_offset = 250_000_000
    for act_id in sorted_actions:
        action_dispatches = sorted(dispatches_by_action[act_id], key=lambda d: d.attempt)
        first_d = action_dispatches[0]
        tool_name = first_d.tool_name
        logical_span_id = get_logical_tool_span_id(trace_id, act_id)

        if first_d.phase == "diagnostic":
            diagnostic_tool_span_ids.append(logical_span_id)

        # 4a. INTERNAL execute_tool <toolName>
        logical_attrs = [
            make_attr("ga5.run.id", run_id),
            make_attr("ga5.public.marker", public_marker),
            make_attr("ga5.action.id", act_id),
            make_attr("gen_ai.tool.name", tool_name),
            make_attr("gen_ai.tool.call.id", first_d.call_id),
            make_attr("gen_ai.operation.name", "execute_tool"),
        ]
        logical_span: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": logical_span_id,
            "parentSpanId": agent_span_id,
            "name": f"execute_tool {tool_name}",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(base_ns + action_offset),
            "endTimeUnixNano": str(base_ns + action_offset + 100_000_000),
            "attributes": logical_attrs,
            "status": {"code": 1},
        }
        spans.append(logical_span)

        # 4b. CLIENT POST tool/<toolName> for each physical attempt
        attempt_offset = action_offset + 10_000_000
        for d in action_dispatches:
            client_span_id = d.client_span_id.lower()
            attempt_num = d.attempt
            receipt = receipts_by_action_attempt.get((act_id, attempt_num))

            client_attrs = [
                make_attr("ga5.run.id", run_id),
                make_attr("ga5.public.marker", public_marker),
                make_attr("ga5.action.id", act_id),
                make_attr("ga5.attempt", attempt_num),
                make_attr("http.request.method", "POST"),
                make_attr("http.request.resend_count", attempt_num - 1),
            ]

            span_status_code = 1  # default OK
            error_type = None

            if receipt:
                client_attrs.append(make_attr("ga5.receipt.id", receipt.receipt_id))
                client_attrs.append(make_attr("ga5.receipt.nonce", receipt.nonce))
                if receipt.status is not None:
                    client_attrs.append(make_attr("http.response.status_code", receipt.status))

                if receipt.status == 503:
                    span_status_code = 2  # ERROR
                    error_type = "503"
                elif receipt.status == 0 or receipt.error_type == "timeout":
                    span_status_code = 2  # ERROR
                    error_type = "timeout"
                elif receipt.status and receipt.status >= 400:
                    span_status_code = 2
                    error_type = str(receipt.status)
            else:
                # If no receipt yet (pending attempt)
                client_attrs.append(make_attr("ga5.receipt.id", "pending"))
                client_attrs.append(make_attr("ga5.receipt.nonce", "pending"))

            if error_type:
                client_attrs.append(make_attr("error.type", error_type))

            physical_span: Dict[str, Any] = {
                "traceId": trace_id,
                "spanId": client_span_id,
                "parentSpanId": logical_span_id,
                "name": f"POST tool/{tool_name}",
                "kind": 3,  # CLIENT
                "startTimeUnixNano": str(base_ns + attempt_offset),
                "endTimeUnixNano": str(base_ns + attempt_offset + 40_000_000),
                "attributes": client_attrs,
                "status": {"code": span_status_code},
            }
            spans.append(physical_span)
            attempt_offset += 45_000_000

        action_offset += 120_000_000

    # 5. INTERNAL incident.join (when diagnostics fan out, i.e. > 1 diagnostic tool)
    if len(diagnostic_tool_span_ids) > 1:
        join_span_id = run.join_span_id or sha256_hex(f"join:{trace_id}")[:16]
        join_links = [{"traceId": trace_id, "spanId": sid} for sid in diagnostic_tool_span_ids]
        join_attrs = [
            make_attr("ga5.run.id", run_id),
            make_attr("ga5.public.marker", public_marker),
        ]
        join_span: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": join_span_id.lower(),
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(base_ns + action_offset),
            "endTimeUnixNano": str(base_ns + action_offset + 10_000_000),
            "attributes": join_attrs,
            "status": {"code": 1},
            "links": join_links,
        }
        spans.append(join_span)
        action_offset += 15_000_000

    # 6. INTERNAL approval_gate (when approval is required)
    approval_receipt = next((r for r in receipts if r.receipt_type == "approval"), None)
    if approvals or approval_receipt or run.approval_gate_span_id:
        app_rec = approvals[0] if approvals else None
        gate_span_id = run.approval_gate_span_id or sha256_hex(f"app_gate:{trace_id}")[:16]
        gate_attrs = [
            make_attr("ga5.run.id", run_id),
            make_attr("ga5.public.marker", public_marker),
        ]
        app_id = (app_rec.approval_id if app_rec else None) or (approval_receipt.approval_id if approval_receipt else None) or "app_unknown"
        gate_attrs.append(make_attr("ga5.approval.id", app_id))

        app_nonce = (approval_receipt.nonce if approval_receipt else (app_rec.nonce if app_rec and app_rec.nonce else None))
        if app_nonce:
            gate_attrs.append(make_attr("ga5.approval.nonce", app_nonce))

        gate_span: Dict[str, Any] = {
            "traceId": trace_id,
            "spanId": gate_span_id.lower(),
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(base_ns + action_offset),
            "endTimeUnixNano": str(base_ns + action_offset + 15_000_000),
            "attributes": gate_attrs,
            "status": {"code": 1},
        }
        spans.append(gate_span)

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        make_attr("service.name", "ga5-incident-agent"),
                        make_attr("ga5.run.id", run_id),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "ga5.incident.agent",
                            "version": "1.0.0",
                        },
                        "spans": spans,
                    }
                ],
            }
        ]
    }
