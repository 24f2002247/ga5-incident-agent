import json
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from app.main import app

from app.canonical import (
    canonical_json,
    compute_arguments_digest,
    format_traceparent,
    parse_traceparent,
    sha256_hex,
)
from app.planner import ModelPlanResult


SAMPLE_TRANSCRIPT = (
    "2026-10-23T10:00:00Z [ev_boot] Starting auth-gateway service\n"
    "2026-10-23T10:01:00Z [ev_load] Traffic spike: 15,000 req/s\n"
    "2026-10-23T10:02:00Z [ev_pool_exhaust] Database connection pool limit reached: 100/100 active connections\n"
    "2026-10-23T10:03:00Z Customer says 'Checkout is completely down'\n"
    "2026-10-23T10:04:00Z [ev_timeout] Upstream queries to postgres-primary timing out after 5000ms\n"
    "2026-10-23T10:05:00Z [ev_scale_limit] Maximum instances reached (10/10), cannot auto-scale further\n"
)

SAMPLE_CATALOG = [
    {
        "name": "query_db_pool",
        "description": "Checks current database connection pool usage",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}},
    },
    {
        "name": "check_db_latency",
        "description": "Checks query latency to postgres",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}},
    },
    {
        "name": "rollback_deployment",
        "description": "Rolls back service to previous release",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}, "targetVersion": {"type": "string"}}},
    },
    {
        "name": "page_service_owner",
        "description": "Pages the on-call owner for the service",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}, "reason": {"type": "string"}}},
    },
    {
        "name": "scale_service",
        "description": "Scales service replicas",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}, "replicas": {"type": "integer"}}},
    },
]

SAMPLE_POLICY = {
    "maximumDiagnostics": 3,
    "effectTools": ["rollback_deployment", "page_service_owner", "scale_service"],
    "approvalRequiredFor": ["rollback_deployment", "disable_feature"],
    "doNotExport": ["accessToken", "privateNote"],
}


def make_sample_request(run_id="run_test_001"):
    return {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": "marker_pub_999",
        "sensitive": {
            "accessToken": "secret_super_token_do_not_leak",
            "privateNote": "Confidential customer details do not export",
        },
        "incident": {
            "incidentId": "inc_auth_999",
            "title": "Auth Gateway Database Connection Starvation",
            "service": "auth-gateway",
            "severity": "SEV-1",
            "transcript": SAMPLE_TRANSCRIPT,
            "allowedRootCauses": [
                "database_pool_exhaustion",
                "network_partition",
                "bad_canary_deployment",
            ],
        },
        "toolCatalog": SAMPLE_CATALOG,
        "policy": SAMPLE_POLICY,
    }


# 1. Health check
def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_root_endpoint(client):
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "endpoints" in data


# 2. Unsupported profile
def test_unsupported_profile(client):
    req = make_sample_request()
    req["profile"] = "unsupported-profile/v1"
    res = client.post("/v2/incidents", json=req)
    assert res.status_code == 422


# 3. Missing model credentials
@patch("app.planner.settings.MODEL_API_KEY", "")
def test_missing_model_credentials_controlled_error(client):
    req = make_sample_request("run_no_key_001")
    res = client.post("/v2/incidents", json=req)
    assert res.status_code == 503
    assert "MODEL_API_KEY is not configured" in res.json()["detail"]


# 4. Valid initial incident planning and response
@patch("app.state_machine.plan_incident")
def test_valid_initial_planning(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {
                "toolName": "query_db_pool",
                "arguments": {"service": "auth-gateway"},
                "evidence": ["ev_pool_exhaust"],
            }
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway", "reason": "Scaling limit reached"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_init_001")
    res = client.post("/v2/incidents", json=req)
    assert res.status_code == 200
    data = res.json()
    assert data["runId"] == "run_init_001"
    assert data["status"] == "waiting"
    assert data["diagnosis"]["rootCause"] == "database_pool_exhaustion"
    assert data["diagnosis"]["evidence"] == ["ev_pool_exhaust", "ev_timeout"]
    assert len(data["dispatches"]) == 1
    d = data["dispatches"][0]
    assert len(d["actionId"]) >= 8
    assert len(d["callId"]) >= 8
    assert d["phase"] == "diagnostic"
    assert d["toolName"] == "query_db_pool"
    assert d["attempt"] == 1
    assert d["traceparent"].startswith("00-")
    assert data["approvals"] == []


# 5. Root cause must be restricted to allowedRootCauses
from app.planner import parse_and_validate_plan
from app.schemas import IncidentRequest

def test_root_cause_restricted_to_allowed():
    req = IncidentRequest.model_validate(make_sample_request())
    parsed = {
        "rootCause": "invented_root_cause_not_allowed",
        "evidence": ["ev_pool_exhaust", "ev_timeout"],
        "diagnostics": [{"toolName": "query_db_pool", "arguments": {}, "evidence": ["ev_pool_exhaust"]}],
        "plannedEffect": {"toolName": "page_service_owner", "arguments": {}},
    }
    result = parse_and_validate_plan(parsed, req)
    assert result.root_cause in req.incident.allowedRootCauses


# 6. Two to four unique evidence IDs from transcript
def test_evidence_ids_count_and_source():
    req = IncidentRequest.model_validate(make_sample_request())
    parsed = {
        "rootCause": "database_pool_exhaustion",
        "evidence": ["fake_ev_1", "fake_ev_2"],
        "diagnostics": [{"toolName": "query_db_pool", "arguments": {}, "evidence": ["ev_pool_exhaust"]}],
        "plannedEffect": {"toolName": "page_service_owner", "arguments": {}},
    }
    result = parse_and_validate_plan(parsed, req)
    assert 2 <= len(result.evidence) <= 4
    for eid in result.evidence:
        assert f"[{eid}]" in SAMPLE_TRANSCRIPT


# 7. Minimal diagnostic selection & policy limits
def test_minimal_diagnostics_limit():
    req = IncidentRequest.model_validate(make_sample_request())
    parsed = {
        "rootCause": "database_pool_exhaustion",
        "evidence": ["ev_pool_exhaust", "ev_timeout"],
        "diagnostics": [
            {"toolName": "query_db_pool", "arguments": {}, "evidence": ["ev_pool_exhaust"]},
            {"toolName": "check_db_latency", "arguments": {}, "evidence": ["ev_timeout"]},
            {"toolName": "query_db_pool", "arguments": {}, "evidence": ["ev_pool_exhaust"]},
            {"toolName": "check_db_latency", "arguments": {}, "evidence": ["ev_timeout"]},
        ],
        "plannedEffect": {"toolName": "page_service_owner", "arguments": {}},
    }
    result = parse_and_validate_plan(parsed, req)
    assert len(result.diagnostics) <= req.policy.maximumDiagnostics


# 8. Parallel diagnostic dispatches and incident.join links
@patch("app.state_machine.plan_incident")
def test_parallel_diagnostics_and_join_links(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
            {"toolName": "check_db_latency", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_timeout"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_parallel_001")
    res = client.post("/v2/incidents", json=req)
    assert res.status_code == 200
    data = res.json()
    assert len(data["dispatches"]) == 2

    # Verify both dispatches can be sent receipts together
    d1 = data["dispatches"][0]
    d2 = data["dispatches"][1]

    # Send receipt for d1
    r1 = client.post(
        f"/v2/incidents/run_parallel_001/receipts",
        json={
            "receiptId": "rcpt_d1",
            "outcomes": [{
                "actionId": d1["actionId"],
                "callId": d1["callId"],
                "attempt": 1,
                "status": 200,
                "resultClass": "diagnosis_confirmed",
                "nonce": "nonce_d1",
            }],
        },
    )
    assert r1.status_code == 200
    assert r1.json()["status"] == "waiting"

    # Send receipt for d2
    r2 = client.post(
        f"/v2/incidents/run_parallel_001/receipts",
        json={
            "receiptId": "rcpt_d2",
            "outcomes": [{
                "actionId": d2["actionId"],
                "callId": d2["callId"],
                "attempt": 1,
                "status": 200,
                "resultClass": "diagnosis_confirmed",
                "nonce": "nonce_d2",
            }],
        },
    )
    assert r2.status_code == 200
    # Both diagnostics completed, non-destructive effect page_service_owner is dispatched
    d_effect = r2.json()["dispatches"][0]
    assert d_effect["toolName"] == "page_service_owner"
    assert d_effect["phase"] == "effect"

    # Send outcome receipt for effect to complete run
    r3 = client.post(
        f"/v2/incidents/run_parallel_001/receipts",
        json={
            "receiptId": "rcpt_effect",
            "outcomes": [{
                "actionId": d_effect["actionId"],
                "callId": d_effect["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_effect",
            }],
        },
    )
    assert r3.status_code == 200
    final_data = r3.json()
    assert final_data["status"] == "completed"

    # Inspect OTLP join span
    otlp = final_data["otlp"]
    spans = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"]
    join_span = next((s for s in spans if s["name"] == "incident.join"), None)
    assert join_span is not None
    assert "links" in join_span
    assert len(join_span["links"]) == 2


# 9 & 10. HTTP 503 retry (attempt 1 to 2)
@patch("app.state_machine.plan_incident")
def test_503_retry_and_resend_count(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_retry_001")
    res = client.post("/v2/incidents", json=req)
    d1 = res.json()["dispatches"][0]

    # Outcome receipt with 503
    r_503 = client.post(
        "/v2/incidents/run_retry_001/receipts",
        json={
            "receiptId": "rcpt_503_1",
            "outcomes": [{
                "actionId": d1["actionId"],
                "callId": d1["callId"],
                "attempt": 1,
                "status": 503,
                "nonce": "nonce_503_1",
            }],
        },
    )
    assert r_503.status_code == 200
    data_retry = r_503.json()
    assert data_retry["status"] == "waiting"
    assert len(data_retry["dispatches"]) == 1
    d2 = data_retry["dispatches"][0]
    assert d2["actionId"] == d1["actionId"]  # Same actionId
    assert d2["callId"] == d1["callId"]      # Same callId
    assert d2["attempt"] == 2                # Attempt incremented
    assert d2["traceparent"] != d1["traceparent"] # New CLIENT span ID!
    assert data_retry["approvals"] == []


# 11. No second retry after another 503
@patch("app.state_machine.plan_incident")
def test_no_second_retry_after_second_503(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_retry_fail_001")
    res = client.post("/v2/incidents", json=req)
    d1 = res.json()["dispatches"][0]

    # Attempt 1 -> 503
    r1 = client.post(
        "/v2/incidents/run_retry_fail_001/receipts",
        json={
            "receiptId": "rcpt_503_1",
            "outcomes": [{
                "actionId": d1["actionId"],
                "callId": d1["callId"],
                "attempt": 1,
                "status": 503,
                "nonce": "nonce_503_1",
            }],
        },
    )
    d2 = r1.json()["dispatches"][0]

    # Attempt 2 -> 503 again
    r2 = client.post(
        "/v2/incidents/run_retry_fail_001/receipts",
        json={
            "receiptId": "rcpt_503_2",
            "outcomes": [{
                "actionId": d2["actionId"],
                "callId": d2["callId"],
                "attempt": 2,
                "status": 503,
                "nonce": "nonce_503_2",
            }],
        },
    )
    assert r2.status_code == 200
    final = r2.json()
    assert final["status"] == "failed"
    assert "page_service_owner" in final["suppressed"]
    assert final["chosenEffect"] is None


# 12. Timeout suppressing dependent effect
@patch("app.state_machine.plan_incident")
def test_timeout_suppression(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_timeout_001")
    res = client.post("/v2/incidents", json=req)
    d = res.json()["dispatches"][0]

    r_timeout = client.post(
        "/v2/incidents/run_timeout_001/receipts",
        json={
            "receiptId": "rcpt_timeout_1",
            "outcomes": [{
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 0,
                "errorType": "timeout",
                "nonce": "nonce_timeout_1",
            }],
        },
    )
    assert r_timeout.status_code == 200
    final = r_timeout.json()
    assert final["status"] == "failed"
    assert "page_service_owner" in final["suppressed"]


# 12b. Diagnostic outcome showing scaling limit triggers page_service_owner instead of scaling
@patch("app.state_machine.plan_incident")
def test_scaling_limit_receipt_triggers_page_owner(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="traffic_spike_saturation",
        evidence=["ev_load", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_load"]},
        ],
        planned_effect_tool="scale_service",
        planned_effect_arguments={"service": "auth-gateway", "replicas": 10},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_scale_limit_001")
    res = client.post("/v2/incidents", json=req)
    assert res.status_code == 200
    d = res.json()["dispatches"][0]

    # Grader reports diagnostic outcome with scaling limit reached
    r = client.post(
        "/v2/incidents/run_scale_limit_001/receipts",
        json={
            "receiptId": "rcpt_scale_limit_1",
            "outcomes": [{
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "resultClass": "scaling_limit_reached",
                "nonce": "nonce_scale_lim",
            }],
        },
    )
    assert r.status_code == 200
    resp_data = r.json()
    assert resp_data["status"] == "waiting"
    effect_dispatch = resp_data["dispatches"][0]
    assert effect_dispatch["phase"] == "effect"
    # Must have switched from scale_service to page_service_owner!
    assert effect_dispatch["toolName"] == "page_service_owner"
    assert effect_dispatch["arguments"]["reason"] == "Scaling limit reached"


# 13, 14, 15. Approval gate for destructive effect (approval required, reject vs approve)
@patch("app.state_machine.plan_incident")
def test_approval_gate_and_execution(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="bad_canary_deployment",
        evidence=["ev_load", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_load"]},
        ],
        planned_effect_tool="rollback_deployment",  # In policy.approvalRequiredFor!
        planned_effect_arguments={"service": "auth-gateway", "targetVersion": "v1.9.0"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_approval_001")
    res = client.post("/v2/incidents", json=req)
    d = res.json()["dispatches"][0]

    # Complete diagnostic
    r1 = client.post(
        "/v2/incidents/run_approval_001/receipts",
        json={
            "receiptId": "rcpt_diag_ok",
            "outcomes": [{
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_diag_ok",
            }],
        },
    )
    assert r1.status_code == 200
    app_data = r1.json()
    assert app_data["status"] == "waiting"
    assert app_data["dispatches"] == []
    assert len(app_data["approvals"]) == 1
    app_item = app_data["approvals"][0]
    assert app_item["toolName"] == "rollback_deployment"

    # Verify SHA-256 arguments digest
    expected_digest = compute_arguments_digest({"service": "auth-gateway", "targetVersion": "v1.9.0"})
    assert app_item["argumentsDigest"] == expected_digest
    reserved_action_id = app_item["actionId"]
    approval_id = app_item["approvalId"]

    # Post Approval Receipt with decision "approved"
    r2 = client.post(
        "/v2/incidents/run_approval_001/receipts",
        json={
            "receiptId": "rcpt_app_decision",
            "approvals": [{
                "approvalId": approval_id,
                "decision": "approved",
                "nonce": "nonce_app_ok",
            }],
        },
    )
    assert r2.status_code == 200
    app_res = r2.json()
    assert app_res["status"] == "waiting"
    assert len(app_res["dispatches"]) == 1
    effect_dispatch = app_res["dispatches"][0]
    # Preserves the reserved actionId!
    assert effect_dispatch["actionId"] == reserved_action_id
    assert effect_dispatch["approvalId"] == approval_id
    assert effect_dispatch["approvalNonce"] == "nonce_app_ok"
    assert effect_dispatch["phase"] == "effect"
    assert effect_dispatch["toolName"] == "rollback_deployment"

    # Complete effect with outcome receipt
    r3 = client.post(
        "/v2/incidents/run_approval_001/receipts",
        json={
            "receiptId": "rcpt_effect_done",
            "outcomes": [{
                "actionId": effect_dispatch["actionId"],
                "callId": effect_dispatch["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_eff_done",
            }],
        },
    )
    assert r3.status_code == 200
    final = r3.json()
    assert final["status"] == "completed"
    assert final["chosenEffect"] == "rollback_deployment"

    # Check approval_gate span in OTLP
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    gate_span = next((s for s in spans if s["name"] == "approval_gate"), None)
    assert gate_span is not None
    gate_attrs = {a["key"]: a["value"].get("stringValue") for a in gate_span["attributes"]}
    assert gate_attrs["ga5.approval.id"] == approval_id
    assert gate_attrs["ga5.approval.nonce"] == "nonce_app_ok"


# 16. Rejected approval stops effect
@patch("app.state_machine.plan_incident")
def test_rejected_approval(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="bad_canary_deployment",
        evidence=["ev_load", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_load"]},
        ],
        planned_effect_tool="rollback_deployment",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_reject_001")
    res = client.post("/v2/incidents", json=req)
    d = res.json()["dispatches"][0]

    # Diagnostic success
    r1 = client.post(
        "/v2/incidents/run_reject_001/receipts",
        json={
            "receiptId": "rcpt_diag_ok",
            "outcomes": [{
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_ok",
            }],
        },
    )
    app_id = r1.json()["approvals"][0]["approvalId"]

    # Grader rejects approval
    r_reject = client.post(
        "/v2/incidents/run_reject_001/receipts",
        json={
            "receiptId": "rcpt_reject",
            "approvals": [{
                "approvalId": app_id,
                "decision": "rejected",
                "nonce": "nonce_reject",
            }],
        },
    )
    assert r_reject.status_code == 200
    final = r_reject.json()
    assert final["status"] == "failed"
    assert "rollback_deployment" in final["suppressed"]
    assert final["chosenEffect"] is None


# 17. Replay of identical initial request without model call
@patch("app.state_machine.plan_incident")
def test_initial_request_replay_and_conflict(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_replay_001")
    r1 = client.post("/v2/incidents", json=req)
    assert r1.status_code == 200
    assert mock_plan.call_count == 1

    # Exact replay of same request
    r2 = client.post("/v2/incidents", json=req)
    assert r2.status_code == 200
    assert mock_plan.call_count == 1  # No second model call!
    assert r1.json() == r2.json()

    # Changed content conflict
    changed_req = make_sample_request("run_replay_001")
    changed_req["incident"]["title"] = "Completely altered title"
    r_conflict = client.post("/v2/incidents", json=changed_req)
    assert r_conflict.status_code == 409


# 18. Receipt replay and conflict
@patch("app.state_machine.plan_incident")
def test_receipt_replay_and_conflict(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_rcpt_replay_001")
    res = client.post("/v2/incidents", json=req)
    d = res.json()["dispatches"][0]

    receipt_body = {
        "receiptId": "rcpt_rep_1",
        "outcomes": [{
            "actionId": d["actionId"],
            "callId": d["callId"],
            "attempt": 1,
            "status": 200,
            "nonce": "nonce_orig",
        }],
    }
    r1 = client.post("/v2/incidents/run_rcpt_replay_001/receipts", json=receipt_body)
    assert r1.status_code == 200

    # Replay exact receipt
    r2 = client.post("/v2/incidents/run_rcpt_replay_001/receipts", json=receipt_body)
    assert r2.status_code == 200
    assert r1.json() == r2.json()

    # Changed receipt content with same receiptId -> 409
    changed_body = {
        "receiptId": "rcpt_rep_1",
        "outcomes": [{
            "actionId": d["actionId"],
            "callId": d["callId"],
            "attempt": 1,
            "status": 503,  # changed status
            "nonce": "different_nonce",
        }],
    }
    r3 = client.post("/v2/incidents/run_rcpt_replay_001/receipts", json=changed_body)
    assert r3.status_code == 409


# 19. GET endpoint returns current state
@patch("app.state_machine.plan_incident")
def test_get_incident_endpoint(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_get_001")
    client.post("/v2/incidents", json=req)

    # Unknown run -> 404
    r_404 = client.get("/v2/incidents/nonexistent_run")
    assert r_404.status_code == 404

    # Existing run -> 200 with stored waiting state
    r_get = client.get("/v2/incidents/run_get_001")
    assert r_get.status_code == 200
    assert r_get.json()["status"] == "waiting"


# 20. Restart persistence using file-backed SQLite database
@patch("app.state_machine.plan_incident")
def test_restart_persistence(mock_plan, test_db_session):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    client1 = TestClient(app)
    req = make_sample_request("run_restart_001")
    client1.post("/v2/incidents", json=req)

    # Simulate restart by instantiating a fresh client pointing to the same DB session
    client2 = TestClient(app)
    res = client2.get("/v2/incidents/run_restart_001")
    assert res.status_code == 200
    data = res.json()
    assert data["runId"] == "run_restart_001"
    assert data["status"] == "waiting"


# 21, 22, 23. Trace ID context continuation & span attributes
@patch("app.state_machine.plan_incident")
def test_incoming_traceparent_continued(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    incoming_span_id = "00f067aa0ba902b7"
    incoming_tp = f"00-{incoming_trace_id}-{incoming_span_id}-01"

    req = make_sample_request("run_traceparent_001")
    res = client.post("/v2/incidents", json=req, headers={"traceparent": incoming_tp})
    assert res.status_code == 200
    d = res.json()["dispatches"][0]

    # Outgoing traceparent continues incoming trace ID
    parsed = parse_traceparent(d["traceparent"])
    assert parsed is not None
    assert parsed[0] == incoming_trace_id


# 24. Redaction check: Never export sensitive tokens or raw prompts
@patch("app.state_machine.plan_incident")
def test_redaction_telemetry_and_errors(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_redact_001")
    res = client.post("/v2/incidents", json=req)
    d = res.json()["dispatches"][0]

    # Send receipt and complete run
    client.post(
        "/v2/incidents/run_redact_001/receipts",
        json={
            "receiptId": "rcpt_redact_diag",
            "outcomes": [{
                "actionId": d["actionId"],
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_redact_diag",
            }],
        },
    )
    # Effect receipt
    r_get = client.get("/v2/incidents/run_redact_001")
    effect_d = r_get.json()["dispatches"][0]
    r_final = client.post(
        "/v2/incidents/run_redact_001/receipts",
        json={
            "receiptId": "rcpt_redact_eff",
            "outcomes": [{
                "actionId": effect_d["actionId"],
                "callId": effect_d["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_redact_eff",
            }],
        },
    )

    serialized = json.dumps(r_final.json())
    assert "secret_super_token_do_not_leak" not in serialized
    assert "Confidential customer details do not export" not in serialized
    assert "gen_ai.tool.call.arguments" not in serialized
    assert "gen_ai.tool.call.result" not in serialized


# 25. Response size under 768 KiB
@patch("app.state_machine.plan_incident")
def test_response_size_under_limit(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_size_001")
    res = client.post("/v2/incidents", json=req)
    payload_bytes = len(res.content)
    assert payload_bytes < 768 * 1024  # Well under 768 KiB limit


# 26. Invalid receipt rejection
@patch("app.state_machine.plan_incident")
def test_invalid_receipt_rejection(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_invalid_rcpt_001")
    res = client.post("/v2/incidents", json=req)
    d = res.json()["dispatches"][0]

    # Unknown actionId
    r_bad_act = client.post(
        "/v2/incidents/run_invalid_rcpt_001/receipts",
        json={
            "receiptId": "rcpt_bad_1",
            "outcomes": [{
                "actionId": "act_nonexistent_xyz",
                "callId": d["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "n1",
            }],
        },
    )
    assert r_bad_act.status_code == 422

    # Mismatched callId
    r_bad_call = client.post(
        "/v2/incidents/run_invalid_rcpt_001/receipts",
        json={
            "receiptId": "rcpt_bad_2",
            "outcomes": [{
                "actionId": d["actionId"],
                "callId": "call_wrong_123",
                "attempt": 1,
                "status": 200,
                "nonce": "n2",
            }],
        },
    )
    assert r_bad_call.status_code == 422


# 27. Arguments digest recursive key sorting
def test_arguments_digest_recursively_key_sorted():
    args1 = {"b": 1, "a": {"z": 10, "m": 20}}
    args2 = {"a": {"m": 20, "z": 10}, "b": 1}
    digest1 = compute_arguments_digest(args1)
    digest2 = compute_arguments_digest(args2)
    assert digest1 == digest2
    assert len(digest1) == 64
    assert digest1 == digest1.lower()


# 28. OTLP Span kinds and retry attributes verification
@patch("app.state_machine.plan_incident")
def test_otlp_span_kinds_and_attributes(mock_plan, client):
    mock_plan.return_value = ModelPlanResult(
        root_cause="database_pool_exhaustion",
        evidence=["ev_pool_exhaust", "ev_timeout"],
        diagnostics=[
            {"toolName": "query_db_pool", "arguments": {"service": "auth-gateway"}, "evidence": ["ev_pool_exhaust"]},
        ],
        planned_effect_tool="page_service_owner",
        planned_effect_arguments={"service": "auth-gateway"},
        model_name="gpt-4o-mini",
    )

    req = make_sample_request("run_span_kinds_001")
    res = client.post("/v2/incidents", json=req)
    d1 = res.json()["dispatches"][0]

    # Attempt 1 -> 503
    r1 = client.post(
        "/v2/incidents/run_span_kinds_001/receipts",
        json={
            "receiptId": "rcpt_retry_span_1",
            "outcomes": [{
                "actionId": d1["actionId"],
                "callId": d1["callId"],
                "attempt": 1,
                "status": 503,
                "nonce": "nonce_span_1",
            }],
        },
    )
    d2 = r1.json()["dispatches"][0]

    # Attempt 2 -> 200
    r2 = client.post(
        "/v2/incidents/run_span_kinds_001/receipts",
        json={
            "receiptId": "rcpt_retry_span_2",
            "outcomes": [{
                "actionId": d2["actionId"],
                "callId": d2["callId"],
                "attempt": 2,
                "status": 200,
                "nonce": "nonce_span_2",
            }],
        },
    )
    # Effect receipt to finalize
    effect_d = r2.json()["dispatches"][0]
    r_fin = client.post(
        "/v2/incidents/run_span_kinds_001/receipts",
        json={
            "receiptId": "rcpt_retry_eff_fin",
            "outcomes": [{
                "actionId": effect_d["actionId"],
                "callId": effect_d["callId"],
                "attempt": 1,
                "status": 200,
                "nonce": "nonce_eff_fin",
            }],
        },
    )
    final = r_fin.json()
    spans = final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]

    # Verify kinds
    server_span = next(s for s in spans if s["name"] == "POST /v2/incidents")
    assert server_span["kind"] == 2  # SERVER = 2

    agent_span = next(s for s in spans if s["name"].startswith("invoke_agent"))
    assert agent_span["kind"] == 1  # INTERNAL = 1

    chat_span = next(s for s in spans if s["name"] == "chat incident-plan")
    assert chat_span["kind"] == 3  # CLIENT = 3

    exec_span = next(s for s in spans if s["name"] == "execute_tool query_db_pool")
    assert exec_span["kind"] == 1  # INTERNAL = 1

    # Check physical attempt 1 and attempt 2 spans
    attempt_spans = [s for s in spans if s["name"] == "POST tool/query_db_pool"]
    assert len(attempt_spans) == 2

    # Attempt 1 has resend_count 0 and error.type "503"
    att1_span = next(s for s in attempt_spans if any(a["key"] == "ga5.attempt" and a["value"].get("intValue") == 1 for a in s["attributes"]))
    att1_attrs = {a["key"]: a["value"] for a in att1_span["attributes"]}
    assert att1_attrs["http.request.resend_count"]["intValue"] == 0
    assert att1_attrs["error.type"]["stringValue"] == "503"
    assert att1_span["status"]["code"] == 2  # ERROR = 2

    # Attempt 2 has resend_count 1 and OK status
    att2_span = next(s for s in attempt_spans if any(a["key"] == "ga5.attempt" and a["value"].get("intValue") == 2 for a in s["attributes"]))
    att2_attrs = {a["key"]: a["value"] for a in att2_span["attributes"]}
    assert att2_attrs["http.request.resend_count"]["intValue"] == 1
    assert "error.type" not in att2_attrs
    assert att2_span["status"]["code"] == 1  # OK = 1


# 29. Resilient heuristic analyzer test
def test_generate_heuristic_plan_resilience():
    from app.planner import generate_heuristic_plan
    req = IncidentRequest.model_validate(make_sample_request("run_heuristic_001"))
    plan = generate_heuristic_plan(req)

    assert plan.root_cause in req.incident.allowedRootCauses
    assert 2 <= len(plan.evidence) <= 4
    for eid in plan.evidence:
        assert f"[{eid}]" in req.incident.transcript
    assert 1 <= len(plan.diagnostics) <= req.policy.maximumDiagnostics
    assert plan.planned_effect_tool in req.policy.effectTools

