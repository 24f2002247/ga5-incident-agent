import os
import pytest
from app.config import settings
from app.planner import plan_incident
from app.schemas import IncidentRequest
from tests.test_incident_agent import make_sample_request


@pytest.mark.skipif(
    not os.getenv("RUN_LIVE_MODEL_TESTS") or not os.getenv("MODEL_API_KEY"),
    reason="Live model integration tests disabled. Set RUN_LIVE_MODEL_TESTS=1 and MODEL_API_KEY to run.",
)
@pytest.mark.asyncio
async def test_live_model_plan_execution():
    """Optional integration test verifying live model connection against OpenAI-compatible endpoint."""
    req = IncidentRequest.model_validate(make_sample_request("run_live_integration_001"))
    plan = await plan_incident(req)

    assert plan.root_cause in req.incident.allowedRootCauses
    assert 2 <= len(plan.evidence) <= 4
    for eid in plan.evidence:
        assert f"[{eid}]" in req.incident.transcript
    assert 1 <= len(plan.diagnostics) <= req.policy.maximumDiagnostics
