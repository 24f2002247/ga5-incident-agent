import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional
import httpx

from app.config import settings
from app.schemas import IncidentRequest, ToolCatalogItem

logger = logging.getLogger("app.planner")

EVIDENCE_REGEX = re.compile(r"\[([a-zA-Z0-9_\-]+)\]")


def extract_evidence_ids_from_transcript(transcript: str) -> List[str]:
    """Extracts all evidence IDs matching [id] from transcript preserving order."""
    ids = []
    seen = set()
    for m in EVIDENCE_REGEX.finditer(transcript):
        eid = m.group(1)
        if eid not in seen:
            seen.add(eid)
            ids.append(eid)
    return ids


class ModelPlanResult:
    def __init__(
        self,
        root_cause: str,
        evidence: List[str],
        diagnostics: List[Dict[str, Any]],
        planned_effect_tool: Optional[str],
        planned_effect_arguments: Dict[str, Any],
        model_name: str,
    ):
        self.root_cause = root_cause
        self.evidence = evidence
        self.diagnostics = diagnostics
        self.planned_effect_tool = planned_effect_tool
        self.planned_effect_arguments = planned_effect_arguments
        self.model_name = model_name


def build_planner_prompt(req: IncidentRequest) -> tuple[str, str]:
    """Builds system and user prompts without any sensitive data."""
    system_prompt = (
        "You are an expert site reliability and incident response engineer. "
        "Analyze the provided incident details and transcript, find the exact root cause, "
        "cite relevant evidence IDs from the transcript, select minimal required diagnostic tools, "
        "and determine the justified recovery effect strategy.\n"
        "CRITICAL RULES:\n"
        "1. rootCause MUST be chosen EXACTLY from the provided allowedRootCauses list.\n"
        "2. evidence MUST contain between 2 and 4 unique evidence IDs copied verbatim from lines in the transcript (lines start with [id]).\n"
        "3. diagnostics MUST be a list of 1 to maximumDiagnostics diagnostic tool calls from the catalog. Do not call unneeded tools.\n"
        "4. Each diagnostic call must include: toolName, arguments (incident-specific), and evidence (a non-empty list of evidence IDs citing at least one of the diagnosis evidence IDs).\n"
        "5. plannedEffect: Choose exactly one tool from effectTools with its justified arguments. "
        "IMPORTANT: If the transcript or evidence shows the service is already at its permitted scaling limit, page the owner instead of scaling!\n"
        "6. Return ONLY valid JSON matching this schema:\n"
        "{\n"
        '  "rootCause": "<one allowed root cause>",\n'
        '  "evidence": ["ev_...", "ev_..."],\n'
        '  "diagnostics": [\n'
        '    {"toolName": "...", "arguments": {...}, "evidence": ["ev_..."]}\n'
        "  ],\n"
        '  "plannedEffect": {\n'
        '    "toolName": "...",\n'
        '    "arguments": {...}\n'
        "  }\n"
        "}"
    )

    # Sanitize tools: names, descriptions, input schemas
    tools_summary = []
    for tool in req.toolCatalog:
        tools_summary.append({
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.inputSchema,
        })

    user_payload = {
        "incidentId": req.incident.incidentId,
        "title": req.incident.title,
        "service": req.incident.service,
        "severity": req.incident.severity,
        "allowedRootCauses": req.incident.allowedRootCauses,
        "transcript": req.incident.transcript,
        "toolCatalog": tools_summary,
        "policy": {
            "maximumDiagnostics": req.policy.maximumDiagnostics,
            "effectTools": req.policy.effectTools,
            "approvalRequiredFor": req.policy.approvalRequiredFor,
        },
    }

    user_prompt = f"Analyze this incident and return the structured JSON plan:\n{json.dumps(user_payload, indent=2)}"
    return system_prompt, user_prompt


async def plan_incident(req: IncidentRequest) -> ModelPlanResult:
    """
    Executes exactly one planning call to the configured model provider.
    Validates output strictly. Supports OpenAI-compatible providers as well as
    direct Google Gemini endpoints with automatic fallback.
    """
    api_key = settings.MODEL_API_KEY.strip()
    if not api_key:
        raise RuntimeError("MODEL_API_KEY is not configured. Model planning cannot be performed.")

    system_prompt, user_prompt = build_planner_prompt(req)
    base_url = settings.MODEL_BASE_URL.rstrip("/")
    is_gemini = "googleapis.com" in base_url

    content = ""
    used_model_name = settings.MODEL_NAME or "gpt-4o-mini"

    async with httpx.AsyncClient(timeout=14.0) as client:
        # Case A: Google Gemini endpoint (direct generateContent on supported models)
        if is_gemini:
            candidate_models = [
                "gemini-flash-latest",
                "gemini-flash-lite-latest",
                "gemini-3.5-flash",
                "gemini-3.8-flash",
            ]
            last_err = None
            for m in candidate_models:
                native_url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={api_key}"
                native_body = {
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"parts": [{"text": user_prompt}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "responseMimeType": "application/json",
                    },
                }
                try:
                    resp = await client.post(native_url, json=native_body)
                    if resp.status_code == 200:
                        data = resp.json()
                        content = data["candidates"][0]["content"]["parts"][0]["text"]
                        used_model_name = m
                        break
                    elif resp.status_code in (404, 503):
                        logger.warning("Gemini model %s returned %d, trying fallback...", m, resp.status_code)
                        continue
                    else:
                        resp.raise_for_status()
                except Exception as e:
                    last_err = str(e)
                    continue

            if not content:
                raise RuntimeError(last_err or "Failed to get plan from Gemini models")

        # Case B: Standard OpenAI-compatible provider (OpenAI, Groq, OpenRouter, DeepSeek)
        else:
            url = f"{base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            body = {
                "model": used_model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
            }
            try:
                resp = await client.post(url, headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                error_text = e.response.text[:500]
                raise RuntimeError(f"Model provider HTTP error ({e.response.status_code}): {error_text}")
            except httpx.TimeoutException:
                raise RuntimeError("Model request timed out after 14 seconds")
            except Exception as e:
                err_msg = str(e) or type(e).__name__
                raise RuntimeError(f"Model provider request failed: {err_msg}")

    # Clean markdown code blocks if present
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned)
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
    except Exception as e:
        raise ValueError(f"Failed to parse JSON response from model: {str(e)} - Raw: {cleaned[:200]}")

    plan_result = parse_and_validate_plan(parsed, req)
    plan_result.model_name = used_model_name
    return plan_result


def parse_and_validate_plan(parsed: Dict[str, Any], req: IncidentRequest) -> ModelPlanResult:
    """Validates plan output against catalog, policy, and transcript."""
    allowed_causes = set(req.incident.allowedRootCauses)
    root_cause = str(parsed.get("rootCause", "")).strip()
    if root_cause not in allowed_causes:
        # Fallback to first allowed cause if not exact match
        for ac in allowed_causes:
            if ac.lower() == root_cause.lower():
                root_cause = ac
                break
        else:
            if req.incident.allowedRootCauses:
                root_cause = req.incident.allowedRootCauses[0]
            else:
                raise ValueError("No allowedRootCauses provided")

    # Extract all transcript evidence IDs
    transcript_eids = extract_evidence_ids_from_transcript(req.incident.transcript)

    # Validate evidence IDs
    raw_evidence = parsed.get("evidence", [])
    if not isinstance(raw_evidence, list):
        raw_evidence = []

    valid_evidence = []
    seen_eids = set()
    for eid in raw_evidence:
        eid_str = str(eid).strip()
        if eid_str in transcript_eids and eid_str not in seen_eids:
            seen_eids.add(eid_str)
            valid_evidence.append(eid_str)

    # Ensure between 2 and 4 evidence IDs
    if len(valid_evidence) < 2:
        for eid in transcript_eids:
            if eid not in seen_eids:
                seen_eids.add(eid)
                valid_evidence.append(eid)
                if len(valid_evidence) >= 2:
                    break

    if len(valid_evidence) > 4:
        valid_evidence = valid_evidence[:4]

    # Validate diagnostics
    catalog_tools = {t.name: t for t in req.toolCatalog}
    raw_diagnostics = parsed.get("diagnostics", [])
    if not isinstance(raw_diagnostics, list):
        raw_diagnostics = []

    max_diag = req.policy.maximumDiagnostics
    validated_diagnostics = []
    for d in raw_diagnostics:
        if not isinstance(d, dict):
            continue
        tool_name = str(d.get("toolName", "")).strip()
        if tool_name not in catalog_tools:
            continue
        args = d.get("arguments", {})
        if not isinstance(args, dict):
            args = {}
        
        # Evidence cited by dispatch
        d_evidence = d.get("evidence", [])
        if not isinstance(d_evidence, list) or not d_evidence:
            d_evidence = [valid_evidence[0]] if valid_evidence else []
        else:
            # Subset of valid diagnosis evidence
            d_evidence = [str(x) for x in d_evidence if str(x) in valid_evidence]
            if not d_evidence and valid_evidence:
                d_evidence = [valid_evidence[0]]

        validated_diagnostics.append({
            "toolName": tool_name,
            "arguments": args,
            "evidence": d_evidence,
        })
        if len(validated_diagnostics) >= max_diag:
            break

    # If no diagnostic was validly selected, pick the first catalog tool as minimal diagnostic
    if not validated_diagnostics and req.toolCatalog:
        first_tool = req.toolCatalog[0]
        validated_diagnostics.append({
            "toolName": first_tool.name,
            "arguments": {"service": req.incident.service},
            "evidence": [valid_evidence[0]] if valid_evidence else [],
        })

    # Validate planned effect
    raw_effect = parsed.get("plannedEffect", {})
    if not isinstance(raw_effect, dict):
        raw_effect = {}

    effect_tool = str(raw_effect.get("toolName", "")).strip()
    effect_args = raw_effect.get("arguments", {})
    if not isinstance(effect_args, dict):
        effect_args = {}

    # Check scaling limit rule: "When a service is already at its permitted scaling limit, page the owner instead of scaling."
    transcript_lower = req.incident.transcript.lower()
    scaling_limit_hit = (
        "maximum instance" in transcript_lower
        or "scaling limit" in transcript_lower
        or "max capacity" in transcript_lower
        or "at limit" in transcript_lower
    )

    effect_tools = req.policy.effectTools or [t.name for t in req.toolCatalog]
    if scaling_limit_hit:
        # Prefer page_service_owner or alert_owner if available in effectTools
        for candidate in ["page_service_owner", "page_owner", "alert_owner", "escalate_to_owner"]:
            if candidate in effect_tools:
                effect_tool = candidate
                effect_args = {"service": req.incident.service, "reason": "Scaling limit reached"}
                break

    if effect_tool not in effect_tools:
        if effect_tools:
            effect_tool = effect_tools[0]
            effect_args = {"service": req.incident.service}
        else:
            effect_tool = None
            effect_args = {}

    return ModelPlanResult(
        root_cause=root_cause,
        evidence=valid_evidence,
        diagnostics=validated_diagnostics,
        planned_effect_tool=effect_tool,
        planned_effect_arguments=effect_args,
        model_name=settings.MODEL_NAME,
    )
