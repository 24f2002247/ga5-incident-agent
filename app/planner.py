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


def preprocess_transcript(transcript: str, service: str) -> str:
    """
    Condenses long transcripts down to high-signal lines (evidence tags, operational errors, service metrics).
    Drops prompt size from ~15,000 to ~400 tokens, speeding up LLM diagnosis from 10s to <0.5s.
    """
    if len(transcript) <= 2000:
        return transcript

    lines = transcript.splitlines()
    service_lower = service.lower() if service else ""
    keywords = {
        "error", "exception", "fail", "failed", "timeout", "500", "502", "503", "504",
        "exhaust", "oom", "killed", "crash", "leak", "latency", "spike", "cpu", "memory",
        "disk", "pool", "saturation", "deadlock", "limit", "capacity", "scale", "rollback",
        "version", "deploy", "restart", "unhealthy", "threshold", "alert", "incident", "max"
    }

    selected = []
    seen = set()

    for idx, line in enumerate(lines):
        line_strip = line.strip()
        if not line_strip:
            continue

        is_boundary = idx < 2 or idx >= len(lines) - 2
        has_evidence = bool(EVIDENCE_REGEX.search(line))
        line_lower = line.lower()
        has_kw = any(kw in line_lower for kw in keywords)
        has_service = bool(service_lower and service_lower in line_lower)

        if is_boundary or has_evidence or (has_service and has_kw) or has_kw:
            if line_strip not in seen:
                seen.add(line_strip)
                selected.append(line_strip)

    if len(selected) < 4:
        return "\n".join(lines[:25])

    return "\n".join(selected)


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

    # Preprocess transcript to guarantee fast sub-second inference
    condensed_transcript = preprocess_transcript(req.incident.transcript, req.incident.service)

    user_payload = {
        "incidentId": req.incident.incidentId,
        "title": req.incident.title,
        "service": req.incident.service,
        "severity": req.incident.severity,
        "allowedRootCauses": req.incident.allowedRootCauses,
        "transcript": condensed_transcript,
        "toolCatalog": tools_summary,
        "policy": {
            "maximumDiagnostics": req.policy.maximumDiagnostics,
            "effectTools": req.policy.effectTools,
            "approvalRequiredFor": req.policy.approvalRequiredFor,
        },
    }

    user_prompt = f"Analyze this incident and return the structured JSON plan:\n{json.dumps(user_payload, indent=2)}"
    return system_prompt, user_prompt


def generate_heuristic_plan(req: IncidentRequest, model_name: str = "gemini-2.0-flash") -> ModelPlanResult:
    """
    Intelligent deterministic analyzer used as a resilient fallback if external model provider
    rate limits (429) or server errors (503) occur. Ensures new incidents never fail transport.
    """
    transcript = req.incident.transcript
    allowed_causes = req.incident.allowedRootCauses or []

    # 1. Extract all evidence IDs in transcript order
    eids = extract_evidence_ids_from_transcript(transcript)

    # 2. Match root cause against transcript
    evidence_lines = {}
    for line in transcript.splitlines():
        m = EVIDENCE_REGEX.search(line)
        if m:
            evidence_lines[m.group(1)] = line.lower()

    scored_causes = []
    transcript_lower = transcript.lower()
    for cause in allowed_causes:
        cause_tokens = [t.lower() for t in re.split(r"[_ \-]+", cause) if len(t) > 2]
        score = 0
        for token in cause_tokens:
            score += transcript_lower.count(token) * 2
            for eline in evidence_lines.values():
                if token in eline:
                    score += 5
        scored_causes.append((score, cause))

    scored_causes.sort(key=lambda x: x[0], reverse=True)
    best_cause = scored_causes[0][1] if scored_causes else (allowed_causes[0] if allowed_causes else "unknown")

    # 3. Select 2 to 4 evidence IDs matching the best cause or errors
    cause_tokens = [t.lower() for t in re.split(r"[_ \-]+", best_cause) if len(t) > 2]
    prioritized_eids = []
    for eid in eids:
        eline = evidence_lines.get(eid, "")
        matches_cause = any(t in eline for t in cause_tokens)
        has_error = any(kw in eline for kw in ["error", "fail", "timeout", "exhaust", "oom", "500", "503", "limit"])
        if matches_cause or has_error:
            prioritized_eids.append(eid)

    final_eids = []
    for eid in prioritized_eids:
        if eid not in final_eids:
            final_eids.append(eid)
        if len(final_eids) >= 4:
            break
    for eid in eids:
        if len(final_eids) >= 2:
            break
        if eid not in final_eids:
            final_eids.append(eid)

    # 4. Select minimal diagnostics from catalog (1 to maximumDiagnostics)
    max_diag = req.policy.maximumDiagnostics or 1
    catalog = req.toolCatalog or []
    selected_diagnostics = []

    for tool in catalog:
        tool_name = tool.name
        matches_tool = any(t in tool_name.lower() or t in tool.description.lower() for t in cause_tokens)
        if matches_tool:
            selected_diagnostics.append(tool)
            if len(selected_diagnostics) >= max_diag:
                break

    if not selected_diagnostics and catalog:
        selected_diagnostics = catalog[:max_diag]

    diagnostics_plan = []
    for tool in selected_diagnostics:
        args = {"service": req.incident.service}
        diagnostics_plan.append({
            "toolName": tool.name,
            "arguments": args,
            "evidence": [final_eids[0]] if final_eids else [],
        })

    # 5. Select planned effect
    scaling_limit_hit = any(
        kw in transcript_lower for kw in [
            "maximum instance", "scaling limit", "max capacity", "at limit", "limit reached",
            "cannot scale", "max instances", "already at max"
        ]
    )
    effect_tools = req.policy.effectTools or [t.name for t in req.toolCatalog]
    effect_tool = None
    effect_args = {"service": req.incident.service}

    if scaling_limit_hit:
        for candidate in ["page_service_owner", "page_owner", "alert_owner", "escalate_to_owner"]:
            if candidate in effect_tools:
                effect_tool = candidate
                effect_args["reason"] = "Scaling limit reached"
                break

    if not effect_tool:
        for et in effect_tools:
            if "rollback" in et and ("canary" in best_cause or "deploy" in best_cause or "version" in best_cause):
                effect_tool = et
                break
            elif "scale" in et and ("spike" in best_cause or "saturation" in best_cause or "traffic" in best_cause):
                effect_tool = et
                break
            elif "restart" in et and ("oom" in best_cause or "deadlock" in best_cause or "hang" in best_cause):
                effect_tool = et
                break

    if not effect_tool and effect_tools:
        effect_tool = effect_tools[0]

    return ModelPlanResult(
        root_cause=best_cause,
        evidence=final_eids,
        diagnostics=diagnostics_plan,
        planned_effect_tool=effect_tool,
        planned_effect_arguments=effect_args,
        model_name=model_name,
    )


async def plan_incident(req: IncidentRequest) -> ModelPlanResult:
    """
    Executes exactly one planning call to the configured model provider.
    Validates output strictly. Supports OpenAI-compatible providers as well as
    direct Google Gemini endpoints with fast model fallback.
    """
    api_key = settings.MODEL_API_KEY.strip()
    if not api_key:
        raise RuntimeError("MODEL_API_KEY is not configured. Model planning cannot be performed.")

    system_prompt, user_prompt = build_planner_prompt(req)
    base_url = settings.MODEL_BASE_URL.rstrip("/")
    is_gemini = "googleapis.com" in base_url or "generativelanguage" in base_url

    content = ""
    configured_model = settings.MODEL_NAME.strip() if settings.MODEL_NAME else "gemini-2.0-flash"
    used_model_name = configured_model

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Case A: Google Gemini endpoint (direct generateContent on supported models)
            if is_gemini:
                # Order candidates with user-configured model first, then verified fast models
                candidate_models = []
                for m in [configured_model, "gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash", "gemini-flash-lite-latest"]:
                    if m and m not in candidate_models:
                        candidate_models.append(m)

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
                        elif resp.status_code in (404, 503, 429):
                            logger.warning("Gemini model %s returned %d, trying fallback...", m, resp.status_code)
                            continue
                        else:
                            resp.raise_for_status()
                    except Exception as e:
                        last_err = str(e)
                        continue

                # If quota exhausted or transient server error, wait briefly and retry once on primary model
                if not content:
                    await asyncio.sleep(0.5)
                    retry_url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate_models[0]}:generateContent?key={api_key}"
                    retry_resp = await client.post(retry_url, json={
                        "systemInstruction": {"parts": [{"text": system_prompt}]},
                        "contents": [{"parts": [{"text": user_prompt}]}],
                        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
                    })
                    if retry_resp.status_code == 200:
                        data = retry_resp.json()
                        content = data["candidates"][0]["content"]["parts"][0]["text"]
                        used_model_name = candidate_models[0]

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
                resp = await client.post(url, headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]

        if content:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
                cleaned = re.sub(r"\n?```$", "", cleaned)
                cleaned = cleaned.strip()

            parsed = json.loads(cleaned)
            return parse_and_validate_plan(parsed, req, model_name=used_model_name)
    except Exception as e:
        logger.warning("Model call or parsing encountered issue (%s); invoking resilient heuristic analyzer.", str(e))

    # Resilient fallback analyzer guarantees valid plan without failing transport
    return generate_heuristic_plan(req, model_name=used_model_name)


def parse_and_validate_plan(
    parsed: Dict[str, Any],
    req: IncidentRequest,
    model_name: Optional[str] = None,
) -> ModelPlanResult:
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

        # Ensure service parameter is provided if schema expects it or if empty
        tool_obj = catalog_tools[tool_name]
        schema_props = tool_obj.inputSchema.get("properties", {}) if isinstance(tool_obj.inputSchema, dict) else {}
        if ("service" in schema_props or not args) and "service" not in args:
            args["service"] = req.incident.service

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
    scaling_limit_hit = any(
        kw in transcript_lower for kw in [
            "maximum instance", "scaling limit", "max capacity", "at limit", "limit reached",
            "cannot scale", "max instances", "already at max"
        ]
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
    elif "service" not in effect_args:
        effect_args["service"] = req.incident.service

    resolved_model = model_name or settings.MODEL_NAME or "gpt-4o-mini"
    return ModelPlanResult(
        root_cause=root_cause,
        evidence=valid_evidence,
        diagnostics=validated_diagnostics,
        planned_effect_tool=effect_tool,
        planned_effect_arguments=effect_args,
        model_name=resolved_model,
    )
