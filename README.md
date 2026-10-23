# GA5 Observable Incident Triage Agent

A production-ready, observable incident triage AI agent implementing the `ga5-incident-agent/v2` specification. Built with **FastAPI**, **SQLAlchemy 2.x**, **OpenTelemetry (OTLP)**, and strict receipt-driven state machine semantics. Ready for manual or blueprint deployment to **Render** with PostgreSQL or SQLite.

---

## Table of Contents

1. [Overview & Core Capabilities](#overview--core-capabilities)
2. [Architecture & Module Responsibilities](#architecture--module-responsibilities)
3. [Required Endpoints](#required-endpoints)
4. [Environment Variables](#environment-variables)
5. [Local Development Setup](#local-development-setup)
   - [Windows (PowerShell)](#windows-powershell)
   - [Linux / macOS (Bash)](#linux--macos-bash)
6. [Running the Application Locally](#running-the-application-locally)
7. [Running Automated Tests](#running-automated-tests)
8. [API Usage & Examples](#api-usage--examples)
   - [1. Initial Incident Planning (`POST /v2/incidents`)](#1-initial-incident-planning-post-v2incidents)
   - [2. Submitting Authoritative Receipts (`POST /v2/incidents/{runId}/receipts`)](#2-submitting-authoritative-receipts-post-v2incidentsrunidreceipts)
   - [3. Fetching Run State (`GET /v2/incidents/{runId}`)](#3-fetching-run-state-get-v2incidentsrunid)
9. [Step-by-Step Render Deployment Guide](#step-by-step-render-deployment-guide)
   - [Option A: Manual Web Service + PostgreSQL Setup](#option-a-manual-web-service--postgresql-setup)
   - [Option B: Render Blueprint Deployment (`render.yaml`)](#option-b-render-blueprint-deployment-renderyaml)
10. [Submission to the Grader](#submission-to-the-grader)
11. [Troubleshooting & Common Deployment Fixes](#troubleshooting--common-deployment-fixes)

---

## Overview & Core Capabilities

The Observable Incident Triage Agent diagnoses production incidents, executes minimal necessary diagnostic steps, processes authoritative outcome receipts from a grading harness, manages retries, enforces approval gates for destructive recovery actions, and emits matching W3C & OTLP telemetry.

### Key Features
- **Profile Compliance**: Implements the exact `ga5-incident-agent/v2` specification.
- **AI Planning Isolation**: Performs exactly one LLM planning call per first-seen `runId`. Never calls LLMs during replay, receipt handling, or GET requests.
- **Zero Information Leakage**: Strictly redacts access tokens, private notes, transcripts, prompts, and tool arguments/results from telemetry and error responses.
- **Deterministic State Machine**:
  - Exactly one retry after HTTP 503 (with incremented `attempt` and new CLIENT span ID).
  - Diagnostic failure or timeout (`status: 0, errorType: "timeout"`) suppresses dependent recovery effects.
  - Scaling limit awareness: If a service is at maximum scaling limit, pages the service owner instead of scaling.
- **Approval Gate**: Requires explicit approval for destructive actions (`rollback_deployment`, `disable_feature`) with canonical SHA-256 arguments digest verification.
- **Idempotency & Conflict Detection**: Identical requests and receipts return stored states deterministically. Modified content with an existing ID returns HTTP 409 Conflict.
- **OTLP Trace Generation**: Builds standard OTLP JSON resource spans with exact span counts, kinds (INTERNAL=1, SERVER=2, CLIENT=3), resend counts, and correlation links.

---

## Architecture & Module Responsibilities

```
ga5-incident-agent/
├── app/
│   ├── __init__.py
│   ├── config.py           # Environment variables & database URL normalization
│   ├── canonical.py        # Canonical compact JSON, SHA-256 digests, W3C trace context
│   ├── schemas.py          # Pydantic v2 validation models for requests and responses
│   ├── database.py         # SQLAlchemy 2.x engine, SQLite WAL pragmas, Session factory
│   ├── models.py           # Relational schema (RunRecord, DispatchRecord, ReceiptRecord, ApprovalRecord)
│   ├── planner.py          # AI prompt construction, sanitization, OpenAI-compatible caller
│   ├── security.py         # Recursive secret redaction, schema validation helpers
│   ├── state_machine.py    # Receipt-driven transitions, retries, approval gate, and replay logic
│   ├── trace_builder.py    # OTLP JSON resource spans generator
│   └── main.py             # FastAPI entrypoint, exception handlers, and API routes
├── tests/
│   ├── __init__.py
│   ├── conftest.py         # Isolated file-backed test database and test fixtures
│   ├── test_incident_agent.py      # Comprehensive 23-test unit & functional suite
│   └── test_live_model_integration.py # Optional live LLM integration test
├── Dockerfile              # Container image definition
├── render.yaml             # Render infrastructure blueprint
├── requirements.txt        # Pinned Python dependencies
├── pytest.ini              # Pytest configuration
├── .env.example            # Environment variable template
└── README.md               # Complete documentation
```

---

## Required Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check endpoint returning `{"status": "ok", "version": "2.0.0"}` |
| `POST` | `/v2/incidents` | Accepts incident report, runs initial diagnosis, dispatches diagnostics |
| `POST` | `/v2/incidents/{runId}/receipts` | Processes authoritative tool outcomes and approval decisions |
| `GET` | `/v2/incidents/{runId}` | Retrieves persisted current state, logs, and matching OTLP trace |

---

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy database URL (PostgreSQL on Render, SQLite locally) | `postgresql://user:pass@ep-host.oregon-postgres.render.com/db` |
| `MODEL_API_KEY` | API key for OpenAI-compatible model provider | `sk-proj-...` |
| `MODEL_BASE_URL` | Base URL for OpenAI-compatible API | `https://api.openai.com/v1` |
| `MODEL_NAME` | Model name to execute planning | `gpt-4o-mini` |
| `PORT` | Port for Uvicorn server (automatically provided by Render) | `8000` |
| `ENVIRONMENT` | Deployment environment | `production` |

---

## Local Development Setup

### Windows (PowerShell)

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd C:\Users\Jayraj\.gemini\antigravity\scratch\ga5-incident-agent
   ```

2. Create and activate a Python virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Create local environment file:
   ```powershell
   Copy-Item .env.example .env
   ```

---

### Linux / macOS (Bash)

1. Clone or navigate to the repository:
   ```bash
   cd ga5-incident-agent
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Create `.env` file:
   ```bash
   cp .env.example .env
   ```

---

## Running the Application Locally

Start the FastAPI application with Uvicorn:

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify the health check:
```bash
curl http://localhost:8000/health
```
Response:
```json
{"status":"ok","version":"2.0.0"}
```

---

## Running Automated Tests

Run the full pytest suite:

```bash
python -m pytest -v
```

All 23 core tests verify:
- Initial incident planning with minimal diagnostic selection
- Root cause constraint to `allowedRootCauses`
- Two to four unique evidence IDs cited directly from transcript
- Parallel diagnostic dispatching and `incident.join` span generation
- HTTP 503 retry semantics (attempt 1 to 2, new client span ID, same action ID)
- Suppression of second 503 retry and failure transition
- Diagnostic timeout suppression of dependent effects
- Destructive effect approval gate (`rollback_deployment`, `disable_feature`)
- Rejection of destructive actions when approval is declined
- Preservation of reserved action ID upon approval
- Exact lowercase SHA-256 compact canonical arguments digest
- Replay idempotency for initial requests and receipts
- Changed-content conflict handling (HTTP 409)
- Rejection of invalid receipts (HTTP 422)
- Persistence across server restarts using file-backed database
- W3C Traceparent propagation and child span hierarchy
- Complete redaction of credentials, tokens, prompts, and tool arguments/results
- Response sizes comfortably below the 768 KiB threshold

### Optional Live Model Integration Test

To verify connectivity with an actual OpenAI-compatible endpoint:

```bash
export MODEL_API_KEY="your-actual-api-key"
export RUN_LIVE_MODEL_TESTS="1"
python -m pytest tests/test_live_model_integration.py -v
```

---

## API Usage & Examples

### 1. Initial Incident Planning (`POST /v2/incidents`)

**Request**:
```bash
curl -X POST http://localhost:8000/v2/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "ga5-incident-agent/v2",
    "runId": "run_demo_001",
    "agentName": "incident-response",
    "publicMarker": "marker_pub_abc",
    "sensitive": {
      "accessToken": "secret_token_123",
      "privateNote": "Confidential internal note"
    },
    "incident": {
      "incidentId": "inc_901",
      "title": "Auth Gateway Connection Starvation",
      "service": "auth-gateway",
      "severity": "SEV-1",
      "transcript": "2026-10-23T10:00:00Z [ev_load] Traffic surge detected\n2026-10-23T10:01:00Z [ev_pool] Connection pool limit 100/100 reached\n2026-10-23T10:02:00Z [ev_timeout] DB queries timed out",
      "allowedRootCauses": ["database_pool_exhaustion", "network_partition"]
    },
    "toolCatalog": [
      {
        "name": "query_db_pool",
        "description": "Checks connection pool metrics",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
      },
      {
        "name": "rollback_deployment",
        "description": "Rolls back service release",
        "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}
      }
    ],
    "policy": {
      "maximumDiagnostics": 3,
      "effectTools": ["rollback_deployment"],
      "approvalRequiredFor": ["rollback_deployment"],
      "doNotExport": ["accessToken", "privateNote"]
    }
  }'
```

**Response (`status: "waiting"`)**:
```json
{
  "runId": "run_demo_001",
  "status": "waiting",
  "diagnosis": {
    "rootCause": "database_pool_exhaustion",
    "evidence": ["ev_pool", "ev_timeout"]
  },
  "dispatches": [
    {
      "actionId": "act_a1b2c3d4",
      "callId": "call_e5f6g7h8",
      "phase": "diagnostic",
      "toolName": "query_db_pool",
      "arguments": {"service": "auth-gateway"},
      "evidence": ["ev_pool"],
      "attempt": 1,
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    }
  ],
  "approvals": []
}
```

---

### 2. Submitting Authoritative Receipts (`POST /v2/incidents/{runId}/receipts`)

#### Diagnostic Outcome Receipt:
```bash
curl -X POST http://localhost:8000/v2/incidents/run_demo_001/receipts \
  -H "Content-Type: application/json" \
  -d '{
    "receiptId": "rcpt_outcome_001",
    "outcomes": [
      {
        "actionId": "act_a1b2c3d4",
        "callId": "call_e5f6g7h8",
        "attempt": 1,
        "status": 200,
        "resultClass": "diagnosis_confirmed",
        "nonce": "e3b0c442-98fc-1c14-9afb-4c8996fb9242"
      }
    ]
  }'
```

If the chosen effect requires approval (`rollback_deployment`), the service responds with:
```json
{
  "runId": "run_demo_001",
  "status": "waiting",
  "diagnosis": {"rootCause": "database_pool_exhaustion", "evidence": ["ev_pool", "ev_timeout"]},
  "dispatches": [],
  "approvals": [
    {
      "approvalId": "app_98765432",
      "actionId": "act_res_12345678",
      "toolName": "rollback_deployment",
      "argumentsDigest": "b4c2...7a1f"
    }
  ]
}
```

#### Approval Decision Receipt:
```bash
curl -X POST http://localhost:8000/v2/incidents/run_demo_001/receipts \
  -H "Content-Type: application/json" \
  -d '{
    "receiptId": "rcpt_app_001",
    "approvals": [
      {
        "approvalId": "app_98765432",
        "decision": "approved",
        "nonce": "c7a8b9d0-1234-5678-90ab-cdef12345678"
      }
    ]
  }'
```

---

### 3. Fetching Run State (`GET /v2/incidents/{runId}`)

```bash
curl http://localhost:8000/v2/incidents/run_demo_001
```

**Terminal Response (`status: "completed"`)**:
```json
{
  "runId": "run_demo_001",
  "status": "completed",
  "diagnosis": {
    "rootCause": "database_pool_exhaustion",
    "evidence": ["ev_pool", "ev_timeout"]
  },
  "chosenEffect": "rollback_deployment",
  "suppressed": [],
  "actionLog": [
    {
      "actionId": "act_a1b2c3d4",
      "callId": "call_e5f6g7h8",
      "phase": "diagnostic",
      "toolName": "query_db_pool",
      "arguments": {"service": "auth-gateway"},
      "evidence": ["ev_pool"],
      "attempt": 1,
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    },
    {
      "actionId": "act_res_12345678",
      "callId": "call_effect_999",
      "phase": "effect",
      "toolName": "rollback_deployment",
      "arguments": {"service": "auth-gateway"},
      "evidence": [],
      "attempt": 1,
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-11e178bb1ca013c8-01",
      "approvalId": "app_98765432",
      "approvalNonce": "c7a8b9d0-1234-5678-90ab-cdef12345678"
    }
  ],
  "receiptLog": [
    {
      "receiptId": "rcpt_outcome_001",
      "actionId": "act_a1b2c3d4",
      "callId": "call_e5f6g7h8",
      "attempt": 1,
      "status": 200,
      "resultClass": "diagnosis_confirmed",
      "nonce": "e3b0c442-98fc-1c14-9afb-4c8996fb9242"
    },
    {
      "receiptId": "rcpt_app_001",
      "approvalId": "app_98765432",
      "decision": "approved",
      "nonce": "c7a8b9d0-1234-5678-90ab-cdef12345678"
    }
  ],
  "otlp": {
    "resourceSpans": [
      {
        "resource": {"attributes": [...]},
        "scopeSpans": [
          {
            "scope": {"name": "ga5.incident.agent", "version": "1.0.0"},
            "spans": [...]
          }
        ]
      }
    ]
  },
  "dispatches": [],
  "approvals": []
}
```

---

## Step-by-Step Render Deployment Guide

### Option A: Manual Web Service + PostgreSQL Setup

#### Step 1: Push Code to GitHub
1. Create a repository on GitHub (e.g. `ga5-incident-agent`).
2. Commit and push:
   ```bash
   git init
   git add .
   git commit -m "feat: complete observable incident triage agent"
   git branch -M main
   git remote add origin https://github.com/<your-username>/ga5-incident-agent.git
   git push -u origin main
   ```

#### Step 2: Create PostgreSQL Database on Render
1. Log into your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** -> **PostgreSQL**.
3. Configure:
   - **Name**: `ga5-incident-db`
   - **Database**: `ga5_db`
   - **User**: `ga5_user`
   - **Region**: Choose closest to you (e.g., Oregon or Frankfurt).
   - **Plan**: Free.
4. Click **Create Database**.
5. Copy the **Internal Database URL** (or External if hosting externally).

> [!NOTE]
> Render's free PostgreSQL databases expire after 30 days of inactivity. For grading, the database will be active and persist all runs during evaluation.

#### Step 3: Create Web Service on Render
1. In Render Dashboard, click **New +** -> **Web Service**.
2. Connect your GitHub repository: `ga5-incident-agent`.
3. Configure the service settings:
   - **Name**: `ga5-incident-agent`
   - **Region**: Same region as your database.
   - **Branch**: `main`
   - **Root Directory**: (Leave blank / repo root)
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
   - **Plan**: Free.

4. Expand **Advanced** -> Add **Environment Variables**:
   - `DATABASE_URL`: Paste the PostgreSQL connection string from Step 2.
     *(The code automatically rewrites `postgres://` to `postgresql://` so SQLAlchemy 2 connects smoothly)*.
   - `MODEL_API_KEY`: Your OpenAI / OpenRouter / Groq API key.
   - `MODEL_BASE_URL`: `https://api.openai.com/v1` (or your provider's base URL).
   - `MODEL_NAME`: `gpt-4o-mini` (or equivalent inexpensive model).
   - `ENVIRONMENT`: `production`

5. In **Health Check Path**, enter:
   ```
   /health
   ```
6. Click **Create Web Service**.

---

### Option B: Render Blueprint Deployment (`render.yaml`)

1. Connect your repository to Render via **New +** -> **Blueprint**.
2. Render detects `render.yaml` automatically.
3. Supply `MODEL_API_KEY` when prompted in the dashboard.
4. Click **Apply**. Render will automatically provision both the PostgreSQL instance and Web Service with attached environment variables.

---

## Submission to the Grader

1. Once the deployment finishes, copy your public service HTTPS base URL from the top of the Render Web Service page:
   ```
   https://ga5-incident-agent-xxxx.onrender.com
   ```
2. Verify the live endpoint:
   ```bash
   curl https://ga5-incident-agent-xxxx.onrender.com/health
   ```
3. Submit the base URL with **no trailing slash, credentials, query string, or fragment**:
   ```
   https://ga5-incident-agent-xxxx.onrender.com
   ```

---

## Troubleshooting & Common Deployment Fixes

1. **Cold Starts on Free Tier**:
   - Render's free tier spins down web services after 15 minutes of inactivity.
   - Before running Check or Save in the grading portal, send a simple GET request to `/health` to ensure the instance is awake and warm within the grader's 18-second per-request window.

2. **Database Connection String**:
   - Render supplies `postgres://...` in `DATABASE_URL`. SQLAlchemy 2 requires `postgresql://`.
   - `app/config.py` normalizes this automatically.

3. **Missing Model Credentials**:
   - If `MODEL_API_KEY` is not provided, new incident requests receive a controlled HTTP 503 error ("MODEL_API_KEY is not configured").
   - Ensure the API key is configured in Render's environment settings.
