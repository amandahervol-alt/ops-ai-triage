# 🛠️ OpsAI-Triage: Operational AI & Developer Tooling Agent

> **Production-grade FastAPI microservice leveraging Claude 3.5 Sonnet tool-calling, Pydantic deterministic guardrails, and automated Pytest regression generation for Incident Triage and PR Code Auditing.**

---

## 🎯 Purpose & Overview
`OpsAI-Triage` is an operational AI assistant built to bridge the gap between high-velocity software engineering and production system reliability. It automates two critical engineering workflows:

1. **Automated Incident Triage & RCA:** Ingests raw stack traces/server logs, performs root-cause analysis (RCA), checks for sensitive PII/secret leaks, and generates executable Pytest code snippets to prevent bug regressions.
2. **Automated PR Code Auditing:** Audits Git diff patches for security vulnerabilities, performance bottlenecks (e.g., N+1 query loops), and unit test coverage prior to PR merge.

---

## 🏗️ Architecture

```
                               ┌────────────────────────────────┐
                               │  FastAPI Microservice Endpoint │
                               └───────────────┬────────────────┘
                                               │
                                               ▼
                               ┌────────────────────────────────┐
                               │   Claude 3.5 Sonnet Agent      │
                               │   (Structured Tool-Calling)    │
                               └───────────────┬────────────────┘
                                               │
                                               ▼
                               ┌────────────────────────────────┐
                               │  Pydantic Deterministic Gate   │
                               │  (Schema & Guardrail Check)    │
                               └───────────────┬────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
  [ Structured JSON Payload ]                                         [ Executable Pytest Fix ]
   (RCA, Severity, Security Risk)                                     (Regression Test Suite)
```

---

## 🚀 Key Features & Guardrails

* **Zero-Hallucination Schema Enforcement:** Uses strict Pydantic models (`schemas.py`) to guarantee valid JSON responses.
* **Deterministic Security Scans:** Scans inputs and log payloads for exposed secrets, passwords, and unsafe execution syntax (`eval()`, `shell=True`).
* **Tool-Calling Integration:** Uses Anthropic Claude 3.5 Sonnet function calling (`submit_incident_report` and `submit_pr_audit`).
* **Fallback Execution Mode:** Includes a deterministic offline simulation engine when live API keys are not present, ensuring 100% test reliability.

---

## 💻 Quickstart & API Reference

### 1. Installation

```bash
git clone https://github.com/amandahervol-alt/ops-ai-triage.git
cd ops-ai-triage
pip install -r requirements.txt
```

### 2. Running the FastAPI Server

```bash
uvicorn main:app --reload --port 8000
```
* Interactive Swagger Docs: `http://localhost:8000/docs`
* ReDoc Specification: `http://localhost:8000/redoc`

### 3. API Endpoints

#### A. Incident Triage Endpoint (`POST /api/v1/triage-log`)
**Sample Request:**
```json
{
  "log_content": "ERROR 2026-10-03 [payment-service] DatabaseTimeoutException: Connection attempt to postgresql://db.internal:5432 timed out. API_KEY=secret_12345",
  "service_name": "payment-service",
  "environment": "production"
}
```

#### B. PR Audit Endpoint (`POST /api/v1/audit-pr`)
**Sample Request:**
```json
{
  "git_diff": "diff --git a/app.py b/app.py\n+ secret_token = 'sk_live_999999'\n+ eval(user_input)",
  "repository": "billing-backend"
}
```

---

## 🧪 Testing

Run the full pytest suite to verify zero-hallucination guardrails and API schema validation:

```bash
py -m pytest test_ops_ai.py -v
```

---

## 🎙️ Interview Talking Point

> *"I designed and built **OpsAI-Triage**, an open-source FastAPI microservice that ingests server stack traces and git diffs, leverages Claude 3.5 Sonnet tool-calling to generate automated root-cause analyses and pytest regression tests, and enforces strict Pydantic schemas to ensure zero-hallucination outputs."*
