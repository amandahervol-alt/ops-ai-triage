"""
OpsAI-Triage FastAPI Server
Production microservice for AI-powered Incident Triage and PR Code Auditing.
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from schemas import (
    IncidentTriageRequest, 
    IncidentTriageReport, 
    PRAuditRequest, 
    PRAuditReport
)
from agent import OpsAIAgent

app = FastAPI(
    title="OpsAI-Triage Microservice",
    description="Operational AI & Developer Tooling Agent for Log Triage, RCA Generation, and Automated PR Auditing.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for local testing / dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Agent Engine
agent_engine = OpsAIAgent()


@app.get("/", tags=["Health"])
def root():
    return {
        "service": "OpsAI-Triage Microservice",
        "status": "healthy",
        "version": "1.0.0",
        "endpoints": ["/api/v1/triage-log", "/api/v1/audit-pr", "/health"]
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok", "mode": "active"}


@app.post(
    "/api/v1/triage-log", 
    response_model=IncidentTriageReport, 
    status_code=status.HTTP_200_OK,
    tags=["Ops AI Core"]
)
def triage_incident_log(request: IncidentTriageRequest):
    """
    Ingests raw server logs or stack traces, conducts RCA, generates executable pytest fixes,
    and checks for PII/security leaks.
    """
    try:
        report = agent_engine.triage_incident(request)
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process incident triage: {str(e)}"
        )


@app.post(
    "/api/v1/audit-pr", 
    response_model=PRAuditReport, 
    status_code=status.HTTP_200_OK,
    tags=["Ops AI Core"]
)
def audit_pr_diff(request: PRAuditRequest):
    """
    Ingests Git diff patches, audits security vulnerabilities, performance bottlenecks,
    and suggests unit tests prior to merge.
    """
    try:
        report = agent_engine.audit_pr(request)
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to audit PR diff: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
