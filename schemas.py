"""
Pydantic Schemas for ops-ai-triage
Enforces strict, deterministic type validation and zero-hallucination guardrails
for Operational Incident Triage and PR Code Auditing.
"""

from typing import List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentTriageRequest(BaseModel):
    log_content: str = Field(
        ..., 
        description="Raw server log, stack trace, or error payload",
        min_length=10
    )
    environment: Optional[str] = Field("production", description="Environment where incident occurred")
    service_name: Optional[str] = Field("unknown-service", description="Name of the reporting microservice")


class IncidentTriageReport(BaseModel):
    service_name: str = Field(description="Name of the affected service")
    error_type: str = Field(description="Categorized error class (e.g. DatabaseTimeout, NullPointer, UnhandledException)")
    severity: SeverityLevel = Field(description="Severity classification of the incident")
    root_cause_analysis: str = Field(description="Clear, technical explanation of the root cause")
    recommended_resolution: str = Field(description="Step-by-step resolution guide for engineers")
    generated_pytest_fix: str = Field(description="Executable Pytest regression test to prevent recurrence")
    security_risk_detected: bool = Field(description="True if sensitive keys, passwords, or PII were found in logs")
    confidence_score: float = Field(description="Agent confidence score between 0.0 and 1.0", ge=0.0, le=1.0)


class PRAuditRequest(BaseModel):
    git_diff: str = Field(
        ..., 
        description="Git diff patch or code changeset to audit",
        min_length=10
    )
    author: Optional[str] = Field("unknown", description="Author of the PR")
    repository: Optional[str] = Field("main-repo", description="Repository name")


class PRAuditReport(BaseModel):
    repository: str = Field(description="Target repository")
    summary: str = Field(description="Executive summary of the PR code changes")
    security_vulnerabilities: List[str] = Field(default_factory=list, description="List of detected security concerns")
    performance_bottlenecks: List[str] = Field(default_factory=list, description="List of potential latency/memory issues")
    suggested_unit_tests: List[str] = Field(default_factory=list, description="Suggested test cases to add before merging")
    approval_recommendation: str = Field(description="RECOMMENDED_APPROVE, NEEDS_REVISION, or BLOCK_SECURITY_RISK")
    hallucination_guardrail_passed: bool = Field(default=True, description="Deterministic validation pass state")
