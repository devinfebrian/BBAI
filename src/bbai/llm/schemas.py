"""Pydantic schemas for LLM structured outputs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilityAnalysis(BaseModel):
    """Schema for vulnerability analysis output."""

    model_config = ConfigDict(frozen=True)

    reasoning: str = Field(
        ...,
        description="Detailed step-by-step analysis",
    )
    is_true_positive: bool = Field(
        ...,
        description="Whether this is a true positive",
    )
    vulnerability_type: str = Field(
        ...,
        description="CWE ID or category name",
    )
    cvss_score: float | None = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS score if applicable",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in this assessment",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Remediation recommendations",
    )


class EndpointAnalysis(BaseModel):
    """Schema for endpoint analysis."""

    model_config = ConfigDict(frozen=True)

    url: str
    sensitivity: str = Field(..., pattern="^(high|medium|low)$")
    attack_surface: str = Field(..., pattern="^(high|medium|low)$")
    priority: int = Field(..., ge=1, le=10)
    reasoning: str


class EndpointAnalysisList(BaseModel):
    """Schema for list of endpoint analyses."""

    model_config = ConfigDict(frozen=True)

    endpoints: list[EndpointAnalysis]


class StrategyDecision(BaseModel):
    """Schema for strategy decision."""

    model_config = ConfigDict(frozen=True)

    decision: str = Field(
        ...,
        pattern="^(CONTINUE|EXPAND|DEEP_DIVE|VERIFY|COMPLETE)$",
    )
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    next_actions: list[str]


class ScopeValidation(BaseModel):
    """Schema for scope validation."""

    model_config = ConfigDict(frozen=True)

    in_scope: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    recommendation: str = Field(..., pattern="^(ALLOW|BLOCK|REVIEW)$")


class PIIFinding(BaseModel):
    """Schema for PII detection."""

    model_config = ConfigDict(frozen=True)

    type: str
    severity: str = Field(..., pattern="^(critical|high|medium|low)$")
    location: str
    recommendation: str


class PIIDetection(BaseModel):
    """Schema for PII detection results."""

    model_config = ConfigDict(frozen=True)

    pii_detected: bool
    findings: list[PIIFinding]


class SubdomainClassification(BaseModel):
    """Schema for subdomain classification."""

    model_config = ConfigDict(frozen=True)

    subdomain: str
    category: str = Field(..., pattern="^(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)$")
    purpose: str
    priority: int = Field(..., ge=1, le=10)
    test_recommended: bool


class SubdomainClassificationList(BaseModel):
    """Schema for list of subdomain classifications."""

    model_config = ConfigDict(frozen=True)

    subdomains: list[SubdomainClassification]
