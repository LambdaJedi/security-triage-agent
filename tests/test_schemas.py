
import pytest
from pydantic import ValidationError

from src.triage_agent.schemas import VulnerabilityAssessment


def test_valid_assessment():
    assessment = VulnerabilityAssessment(
        title="SQL Injection in Login Endpoint",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity="Critical",
        confidence=0.95,
        evidence=[
            "The login endpoint accepts user-controlled input.",
            "User input is directly incorporated into SQL queries."
        ],
        retrieved_context=[
            "A historical report describes a similar SQL injection issue."
        ],
        potential_impact=(
            "An attacker could potentially bypass authentication "
            "or access unauthorised database records."
        ),
        verified_impact=(
            "No successful exploitation or unauthorised access "
            "has been demonstrated."
        ),
        limitations=[
            "The finding has not been independently reproduced.",
            "Database access has not been verified."
        ],
        reasoning=(
            "Directly incorporating untrusted input into SQL queries "
            "is consistent with SQL injection."
        ),
        remediation="Use parameterized SQL queries."
    )

    assert assessment.severity == "Critical"
    assert assessment.confidence == 0.95
    assert len(assessment.evidence) == 2
    assert len(assessment.retrieved_context) == 1


def test_invalid_severity():
    with pytest.raises(ValidationError):
        VulnerabilityAssessment(
            title="Test",
            vulnerability_type="SQL Injection",
            cwe="CWE-89",
            severity="Extreme",
            confidence=0.8,
            evidence=["Test evidence"],
            retrieved_context=[],
            potential_impact="Potential database access.",
            verified_impact="No impact demonstrated.",
            limitations=["Testing required."],
            reasoning="Test reasoning.",
            remediation="Use parameterized queries."
        )


def test_invalid_confidence():
    with pytest.raises(ValidationError):
        VulnerabilityAssessment(
            title="Test",
            vulnerability_type="SQL Injection",
            cwe="CWE-89",
            severity="High",
            confidence=1.5,
            evidence=["Test evidence"],
            retrieved_context=[],
            potential_impact="Potential database access.",
            verified_impact="No impact demonstrated.",
            limitations=["Testing required."],
            reasoning="Test reasoning.",
            remediation="Use parameterized queries."
        )


def test_missing_evidence():
    with pytest.raises(ValidationError):
        VulnerabilityAssessment(
            title="Test",
            vulnerability_type="SQL Injection",
            cwe="CWE-89",
            severity="High",
            confidence=0.8,
            retrieved_context=[],
            potential_impact="Potential database access.",
            verified_impact="No impact demonstrated.",
            limitations=["Testing required."],
            reasoning="Test reasoning.",
            remediation="Use parameterized queries."
        )
