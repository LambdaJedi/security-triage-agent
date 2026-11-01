
from src.triage_agent.schemas import VulnerabilityAssessment
from src.triage_agent.validation import (
    validate_assessment,
    validate_cwe,
)


def create_assessment(evidence, verified_impact):
    return VulnerabilityAssessment(
        title="Potential SQL Injection",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity="High",
        confidence=0.8,
        evidence=evidence,
        retrieved_context=[
            "A historical report describes a similar SQL injection."
        ],
        potential_impact="An attacker could bypass authentication.",
        verified_impact=verified_impact,
        limitations=["No successful exploitation demonstrated."],
        reasoning="The finding suggests possible SQL injection.",
        remediation="Use parameterized SQL queries."
    )


# Existing evidence validation tests

def test_supported_evidence():
    finding = (
        "The login endpoint accepts user input "
        "and directly inserts it into SQL queries."
    )

    assessment = create_assessment(
        evidence=[
            "The login endpoint accepts user input"
        ],
        verified_impact="No successful exploitation has been demonstrated."
    )

    errors = validate_assessment(finding, assessment)

    assert errors == []


def test_unsupported_evidence():
    finding = (
        "The login endpoint accepts user input "
        "and directly inserts it into SQL queries."
    )

    assessment = create_assessment(
        evidence=[
            "The attacker successfully bypassed authentication."
        ],
        verified_impact="No successful exploitation has been demonstrated."
    )

    errors = validate_assessment(finding, assessment)

    assert any("not directly supported" in error for error in errors)


def test_unsupported_verified_impact():
    finding = (
        "The login endpoint accepts user input "
        "and directly inserts it into SQL queries."
    )

    assessment = create_assessment(
        evidence=[
            "The login endpoint accepts user input"
        ],
        verified_impact="The attacker successfully exploited the endpoint."
    )

    errors = validate_assessment(finding, assessment)

    assert any("unsupported claim" in error for error in errors)


# New CWE classification validation tests

def test_supported_cwe_classification():
    finding = (
        "The login endpoint accepts user input "
        "and directly inserts it into SQL queries "
        "without parameterized statements."
    )

    assessment = create_assessment(
        evidence=[
            "The login endpoint accepts user input"
        ],
        verified_impact="No successful exploitation has been demonstrated."
    )

    errors = validate_cwe(finding, assessment)

    assert errors == []


def test_mismatched_cwe_classification():
    finding = (
        "The login endpoint accepts user input "
        "and directly inserts it into SQL queries "
        "without parameterized statements."
    )

    assessment = create_assessment(
        evidence=[
            "The login endpoint accepts user input"
        ],
        verified_impact="No successful exploitation has been demonstrated."
    )

    assessment.cwe = "CWE-79"

    errors = validate_cwe(finding, assessment)

    assert any("does not match" in error for error in errors)


def test_cwe_without_sufficient_evidence():
    finding = (
        "The application may have a security issue. "
        "Further investigation is required."
    )

    assessment = create_assessment(
        evidence=[],
        verified_impact="No impact has been demonstrated."
    )

    errors = validate_cwe(finding, assessment)

    assert any("insufficient evidence" in error for error in errors)
