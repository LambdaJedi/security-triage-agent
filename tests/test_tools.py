
import pytest

from src.triage_agent.tools import lookup_cwe, assess_severity


def test_lookup_known_cwe():
    result = lookup_cwe.invoke({
        "cwe_id": "CWE-89"
    })

    assert "CWE-89" in result
    assert "SQL Injection" in result
    assert "parameterized queries" in result


def test_lookup_unknown_cwe():
    result = lookup_cwe.invoke({
        "cwe_id": "CWE-99999"
    })

    assert "not found" in result


def test_severity_critical():
    result = assess_severity.invoke({
        "impact": 4,
        "exploitability": 4
    })

    assert "Critical" in result


def test_severity_high():
    result = assess_severity.invoke({
        "impact": 3,
        "exploitability": 3
    })

    assert "High" in result


def test_severity_medium():
    result = assess_severity.invoke({
        "impact": 2,
        "exploitability": 1
    })

    assert "Medium" in result


def test_invalid_impact():
    result = assess_severity.invoke({
        "impact": 5,
        "exploitability": 3
    })

    assert "Invalid impact" in result


def test_invalid_exploitability():
    result = assess_severity.invoke({
        "impact": 3,
        "exploitability": 0
    })

    assert "Invalid exploitability" in result
