"""Restart-survival test for the persistent workflow.

The LLM and vector store are replaced with stubs so the test needs
neither Ollama nor ChromaDB data, but the LangGraph workflow, the SQLite
checkpointer, and the SQL recording nodes are all real.
"""

import pytest
from langgraph.types import Command

import src.triage_agent.graph as graph_module
from src.triage_agent.schemas import VulnerabilityAssessment


class _Report:
    page_content = "Historical report about SQL injection."


def _assessment(**overrides):
    values = dict(
        title="SQL Injection in Login Endpoint",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity="High",
        confidence=0.9,
        evidence=["The id parameter is concatenated into a query."],
        retrieved_context=[],
        potential_impact="Data exposure.",
        verified_impact="None demonstrated.",
        limitations=["Not exploited."],
        reasoning="Concatenation without parameterisation.",
        remediation="Use parameterised queries.",
    )
    values.update(overrides)
    return VulnerabilityAssessment(**values)


@pytest.fixture
def stubbed(monkeypatch):
    monkeypatch.setattr(graph_module, "search_reports", lambda finding, k=3: [_Report()])
    monkeypatch.setattr(
        graph_module,
        "analyse_finding",
        lambda finding, context: {
            "assessment": _assessment(),
            "tool_calls": [{"tool": "lookup_cwe", "arguments": {"cwe_id": "CWE-89"}}],
        },
    )
    # Validation is covered by its own tests; here it is a pass-through.
    monkeypatch.setattr(graph_module, "validate_assessment", lambda finding, assessment: [])


FINDING = "Login id parameter is concatenated into a SQL query. Contact bob@example.com"
CONFIG = {"configurable": {"thread_id": "case-1"}}


def test_pending_approval_survives_restart_and_is_recorded(tmp_path, stubbed):
    db_path = tmp_path / "triage.sqlite3"

    # --- first run: stops at the human approval gate -------------------
    graph, db, close = graph_module.create_persistent_graph(db_path)
    graph.invoke({"finding": FINDING}, CONFIG)

    assert graph.get_state(CONFIG).next == ("approval",)
    assert len(db.pending_approvals()) == 1
    close()  # simulates the application exiting

    # --- second run: new process state, same file ----------------------
    graph, db, close = graph_module.create_persistent_graph(db_path)

    assert graph.get_state(CONFIG).next == ("approval",)

    result = graph.invoke(Command(resume={"decision": "approve"}), CONFIG)

    assert result["approved"] is True
    assert "MOCK VULNERABILITY DISCLOSURE REPORT" in result["mock_disclosure"]

    # The decision is in SQL, exactly once.
    assert db.pending_approvals() == []
    summary = db.approval_summary_by_severity()
    assert summary[0]["severity"] == "High" and summary[0]["approved"] == 1

    finding_id = result["finding_id"]
    assert [row["event"] for row in db.audit_trail(finding_id)] == [
        "finding_received",
        "assessment_created",
        "validation_passed",
        "assessment_approved",
    ]

    # The raw email never reached the relational tables.
    stored = db._rows("SELECT finding_redacted, thread_id FROM findings")[0]
    assert "bob@example.com" not in stored["finding_redacted"]
    assert stored["thread_id"] == "case-1"

    close()


def test_rejection_is_recorded(tmp_path, stubbed):
    graph, db, close = graph_module.create_persistent_graph(tmp_path / "t.sqlite3")

    graph.invoke({"finding": FINDING}, CONFIG)
    result = graph.invoke(Command(resume={"decision": "reject"}), CONFIG)

    assert result["approved"] is False
    assert result.get("mock_disclosure") is None
    assert db.approval_summary_by_severity()[0]["rejected"] == 1

    close()


def test_validation_failure_stops_before_approval(tmp_path, monkeypatch, stubbed):
    monkeypatch.setattr(
        graph_module,
        "validate_assessment",
        lambda finding, assessment: ["Evidence is not supported by the finding."],
    )

    graph, db, close = graph_module.create_persistent_graph(tmp_path / "t.sqlite3")
    result = graph.invoke({"finding": FINDING}, CONFIG)

    assert graph.get_state(CONFIG).next == ()  # finished, never asked for approval
    assert db.pending_approvals() == []
    assert db.top_validation_errors() == [
        {"message": "Evidence is not supported by the finding.", "occurrences": 1}
    ]
    assert [row["event"] for row in db.audit_trail(result["finding_id"])][-1] == (
        "validation_failed"
    )

    close()


def test_default_graph_still_works_without_a_database(stubbed):
    config = {"configurable": {"thread_id": "no-db"}}

    graph_module.triage_graph.invoke({"finding": FINDING}, config)
    result = graph_module.triage_graph.invoke(
        Command(resume={"decision": "approve"}), config
    )

    assert result["approved"] is True
