import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from src.triage_agent.database import MIGRATIONS, TriageDatabase
from src.triage_agent.schemas import VulnerabilityAssessment


def make_assessment(**overrides) -> VulnerabilityAssessment:
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
def db():
    with TriageDatabase(":memory:") as database:
        yield database


def store(db, text="finding", severity="High", cwe="CWE-89", errors=(), decision=None):
    """Create a finding with an assessment, validation result, and decision."""

    finding_id = db.add_finding(text)
    assessment_id = db.add_assessment(
        finding_id, make_assessment(severity=severity, cwe=cwe)
    )
    db.add_validation_result(finding_id, assessment_id, list(errors))

    if decision:
        db.add_approval(assessment_id, decision, "reviewed")

    return finding_id, assessment_id


# --- schema ------------------------------------------------------------

def test_schema_version_matches_migrations(db):
    assert db.schema_version == len(MIGRATIONS)


def test_reopening_does_not_reapply_migrations(tmp_path):
    path = tmp_path / "triage.sqlite3"

    first = TriageDatabase(path)
    first.add_finding("kept across restarts")
    first.close()

    second = TriageDatabase(path)

    assert second.schema_version == len(MIGRATIONS)
    assert second._rows("SELECT COUNT(*) AS n FROM findings")[0]["n"] == 1
    second.close()


def test_foreign_keys_are_enforced(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.add_assessment(9999, make_assessment())


def test_check_constraint_rejects_bad_severity(db):
    finding_id = db.add_finding("x")

    with pytest.raises(sqlite3.IntegrityError):
        db._conn.execute(
            "INSERT INTO assessments (finding_id, title, vulnerability_type, "
            "severity, confidence, assessment_json, created_at) "
            "VALUES (?, 't', 'v', 'Catastrophic', 0.5, '{}', 'now')",
            (finding_id,),
        )


def test_check_constraint_rejects_confidence_out_of_range(db):
    finding_id = db.add_finding("x")

    with pytest.raises(sqlite3.IntegrityError):
        db._conn.execute(
            "INSERT INTO assessments (finding_id, title, vulnerability_type, "
            "severity, confidence, assessment_json, created_at) "
            "VALUES (?, 't', 'v', 'High', 1.5, '{}', 'now')",
            (finding_id,),
        )


# --- privacy -----------------------------------------------------------

def test_finding_is_stored_redacted(db):
    finding_id = db.add_finding(
        "Admin alice@example.com used password: Hunter2! from 10.0.0.5"
    )

    row = db._rows("SELECT * FROM findings WHERE id = ?", (finding_id,))[0]

    assert "alice@example.com" not in row["finding_redacted"]
    assert "Hunter2!" not in row["finding_redacted"]
    assert "10.0.0.5" not in row["finding_redacted"]
    assert json.loads(row["redaction_summary"]) == {
        "CREDENTIAL": 1, "EMAIL": 1, "IPV4": 1
    }


def test_assessment_json_is_redacted(db):
    finding_id = db.add_finding("x")
    assessment_id = db.add_assessment(
        finding_id,
        make_assessment(evidence=["Leaked token: api_key=sk-abcdefghijklmnopqrstuv"]),
    )

    stored = db.get_assessment(assessment_id)

    assert "sk-abcdefghijklmnopqrstuv" not in json.dumps(stored["assessment"])


def test_sql_injection_text_is_stored_as_data(db):
    hostile = "x'); DROP TABLE findings; --"

    db.add_finding(hostile)

    assert db._rows("SELECT COUNT(*) AS n FROM findings")[0]["n"] == 1
    assert db._rows("SELECT finding_redacted FROM findings")[0][
        "finding_redacted"
    ] == hostile


def test_duplicate_findings_are_detected_without_storing_raw_text(db):
    db.add_finding("Reflected XSS in /search")
    db.add_finding("reflected   xss in /search")
    db.add_finding("Something else")

    duplicates = db.duplicate_findings()

    assert len(duplicates) == 1
    assert duplicates[0]["submissions"] == 2


# --- workflow records --------------------------------------------------

def test_assessment_and_tool_calls_round_trip(db):
    finding_id = db.add_finding("x")
    assessment_id = db.add_assessment(
        finding_id,
        make_assessment(),
        tool_calls=[{"tool": "lookup_cwe", "arguments": {"cwe_id": "CWE-89"}}],
    )

    stored = db.get_assessment(assessment_id)
    tools = db._rows("SELECT * FROM tool_calls")

    assert stored["cwe"] == "CWE-89"
    assert stored["assessment"]["severity"] == "High"
    assert len(tools) == 1 and tools[0]["tool"] == "lookup_cwe"


def test_undetermined_cwe_is_stored_as_null(db):
    _, assessment_id = store(db, cwe=None, severity="Informational")

    assert db.get_assessment(assessment_id)["cwe"] is None


def test_decision_must_be_valid(db):
    _, assessment_id = store(db)

    with pytest.raises(ValueError):
        db.add_approval(assessment_id, "maybe")


def test_only_one_decision_per_assessment(db):
    _, assessment_id = store(db, decision="approve")

    with pytest.raises(sqlite3.IntegrityError):
        db.add_approval(assessment_id, "reject")


def test_pending_approvals_only_lists_valid_undecided(db):
    _, pending = store(db)
    store(db, decision="approve")
    store(db, errors=["Unsupported evidence claim."])

    result = db.pending_approvals()

    assert [row["assessment_id"] for row in result] == [pending]


# --- reporting ---------------------------------------------------------

def test_approval_summary_by_severity(db):
    store(db, severity="High", decision="approve")
    store(db, severity="High", decision="reject")
    store(db, severity="High", decision="approve")
    store(db, severity="Low")
    store(db, severity="Critical", decision="approve")

    summary = {row["severity"]: row for row in db.approval_summary_by_severity()}

    assert list(summary) == ["Critical", "High", "Low"]  # severity order
    assert summary["High"]["assessed"] == 3
    assert summary["High"]["approved"] == 2
    assert summary["High"]["rejected"] == 1
    assert summary["High"]["approval_rate"] == 0.67
    assert summary["Low"]["undecided"] == 1
    assert summary["Low"]["approval_rate"] is None  # no decisions yet


def test_cwe_breakdown_groups_null_as_undetermined(db):
    store(db, cwe="CWE-89", decision="approve")
    store(db, cwe="CWE-89", decision="reject")
    store(db, cwe=None, severity="Informational")

    rows = {row["cwe"]: row for row in db.cwe_breakdown()}

    assert rows["CWE-89"]["assessed"] == 2
    assert rows["CWE-89"]["approved"] == 1
    assert rows["Undetermined"]["assessed"] == 1


def test_top_validation_errors(db):
    store(db, errors=["Unsupported claim.", "Wrong CWE."])
    store(db, errors=["Unsupported claim."])

    top = db.top_validation_errors(limit=1)

    assert top == [{"message": "Unsupported claim.", "occurrences": 2}]


# --- audit trail -------------------------------------------------------

def test_audit_trail_records_the_full_lifecycle(db):
    finding_id, _ = store(db, decision="approve")

    events = [row["event"] for row in db.audit_trail(finding_id)]

    assert events == [
        "finding_received",
        "assessment_created",
        "validation_passed",
        "assessment_approved",
    ]


def test_audit_log_cannot_be_updated(db):
    db.log_event("something_happened")

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db._conn.execute("UPDATE audit_log SET event = 'tampered'")


def test_audit_detail_is_redacted(db):
    db.log_event("note", detail="contact bob@example.com")

    assert "bob@example.com" not in db._rows("SELECT detail FROM audit_log")[0]["detail"]


# --- retention ---------------------------------------------------------

def test_purge_removes_old_data_and_cascades():
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    current = {"time": now - timedelta(days=100)}

    with TriageDatabase(":memory:", clock=lambda: current["time"]) as db:
        store(db, text="old finding", decision="approve")

        current["time"] = now
        _, recent_assessment = store(db, text="recent finding")

        result = db.purge_older_than(days=30)

        assert result["findings"] == 1
        assert [r["finding_redacted"] for r in db._rows("SELECT * FROM findings")] == [
            "recent finding"
        ]

        # Everything linked to the old finding went with it.
        assert db._rows("SELECT COUNT(*) AS n FROM approvals")[0]["n"] == 0
        assert db._rows("SELECT COUNT(*) AS n FROM validation_errors")[0]["n"] == 0
        assert db.get_assessment(recent_assessment) is not None

        # The purge itself is on record.
        events = [r["event"] for r in db._rows("SELECT event FROM audit_log")]
        assert "retention_purge" in events


def test_purge_rejects_negative_days(db):
    with pytest.raises(ValueError):
        db.purge_older_than(-1)
