
import sqlite3
from pathlib import Path

from langchain_core.runnables import RunnableConfig
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.types import interrupt

from src.triage_agent.state import TriageState
from src.triage_agent.agent import analyse_finding
from src.triage_agent.retrieval import search_reports
from src.triage_agent.approval import process_approval
from src.triage_agent.validation import validate_assessment
from src.triage_agent.database import TriageDatabase


def retrieve_node(state: TriageState):
    """Retrieve relevant historical security reports."""

    reports = search_reports(
        state["finding"],
        k=3
    )

    return {
        "retrieved_reports": [
            report.page_content for report in reports
        ]
    }


def analyse_node(state: TriageState):
    """Analyse the finding and record executed tools."""

    result = analyse_finding(
        state["finding"],
        context=state["retrieved_reports"]
    )

    return {
        "assessment": result["assessment"],
        "tool_calls": result["tool_calls"]
    }


def validate_node(state: TriageState):
    """Validate the generated assessment."""

    assessment = state.get("assessment")

    if assessment is None:
        return {
            "errors": state.get("errors", []) + [
                "No vulnerability assessment was generated."
            ],
            "validation_errors": [
                "Validation could not run because no assessment exists."
            ]
        }

    # Run independent validation checks
    validation_errors = validate_assessment(
        finding=state["finding"],
        assessment=assessment
    )

    return {
        "validation_errors": validation_errors
    }


def route_after_validation(state: TriageState):
    """Stop the workflow if validation fails."""

    if state.get("assessment") is None:
        return "invalid"

    if state.get("validation_errors"):
        return "invalid"

    return "valid"


def approval_node(state: TriageState):
    """Pause the workflow and request human approval."""

    assessment = state["assessment"]

    # Pause execution and present the assessment to the human
    decision = interrupt({
        "message": "Review the vulnerability assessment.",
        "assessment": assessment.model_dump()
    })

    # Process the human's decision after the workflow resumes
    result = process_approval(decision["decision"])

    return result


def route_after_approval(state: TriageState):
    """Choose the next workflow path based on human approval."""

    if state.get("approved") is True:
        return "approved"

    return "rejected"


def mock_disclosure_node(state: TriageState):
    """Generate a mock disclosure report after approval."""

    assessment = state["assessment"]

    evidence = "\n".join(
        f"- {item}" for item in assessment.evidence
    )

    retrieved_context = "\n".join(
        f"- {item}" for item in assessment.retrieved_context
    )

    limitations = "\n".join(
        f"- {item}" for item in assessment.limitations
    )

    disclosure = f"""
MOCK VULNERABILITY DISCLOSURE REPORT

Title:
{assessment.title}

Vulnerability Type:
{assessment.vulnerability_type}

CWE:
{assessment.cwe}

Severity:
{assessment.severity}

Confidence:
{assessment.confidence}

Submitted Evidence:
{evidence}

Historical Context:
{retrieved_context or "No relevant historical context retrieved."}

Potential Impact:
{assessment.potential_impact}

Verified Impact:
{assessment.verified_impact}

Limitations:
{limitations}

Analysis:
{assessment.reasoning}

Recommended Remediation:
{assessment.remediation}

Status:
Approved for mock disclosure.

NOTE:
This report was generated locally for demonstration.
It has not been submitted to any organisation or
vulnerability disclosure programme.
"""

    return {
        "mock_disclosure": disclosure
    }


# Configure checkpoint serialization
serializer = JsonPlusSerializer(
    allowed_msgpack_modules=[
        ("src.triage_agent.schemas", "VulnerabilityAssessment")
    ]
)


def _make_record_nodes(db: TriageDatabase):
    """Create the nodes that write workflow results to SQL."""

    def record_assessment_node(state: TriageState, config: RunnableConfig):
        """Store the finding, assessment, and tool calls."""

        thread_id = config.get("configurable", {}).get("thread_id")

        finding_id = db.add_finding(state["finding"], thread_id=thread_id)
        assessment = state.get("assessment")

        if assessment is None:
            db.log_event(
                "assessment_missing",
                finding_id=finding_id,
                detail="The analysis stage produced no assessment.",
            )
            return {"finding_id": finding_id, "assessment_id": None}

        assessment_id = db.add_assessment(
            finding_id,
            assessment,
            tool_calls=state.get("tool_calls", [])
        )

        return {"finding_id": finding_id, "assessment_id": assessment_id}

    def record_validation_node(state: TriageState):
        """Store the deterministic validation outcome."""

        db.add_validation_result(
            state["finding_id"],
            state.get("assessment_id"),
            state.get("validation_errors", [])
        )

        return {}

    def record_decision_node(state: TriageState):
        """Store the human approval decision."""

        decision = "approve" if state.get("approved") else "reject"

        db.add_approval(
            state["assessment_id"],
            decision,
            state.get("approval_message")
        )

        return {}

    return (
        record_assessment_node,
        record_validation_node,
        record_decision_node
    )


def build_graph(checkpointer=None, db: TriageDatabase | None = None):
    """Build and compile the triage workflow.

    Without ``db`` the graph matches the original in-memory workflow.
    With ``db`` three recording nodes are added so every finding,
    assessment, validation result, and human decision is written to SQL.
    """

    workflow = StateGraph(TriageState)

    workflow.add_node("retrieve", retrieve_node)
    workflow.add_node("analyse", analyse_node)
    workflow.add_node("validate", validate_node)
    workflow.add_node("approval", approval_node)
    workflow.add_node("mock_disclosure", mock_disclosure_node)

    workflow.add_edge(START, "retrieve")
    workflow.add_edge("retrieve", "analyse")

    after_validation = "validate"
    after_approval = "approval"

    if db is not None:
        (
            record_assessment_node,
            record_validation_node,
            record_decision_node
        ) = _make_record_nodes(db)

        workflow.add_node("record_assessment", record_assessment_node)
        workflow.add_node("record_validation", record_validation_node)
        workflow.add_node("record_decision", record_decision_node)

        workflow.add_edge("analyse", "record_assessment")
        workflow.add_edge("record_assessment", "validate")
        workflow.add_edge("validate", "record_validation")
        workflow.add_edge("approval", "record_decision")

        after_validation = "record_validation"
        after_approval = "record_decision"
    else:
        workflow.add_edge("analyse", "validate")

    # Route based on validation results
    workflow.add_conditional_edges(
        after_validation,
        route_after_validation,
        {
            "valid": "approval",
            "invalid": END
        }
    )

    # Route based on the human's decision
    workflow.add_conditional_edges(
        after_approval,
        route_after_approval,
        {
            "approved": "mock_disclosure",
            "rejected": END
        }
    )

    workflow.add_edge("mock_disclosure", END)

    return workflow.compile(checkpointer=checkpointer)


def create_persistent_graph(db_path: str | Path):
    """Create a graph whose state and results survive restarts.

    Workflow checkpoints (LangGraph) and the relational tables
    (``TriageDatabase``) share one SQLite file. Returns
    ``(graph, db, close)``; call ``close()`` when finished.
    """

    from langgraph.checkpoint.sqlite import SqliteSaver

    db = TriageDatabase(db_path)

    connection = sqlite3.connect(str(db_path), check_same_thread=False)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")

    checkpointer = SqliteSaver(connection, serde=serializer)

    graph = build_graph(checkpointer=checkpointer, db=db)

    def close():
        connection.close()
        db.close()

    return graph, db, close


# Default in-memory graph (no files are created on import)
triage_graph = build_graph(
    checkpointer=InMemorySaver(serde=serializer)
)
