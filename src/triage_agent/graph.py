
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.types import interrupt

from src.triage_agent.state import TriageState
from src.triage_agent.agent import analyse_finding
from src.triage_agent.retrieval import search_reports
from src.triage_agent.approval import process_approval
from src.triage_agent.validation import validate_assessment


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


# Build the graph
workflow = StateGraph(TriageState)

workflow.add_node("retrieve", retrieve_node)
workflow.add_node("analyse", analyse_node)
workflow.add_node("validate", validate_node)
workflow.add_node("approval", approval_node)
workflow.add_node("mock_disclosure", mock_disclosure_node)


# Connect the initial workflow
workflow.add_edge(START, "retrieve")
workflow.add_edge("retrieve", "analyse")
workflow.add_edge("analyse", "validate")


# Route based on validation results
workflow.add_conditional_edges(
    "validate",
    route_after_validation,
    {
        "valid": "approval",
        "invalid": END
    }
)


# Route based on the human's decision
workflow.add_conditional_edges(
    "approval",
    route_after_approval,
    {
        "approved": "mock_disclosure",
        "rejected": END
    }
)

workflow.add_edge("mock_disclosure", END)


# Configure checkpoint serialization
serializer = JsonPlusSerializer(
    allowed_msgpack_modules=[
        ("src.triage_agent.schemas", "VulnerabilityAssessment")
    ]
)


# Initialise checkpoint storage
memory = InMemorySaver(
    serde=serializer
)


# Compile the workflow
triage_graph = workflow.compile(
    checkpointer=memory
)
