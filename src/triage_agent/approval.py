
from typing import Literal


ApprovalDecision = Literal["approve", "reject"]


def process_approval(
    decision: ApprovalDecision
) -> dict:
    """
    Process the human approval decision.

    The workflow can only proceed with a mock disclosure
    when the human explicitly approves the assessment.
    """

    if decision == "approve":
        return {
            "approved": True,
            "approval_message": (
                "Assessment approved. "
                "The workflow may proceed to mock disclosure."
            )
        }

    if decision == "reject":
        return {
            "approved": False,
            "approval_message": (
                "Assessment rejected. "
                "The mock disclosure process must stop."
            )
        }

    raise ValueError(
        "Invalid approval decision. "
        "Choose 'approve' or 'reject'."
    )
