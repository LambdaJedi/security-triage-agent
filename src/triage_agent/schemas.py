
from pydantic import BaseModel, Field
from typing import Literal


class VulnerabilityAssessment(BaseModel):
    title: str = Field(
        description="Short title of the vulnerability. If no vulnerability is established, describe the finding accurately without claiming one exists."
    )

    vulnerability_type: str = Field(
        description="Category of the identified vulnerability. If no vulnerability can be identified, state 'Undetermined'."
    )

    cwe: str | None = Field(
        default=None,
        description=(
            "Relevant CWE identifier, for example CWE-89. "
            "Return null if the available evidence is insufficient "
            "to identify a vulnerability or if the finding does not "
            "establish a vulnerability."
        )
    )

    severity: Literal[
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational"
    ] = Field(
        description="Preliminary severity based on available evidence. Do not assign a vulnerability severity when no vulnerability is established; use Informational."
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence in the overall vulnerability assessment, "
            "between 0.0 and 1.0. This is not proof of exploitation."
        )
    )

    evidence: list[str] = Field(
        description=(
            "Facts explicitly stated or demonstrated in the current "
            "submitted finding only. Never include historical reports, "
            "CWE descriptions, assumptions, or inferred facts."
        )
    )

    retrieved_context: list[str] = Field(
        description=(
            "Relevant information retrieved from historical reports. "
            "Keep this separate from current finding evidence. "
            "Historical reports do not prove the current vulnerability."
        )
    )

    potential_impact: str = Field(
        description=(
            "What an attacker could potentially achieve if the "
            "vulnerability is exploitable. Clearly distinguish "
            "hypothetical consequences from demonstrated impact."
        )
    )

    verified_impact: str = Field(
        description=(
            "Impact actually demonstrated by the current finding. "
            "If no impact has been demonstrated, explicitly state so. "
            "Do not dismiss impact that the submitted evidence directly demonstrates."
        )
    )

    limitations: list[str] = Field(
        description=(
            "Missing information, unverified assumptions, and "
            "additional validation required."
        )
    )

    reasoning: str = Field(
        description=(
            "Explanation supporting the assessment. Distinguish "
            "submitted evidence from retrieved context and assumptions. "
            "Explain why a CWE was selected or why it was left undetermined."
        )
    )

    remediation: str = Field(
        description="Recommended remediation. If no vulnerability is established, recommend further investigation where appropriate."
    )
