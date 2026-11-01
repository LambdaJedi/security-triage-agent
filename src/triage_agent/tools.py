
from langchain_core.tools import tool


# Starter CWE reference database
CWE_DATABASE = {
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command",
        "category": "SQL Injection",
        "description": (
            "The application constructs SQL commands using "
            "externally influenced input without properly "
            "neutralizing special elements."
        ),
        "mitigation": (
            "Use parameterized queries or prepared statements. "
            "Avoid building SQL queries through string concatenation."
        )
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation",
        "category": "Cross-Site Scripting (XSS)",
        "description": (
            "The application does not properly neutralize "
            "user-controlled input before including it in web pages."
        ),
        "mitigation": (
            "Apply context-aware output encoding and use safe "
            "templating practices."
        )
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory",
        "category": "Path Traversal",
        "description": (
            "The application uses external input to construct a "
            "pathname without adequately restricting the resulting path."
        ),
        "mitigation": (
            "Canonicalize paths and verify that resolved paths "
            "remain within the intended directory."
        )
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "category": "Authentication",
        "description": (
            "The application does not sufficiently prove that "
            "a user or entity is who it claims to be."
        ),
        "mitigation": (
            "Implement secure authentication mechanisms and "
            "validate authentication credentials correctly."
        )
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "category": "Cross-Site Request Forgery",
        "description": (
            "A web application does not sufficiently verify that "
            "a request was intentionally submitted by the user."
        ),
        "mitigation": (
            "Use anti-CSRF tokens and appropriate request-origin "
            "validation."
        )
    }
}


@tool
def lookup_cwe(cwe_id: str) -> str:
    """
    Look up a CWE identifier in the local CWE reference database.

    Example input: CWE-89
    """

    cwe_id = cwe_id.strip().upper()

    cwe = CWE_DATABASE.get(cwe_id)

    if cwe is None:
        return (
            f"{cwe_id} was not found in the local CWE reference database. "
            "Do not assume that the identifier is invalid. "
            "The local database currently contains only a small subset "
            "of CWE entries."
        )

    return (
        f"CWE ID: {cwe_id}\n"
        f"Name: {cwe['name']}\n"
        f"Category: {cwe['category']}\n"
        f"Description: {cwe['description']}\n"
        f"Mitigation: {cwe['mitigation']}"
    )


@tool
def assess_severity(impact: int, exploitability: int) -> str:
    """
    Calculate a preliminary severity using a deterministic scoring matrix.

    Both inputs must be integers from 1 to 4.

    Impact:
    1 = Negligible
    2 = Limited
    3 = Significant
    4 = Severe

    Exploitability:
    1 = Difficult
    2 = Requires specific conditions
    3 = Practical
    4 = Easily exploitable

    The score is the sum of impact and exploitability.
    """

    if not 1 <= impact <= 4:
        return "Invalid impact. Provide an integer from 1 to 4."

    if not 1 <= exploitability <= 4:
        return "Invalid exploitability. Provide an integer from 1 to 4."

    score = impact + exploitability

    if score >= 7:
        severity = "Critical"
    elif score >= 5:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    else:
        severity = "Low"

    return (
        f"Impact: {impact}/4\n"
        f"Exploitability: {exploitability}/4\n"
        f"Combined score: {score}/8\n"
        f"Preliminary severity: {severity}\n"
        "Note: This is a preliminary project-specific scoring matrix, "
        "not an official CVSS calculation."
    )
