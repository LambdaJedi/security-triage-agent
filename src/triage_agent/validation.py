
import re
from typing import Optional

from src.triage_agent.schemas import VulnerabilityAssessment


def normalize_text(text: str) -> str:
    """Normalize text for consistent evidence comparisons."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def contains_speculative_language(text: str) -> bool:
    """Identify language suggesting an unverified claim."""
    speculative_phrases = [
        "might be",
        "may be",
        "could be",
        "possibly",
        "potentially",
        "suspects that",
        "suspect that",
        "seems to",
        "appears to",
        "does not appear to",
        "i think",
        "i believe",
        "not been tested",
        "not been verified",
        "not been demonstrated",
        "no successful test",
        "no successful exploitation",
        "have not tested",
        "have not identified",
    ]

    normalized = normalize_text(text)

    return any(
        phrase in normalized
        for phrase in speculative_phrases
    )


def validate_evidence(
    finding: str,
    assessment: VulnerabilityAssessment,
) -> list[str]:
    """
    Ensure every evidence statement is supported by the
    submitted finding.

    Historical reports and assumptions must not become
    current-finding evidence.
    """
    errors = []
    normalized_finding = normalize_text(finding)

    for item in assessment.evidence:
        normalized_item = normalize_text(item)

        if not normalized_item:
            errors.append("Evidence contains an empty statement.")
            continue

        if normalized_item not in normalized_finding:
            errors.append(
                f"Evidence is not directly supported by the finding: {item}"
            )

        if contains_speculative_language(item):
            errors.append(
                f"Evidence contains speculative language: {item}"
            )

    return errors


def validate_verified_impact(
    finding: str,
    assessment: VulnerabilityAssessment,
) -> list[str]:
    """
    Check that verified impact is supported by the submitted
    finding and is not merely a potential consequence.
    """
    errors = []
    verified = normalize_text(assessment.verified_impact)
    normalized_finding = normalize_text(finding)

    unsupported_claims = [
        "account takeover",
        "remote code execution",
        "database modified",
        "data extracted",
        "administrator privileges obtained",
        "session cookie stolen",
        "authentication bypass confirmed",
        "successfully exploited",
        "successfully exploited the endpoint",
        "attacker successfully exploited",
        "exploitation was successful",
    ]

    negative_indicators = [
        "no successful exploitation",
        "not been demonstrated",
        "not demonstrated",
        "not been verified",
        "no impact has been demonstrated",
        "not established",
        "no successful test",
        "not reproduced",
    ]

    # A statement explicitly saying that impact has not
    # been demonstrated is acceptable.
    if any(
        phrase in verified
        for phrase in negative_indicators
    ):
        return errors

    # Check whether the claimed impact is actually supported.
    for claim in unsupported_claims:
        if claim in verified and claim not in normalized_finding:
            errors.append(
                f"unsupported claim in verified impact: {claim}"
            )

    # Prevent hypothetical impact from being presented as proven.
    if contains_speculative_language(verified):
        errors.append(
            "Verified impact contains speculative language."
        )

    return errors


def identify_supported_cwe(finding: str) -> Optional[str]:
    """
    Deterministically identify a CWE only when the finding
    contains sufficient technical indicators.

    This is a deliberately limited classifier, not a complete
    replacement for MITRE CWE analysis.
    """
    text = normalize_text(finding)

    # ---------------------------------------------------------
    # First: reject explicit protective or insufficient evidence
    # ---------------------------------------------------------

    protective_sql_patterns = [
        r"uses parameterized sql",
        r"uses parameterized quer(?:y|ies)",
        r"passed separately from the sql statement",
        r"does not concatenate user.controlled input",
        r"no sql injection was reproduced",
    ]

    if any(
        re.search(pattern, text)
        for pattern in protective_sql_patterns
    ):
        return None

    insufficient_patterns = [
        r"no payload",
        r"no request",
        r"no response",
        r"have not tested",
        r"have not identified",
        r"no technical evidence",
    ]

    if any(
        re.search(pattern, text)
        for pattern in insufficient_patterns
    ):
        # Do not classify a merely suspected vulnerability.
        if (
            "suspect" in text
            or "suspects" in text
            or "might contain" in text
            or "may contain" in text
            or "could contain" in text
        ):
            return None

    # ---------------------------------------------------------
    # CWE-89: SQL Injection
    # ---------------------------------------------------------

    has_sql = bool(
        re.search(
            r"\b(sql quer(?:y|ies)|sql statements?|"
            r"database quer(?:y|ies)|sql commands?)\b",
            text,
        )
    )

    has_user_input = bool(
        re.search(
            r"\b(user input|user-provided|user controlled|"
            r"user-controlled input|input parameter|"
            r"filename parameter)\b",
            text,
        )
    )

    has_unsafe_sql = bool(
        re.search(
            r"\b(directly inserts?|direct insertion|"
            r"concatenates?|concatenated|"
            r"without parameterized statements|"
            r"without parameterization|"
            r"prepared statements are not used|"
            r"directly incorporates?)\b",
            text,
        )
    )

    has_demonstrated_sql_exploitation = bool(
        re.search(r"\bsql payload\b", text)
        and re.search(r"\blogin endpoint\b", text)
        and re.search(
            r"\b(authenticated administrator session|"
            r"authentication bypass|"
            r"authenticated admin session)\b",
            text,
        )
    )

    if (
        has_sql
        and has_user_input
        and has_unsafe_sql
    ) or has_demonstrated_sql_exploitation:
        return "CWE-89"

    # ---------------------------------------------------------
    # CWE-79: Cross-Site Scripting
    # ---------------------------------------------------------

    has_profile_content = bool(
        re.search(
            r"\b(profile descriptions?|"
            r"user.provided content|"
            r"user.generated content|"
            r"user input)\b",
            text,
        )
    )

    has_html_output = bool(
        re.search(
            r"\b(displays?|displayed|renders?|rendered|"
            r"html|browser|web page)\b",
            text,
        )
    )

    has_missing_output_encoding = bool(
        re.search(
            r"\b(without html escaping|"
            r"without escaping|"
            r"not escaped|"
            r"unescaped|"
            r"without output encoding|"
            r"missing output encoding|"
            r"unsanitized|"
            r"not sanitized)\b",
            text,
        )
    )

    has_script_evidence = bool(
        re.search(
            r"\b(script element|script tag|javascript payload|"
            r"script entered)\b",
            text,
        )
    )

    if (
        has_profile_content
        and has_html_output
        and has_missing_output_encoding
    ) or (
        has_profile_content
        and has_script_evidence
        and has_html_output
        and has_missing_output_encoding
    ):
        return "CWE-79"

    # ---------------------------------------------------------
    # CWE-22: Path Traversal
    # ---------------------------------------------------------

    has_filename_or_path = bool(
        re.search(
            r"\b(filename parameter|filename|file path|"
            r"directory path|path parameter)\b",
            text,
        )
    )

    has_file_operation = bool(
        re.search(
            r"\b(file download|file upload|file access|"
            r"file read|file write|server upload directory|"
            r"download endpoint|upload directory)\b",
            text,
        )
    )

    has_unsafe_path_handling = bool(
        re.search(
            r"\b(concatenates?|concatenated|"
            r"directly appends?|"
            r"without path validation|"
            r"does not validate|"
            r"does not normalise|"
            r"does not normalize|"
            r"without normalisation|"
            r"without normalization|"
            r"does not canonicalize|"
            r"does not canonicalise)\b",
            text,
        )
    )

    if (
        has_filename_or_path
        and has_file_operation
        and has_unsafe_path_handling
    ):
        return "CWE-22"

    # ---------------------------------------------------------
    # CWE-352: Cross-Site Request Forgery
    # ---------------------------------------------------------

    has_state_changing_action = bool(
        re.search(
            r"\b(account settings|"
            r"change the user's email|"
            r"changes the user's email|"
            r"change email address|"
            r"update account|"
            r"account details)\b",
            text,
        )
    )

    has_request_method = bool(
        re.search(
            r"\b(post requests?|http post|"
            r"state.changing request|"
            r"changes? the user's email address)\b",
            text,
        )
    )

    has_missing_csrf_protection = bool(
        re.search(
            r"\b(no anti.csrf token|"
            r"missing anti.csrf token|"
            r"without anti.csrf token|"
            r"no csrf token|"
            r"without csrf protection|"
            r"missing csrf protection|"
            r"does not include an anti.csrf token|"
            r"no request verification)\b",
            text,
        )
    )

    if (
        has_state_changing_action
        and has_request_method
        and has_missing_csrf_protection
    ):
        return "CWE-352"

    # ---------------------------------------------------------
    # CWE-306: Missing Authentication for Critical Function
    # ---------------------------------------------------------

    has_protected_resource = bool(
        re.search(
            r"\b(protected account information|"
            r"protected account data|"
            r"account owner's email|"
            r"account owner email|"
            r"protected information|"
            r"account details)\b",
            text,
        )
    )

    has_missing_authentication = bool(
        re.search(
            r"\b(without valid authentication credentials|"
            r"without authentication credentials|"
            r"without valid credentials|"
            r"does not enforce authentication|"
            r"no authentication required|"
            r"without authentication|"
            r"missing authentication)\b",
            text,
        )
    )

    if (
        has_protected_resource
        and has_missing_authentication
    ):
        return "CWE-306"

    # ---------------------------------------------------------
    # CWE-287: Improper Authentication
    # ---------------------------------------------------------

    explicit_authentication_failure = bool(
        re.search(
            r"\b(invalid credentials are accepted|"
            r"accepts invalid credentials|"
            r"credentials are not validated|"
            r"authentication validation is bypassed|"
            r"authentication check can be bypassed|"
            r"incorrect credentials are accepted)\b",
            text,
        )
    )

    if explicit_authentication_failure:
        return "CWE-287"

    # ---------------------------------------------------------
    # No sufficiently supported classification
    # ---------------------------------------------------------

    return None


def validate_cwe(
    finding: str,
    assessment: VulnerabilityAssessment,
) -> list[str]:
    """
    Validate the model's proposed CWE against deterministic
    classification of the submitted finding.
    """
    errors = []

    proposed_cwe = assessment.cwe

    # Abstention is allowed when evidence is insufficient.
    if proposed_cwe is None:
        return errors

    proposed_cwe = proposed_cwe.strip().upper()

    supported_cwe = identify_supported_cwe(finding)

    if supported_cwe is None:
        errors.append(
            "insufficient evidence to validate the proposed CWE: "
            f"{proposed_cwe}"
        )

    elif proposed_cwe != supported_cwe:
        errors.append(
            f"proposed CWE {proposed_cwe} does not match "
            f"the supported CWE {supported_cwe}."
        )

    return errors


def validate_assessment(
    finding: str,
    assessment: VulnerabilityAssessment,
) -> list[str]:
    """
    Run all assessment validation checks.
    """
    errors = []

    errors.extend(
        validate_evidence(finding, assessment)
    )

    errors.extend(
        validate_verified_impact(finding, assessment)
    )

    errors.extend(
        validate_cwe(finding, assessment)
    )

    return errors
