
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, ToolMessage

from src.triage_agent.schemas import VulnerabilityAssessment
from src.triage_agent.retrieval import search_reports
from src.triage_agent.tools import lookup_cwe, assess_severity
from src.triage_agent.validation import identify_supported_cwe


# Initialise our local reasoning model
llm = ChatOllama(
    model="qwen2.5:7b",
    base_url="http://localhost:11434",
    temperature=0,
    timeout=300,
)


# Give Qwen access to both security tools
llm_with_tools = llm.bind_tools([
    lookup_cwe,
    assess_severity,
])


# Create a structured-output model
structured_llm = llm.with_structured_output(
    VulnerabilityAssessment,
    method="json_schema",
)


# Define the final analysis prompt
prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are a cybersecurity vulnerability triage assistant.

        Analyse security findings using submitted evidence,
        retrieved historical reports, and tool reference information.

        Your priority is accurate, evidence-based vulnerability triage.
        Correctly identifying when a vulnerability is NOT established
        is just as important as identifying a real vulnerability.

        CWE CLASSIFICATION RULES:

        - Identify a CWE only when the submitted finding supports
          a specific technical weakness.
        - Do not force a CWE classification.
        - Return null for cwe when the evidence is insufficient,
          ambiguous, contradictory, or does not establish a weakness.
        - Return null when the finding only expresses suspicion
          without supporting technical evidence.
        - Return null when the finding describes a protective
          implementation and provides no evidence of a vulnerability.
        - Do not classify an unexpected response as a vulnerability
          without evidence of a security weakness.
        - Do not assume that every finding must represent a valid
          vulnerability.
        - Do not choose a CWE simply because a keyword appears
          in the finding.
        - Classify the underlying technical weakness, not merely
          the possible consequences.
        - Distinguish SQL injection, OS command injection,
          path traversal, authentication failures, and
          authorization failures.
        - Do not classify file path manipulation as OS command
          injection unless command execution is implicated.
        - A CWE lookup result is reference information.
          It does not prove that the current finding matches
          that weakness.
        - Never invent a CWE identifier.

        IMPORTANT CWE CLASSIFICATION DISTINCTION:

        - Do not require successful exploitation to assign a CWE.
        - A clearly described insecure implementation or technical
          weakness can support a preliminary CWE classification
          even when exploitation has not been demonstrated.
        - Distinguish identifying a vulnerability from proving
          its exploitability or impact.
        - Direct insertion of user input into SQL queries without
          parameterization supports CWE-89.
        - Do not let missing exploitation evidence alone cause
          an otherwise supported CWE classification to become null.
        - Explain why the CWE was selected or withheld.

        EVIDENCE RULES:

        - The evidence field must contain only directly stated
          technical facts from the current submitted finding.
        - Evidence must describe an observed condition, behaviour,
          configuration, or test result.
        - Do not include hypothetical attack scenarios in evidence.
        - Do not include speculative language such as may, might,
          could, potentially, or possibly.
        - Never include historical reports or CWE descriptions
          in the evidence field.
        - Never invent evidence or testing results.
        - Do not convert assumptions into confirmed facts.
        - Historical reports provide context, not proof.
        - Do not claim successful exploitation unless the
          submitted finding demonstrates it.
        - Include relevant protective controls or contradictory
          technical facts when explicitly stated.

        RETRIEVED CONTEXT RULES:

        - The retrieved_context field must contain relevant
          information obtained from historical reports.
        - Keep historical information separate from current evidence.
        - Historical similarities do not independently confirm
          the current finding.
        - If no relevant historical reports were retrieved,
          return an empty list.

        IMPACT RULES:

        - Separate potential impact from verified impact.
        - potential_impact describes what an attacker could
          potentially achieve if the vulnerability is exploitable.
        - verified_impact describes only what the current
          submitted finding actually demonstrates.
        - If no impact has been demonstrated, explicitly state that.
        - Do not convert a possible consequence into a confirmed result.
        - If the finding explicitly demonstrates unauthorised
          access, data disclosure, or another security outcome,
          acknowledge that outcome in verified_impact.
        - Distinguish a demonstrated outcome from independently
          reproducing or verifying that outcome.

        LIMITATION RULES:

        - Record missing evidence and unverified assumptions.
        - Identify testing or validation that would strengthen
          the finding.
        - Do not claim independent reproduction unless evidence
          of reproduction is supplied.

        SEVERITY RULES:

        - Select severity based on available evidence.
        - Distinguish potential impact from demonstrated impact.
        - If no vulnerability is established, use Informational.
        - The severity matrix is a project-specific scoring method,
          not an official CVSS calculation.
        - Explain uncertainty in your reasoning.
        - Do not automatically assign Critical severity merely
          because a vulnerability category can have serious consequences.

        CONFIDENCE RULES:

        - Confidence represents confidence in the overall assessment,
          not proof that exploitation has occurred.
        - Use a decimal between 0.0 and 1.0.
        - Lower confidence when important evidence is missing.
        - Correct abstention can still have high confidence.

        OUTPUT RULES:

        - Return a valid structured assessment.
        - Populate every required field.
        - The cwe field may be null.
        - Use concise, technically accurate explanations.
        - Never use retrieved context to strengthen the evidence field.

        EXAMPLE: POSSIBLE SQL INJECTION

        Submitted finding:
        "The login endpoint accepts user input and directly
        inserts it into SQL queries. An attacker may manipulate
        the query to bypass authentication."

        Correct CWE:
        CWE-89.

        Correct verified impact:
        No successful exploitation or authentication bypass
        has been demonstrated.

        EXAMPLE: INSUFFICIENT EVIDENCE

        Submitted finding:
        "Something seems wrong with the account page. I think
        there might be a security issue, but I have not tested it."

        Correct CWE:
        null.

        EXAMPLE: PROTECTIVE IMPLEMENTATION

        Submitted finding:
        "The login endpoint uses parameterized SQL queries.
        User input is passed separately from the SQL statement.
        No SQL injection was reproduced."

        Correct CWE:
        null.

        EXAMPLE: PATH TRAVERSAL

        Submitted finding:
        "The file download endpoint accepts a filename parameter
        and concatenates it directly into the server upload
        directory path without path validation."

        Correct CWE:
        CWE-22.

        EXAMPLE: DEMONSTRATED UNAUTHORISED ACCESS

        Submitted finding:
        "The API endpoint returns protected account information
        when a request is sent without valid authentication
        credentials."

        Acknowledge the returned protected information in
        verified_impact. Do not force an inaccurate CWE.
        """
    ),
    (
        "human",
        """
        SECURITY FINDING:

        {finding}

        RELEVANT HISTORICAL REPORTS:

        {context}

        CWE REFERENCE INFORMATION:

        {cwe_context}

        PRELIMINARY SEVERITY CALCULATION:

        {severity_context}

        PRESERVED CWE CANDIDATE:

        {cwe_candidate}

        DETERMINISTIC CWE VALIDATION:

        {cwe_validation}

        Produce an evidence-based vulnerability assessment.

        The evidence field must contain only technical facts
        from SECURITY FINDING.

        Keep historical context separate from current evidence.

        Do not require successful exploitation to assign a CWE.

        Do not force a CWE classification.

        If the deterministic validation identifies a supported CWE,
        use that CWE in the assessment.

        If deterministic validation reports insufficient evidence,
        return null for cwe.

        If deterministic validation identifies a different CWE
        from the preserved candidate, do not use the mismatched
        candidate. Use the evidence-supported CWE instead.

        If the finding describes a protective implementation,
        return null for cwe.

        Distinguish potential consequences from demonstrated impact.

        If the finding explicitly describes a successful security
        outcome, acknowledge that outcome in verified_impact.
        """
    ),
])


def analyse_finding(
    finding: str,
    context: list[str] | None = None
) -> dict:
    """
    Analyse a finding using RAG, CWE lookup, severity assessment,
    and structured output.

    Preserves proposed CWE candidates and checks them against
    deterministic technical evidence before finalizing the result.
    """

    # Retrieve historical reports when context was not supplied
    if context is None:
        reports = search_reports(finding, k=3)

        context = [
            report.page_content for report in reports
        ]

    formatted_context = "\n\n".join(context)

    # Ask Qwen to identify a defensible CWE and estimate severity
    tool_request = llm_with_tools.invoke([
        HumanMessage(
            content=f"""
            Analyse the following security finding.

            Determine whether it describes a specific,
            technically supported vulnerability.

            Use lookup_cwe only when a plausible CWE is supported
            by the actual technical weakness.

            Do not force a classification or invent identifiers.

            Do not require successful exploitation to identify
            a clearly described technical weakness.

            Use assess_severity when enough information exists
            for a meaningful preliminary estimate.

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

            Do not invent missing details.

            Finding:
            {finding}
            """
        )
    ])

    # Tool context
    cwe_context = "No CWE lookup information was retrieved."
    severity_context = (
        "No preliminary severity calculation was retrieved."
    )

    # Preserve the candidate separately
    cwe_candidate = None

    # Audit log
    tool_call_log = []

    if tool_request.tool_calls:

        messages = [
            HumanMessage(
                content=(
                    "Analyse the finding and use the available "
                    "security reference tools where appropriate."
                )
            ),
            tool_request,
        ]

        cwe_results = []
        severity_results = []

        for tool_call in tool_request.tool_calls:

            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            if tool_name == "lookup_cwe":

                # Preserve the CWE requested by Qwen
                requested_cwe = tool_args.get("cwe_id")

                if requested_cwe:
                    cwe_candidate = requested_cwe.strip().upper()

                result = lookup_cwe.invoke(tool_args)
                cwe_results.append(str(result))

            elif tool_name == "assess_severity":

                result = assess_severity.invoke(tool_args)
                severity_results.append(str(result))

            else:
                result = f"Unknown tool requested: {tool_name}"

            tool_call_log.append({
                "tool": tool_name,
                "arguments": tool_args,
                "result": str(result),
            })

            messages.append(
                ToolMessage(
                    content=str(result),
                    tool_call_id=tool_call["id"],
                )
            )

        # Allow Qwen to interpret the tool responses
        tool_response = llm_with_tools.invoke(messages)

        if cwe_results:
            cwe_context = (
                "\n\n".join(cwe_results)
                + "\n\nQwen's interpretation:\n"
                + str(tool_response.content)
            )

        if severity_results:
            severity_context = "\n\n".join(severity_results)

    else:
        tool_call_log.append({
            "tool": "none",
            "arguments": {},
            "result": "Qwen did not request any tools.",
        })

    # Deterministically inspect the submitted finding
    supported_cwe = identify_supported_cwe(finding)

    # Decide whether the candidate is supported
    if supported_cwe is None:

        cwe_validation = (
            "Insufficient evidence for a deterministic CWE "
            "classification. The final CWE must be null."
        )

        accepted_cwe = None

    elif cwe_candidate is None:

        cwe_validation = (
            f"The finding supports {supported_cwe}, but Qwen "
            "did not request a CWE lookup. A candidate was "
            "identified by deterministic validation."
        )

        accepted_cwe = supported_cwe

    elif cwe_candidate == supported_cwe:

        cwe_validation = (
            f"The proposed candidate {cwe_candidate} matches "
            "the technical evidence."
        )

        accepted_cwe = supported_cwe

    else:

        cwe_validation = (
            f"The proposed candidate {cwe_candidate} does not "
            f"match the evidence-supported classification "
            f"{supported_cwe}. The proposed candidate is rejected."
        )

        accepted_cwe = supported_cwe

    # Record the deterministic validation
    tool_call_log.append({
        "tool": "validate_cwe",
        "arguments": {
            "proposed_cwe": cwe_candidate,
        },
        "result": cwe_validation,
        "accepted_cwe": accepted_cwe,
    })

    # Prepare final structured assessment
    messages = prompt.format_messages(
        finding=finding,
        context=formatted_context or "No relevant reports found.",
        cwe_context=cwe_context,
        severity_context=severity_context,
        cwe_candidate=cwe_candidate or "None",
        cwe_validation=cwe_validation,
    )

    assessment = structured_llm.invoke(messages)

    # Enforce the deterministic CWE decision.
    # Do not rely on the LLM to reproduce a tool-call result.
    assessment.cwe = accepted_cwe

    return {
        "assessment": assessment,
        "tool_calls": tool_call_log,
        "cwe_candidate": cwe_candidate,
        "validated_cwe": accepted_cwe,
        "cwe_validation": cwe_validation,
    }
