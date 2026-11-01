# Design Decisions

## 1. Local-First LLM Inference

**Decision:** Use Ollama to run Qwen 2.5 7B locally.

**Reasoning:** Security findings can contain sensitive technical information. Local inference reduces the need to send submitted findings to external model providers.

**Trade-off:** Local inference requires sufficient hardware resources and can be slower than hosted models.

## 2. LangGraph for Workflow Orchestration

**Decision:** Use LangGraph to coordinate retrieval, analysis, validation, approval, and mock disclosure.

**Reasoning:** A security triage process has distinct stages and conditional transitions. A graph makes these stages and their execution paths explicit.

## 3. Retrieval-Augmented Generation

**Decision:** Use ChromaDB with Ollama embeddings to retrieve relevant historical reports.

**Reasoning:** Historical findings can provide useful reference material during analysis.

**Trade-off:** Retrieved reports may be incomplete or irrelevant. They must not be treated as proof of the current finding.

## 4. Structured Assessment with Pydantic

**Decision:** Use Pydantic to define the vulnerability assessment output.

**Reasoning:** Structured fields make assessments easier to validate, evaluate, inspect, and process programmatically.

## 5. Deterministic Validation

**Decision:** Separate evidence and CWE validation from LLM-generated reasoning.

**Reasoning:** An LLM can produce plausible but unsupported conclusions. Independent validation provides an additional control over evidence attribution and vulnerability classification.

**Trade-off:** Pattern-based validation has limited coverage and may miss valid findings or incorrectly classify ambiguous ones.

## 6. Human-in-the-Loop Approval

**Decision:** Require explicit human approval before generating a mock disclosure.

**Reasoning:** Security reports can have significant consequences. An automated assessment should not independently initiate a disclosure process.

## 7. Preliminary Severity Assessment

**Decision:** Implement a project-specific impact and exploitability scoring matrix.

**Reasoning:** This provides a consistent starting point for preliminary prioritisation.

**Limitation:** The matrix is not CVSS and must not be represented as an official severity standard.

## 8. Evaluation-Driven Development

**Decision:** Maintain a labelled evaluation dataset and automated tests.

**Reasoning:** A security triage agent needs to be evaluated on more than whether it produces valid text. Classification, evidence quality, and impact assessment must also be examined.

**Limitation:** A small synthetic dataset cannot establish real-world detection performance.