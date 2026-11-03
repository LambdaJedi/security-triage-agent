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

## 9. SQLite for Persistence

**Decision:** Store workflow checkpoints and triage records in a local SQLite database, using the standard library `sqlite3` module and `langgraph-checkpoint-sqlite`.

**Reasoning:** The approval step can wait for a human indefinitely, so the paused workflow must survive a restart. SQLite needs no server, keeps all data on the local machine (consistent with decision 1), and supports foreign keys, constraints, and indexes.

**Trade-off:** SQLite is single-writer and suited to one user. A shared deployment would need PostgreSQL or similar.

## 10. Redact Before Storing

**Decision:** Redact credentials and personal data from text before it reaches the relational tables, and keep only a SHA-256 fingerprint for duplicate detection.

**Reasoning:** Security findings often quote tokens, passwords, and internal addresses. Data that is never stored cannot leak from the database.

**Limitation:** Redaction is pattern-based and can miss unusual formats. LangGraph checkpoints still contain the original state until the thread is deleted.

## 11. Append-Only Audit Log

**Decision:** Record each lifecycle event in an `audit_log` table and block `UPDATE` with a trigger.

**Reasoning:** A human-approval workflow needs a trustworthy record of who decided what and when. Retention purges are the only path that removes rows, and each purge is itself logged.

