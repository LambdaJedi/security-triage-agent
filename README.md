# Security Triage Agent

A local LLM-powered cybersecurity vulnerability triage agent built with Python and LangGraph.

The system analyses submitted security findings, retrieves relevant historical reports using Retrieval-Augmented Generation (RAG), consults security reference tools, and produces structured vulnerability assessments.

It also applies deterministic validation rules and requires human approval before generating a mock vulnerability disclosure.

## Features

- **Local LLM inference:** Uses Ollama with Qwen 2.5 7B.
- **Retrieval-Augmented Generation:** Uses ChromaDB and `nomic-embed-text` to retrieve relevant historical security reports.
- **Tool calling:** Provides CWE lookup and a preliminary project-specific severity assessment tool.
- **Structured outputs:** Uses Pydantic to enforce a consistent vulnerability assessment schema.
- **Deterministic validation:** Checks evidence, verified impact claims, and CWE classifications independently of the LLM.
- **Human-in-the-loop approval:** Requires an explicit approval decision before proceeding to mock disclosure.
- **Workflow orchestration:** Uses LangGraph to manage the triage process and workflow state.
- **Persistent checkpointing:** Workflow state is stored in SQLite, so a pending human approval survives an application restart. An in-memory graph is still available for quick experiments.
- **SQL data layer:** Findings, assessments, tool calls, validation results, human decisions, and an append-only audit log are stored in a normalised SQLite schema with constraints, indexes, and reporting queries.
- **Privacy by default:** Credentials, tokens, emails, and IP addresses are redacted before anything is written to the relational tables, and a retention purge deletes old data.
- **Evaluation:** Includes a labelled dataset and evaluation script for measuring classification, evidence, and impact performance.

## Architecture

```text
                 Security Finding
                        |
                        v
               Retrieve Historical
                  Reports (RAG)
                        |
                        v
                 LangGraph Agent
                        |
             +----------+----------+
             |                     |
             v                     v
         CWE Lookup          Severity Tool
             |                     |
             +----------+----------+
                        |
                        v
               Structured Assessment
                     (Pydantic)
                        |
                        v
              Deterministic Validation
                        |
                 +------+------+
                 |             |
               Invalid        Valid
                 |             |
                 v             v
                Stop      Human Approval
                               |
                         +-----+-----+
                         |           |
                       Reject      Approve
                         |           |
                         v           v
                        Stop    Mock Disclosure
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.11 | Application development |
| LangGraph | Agent workflow orchestration |
| LangChain | LLM integration and tool calling |
| Ollama | Local model inference |
| Qwen 2.5 7B | Vulnerability analysis |
| ChromaDB | Vector database |
| SQLite | Relational storage, audit log, and workflow checkpoints |
| nomic-embed-text | Text embeddings |
| Pydantic | Structured assessment validation |
| Pytest | Automated testing |

## Project Structure

```text
security-triage-agent/
├── .github/workflows/
│   └── tests.yml             # CI: runs pytest on every push and pull request
├── data/
│   └── reports/              # Local historical security reports (not committed)
├── evaluation/
│   ├── dataset.json          # Labelled evaluation findings
│   └── evaluate.py           # Evaluation runner
├── src/
│   └── triage_agent/
│       ├── agent.py          # LLM reasoning and tool calling
│       ├── approval.py       # Approval decisions
│       ├── database.py       # SQLite schema, repository, reports, retention
│       ├── graph.py          # LangGraph workflow (in-memory or persistent)
│       ├── privacy.py        # Redaction and fingerprinting
│       ├── report.py         # Command-line SQL reports
│       ├── retrieval.py      # RAG and vector search
│       ├── schemas.py        # Pydantic assessment schema
│       ├── state.py          # Workflow state
│       ├── tools.py          # CWE and severity tools
│       └── validation.py     # Deterministic validation
├── tests/
│   ├── test_database.py
│   ├── test_persistent_graph.py
│   ├── test_privacy.py
│   ├── test_schemas.py
│   ├── test_tools.py
│   └── test_validation.py
├── design_decisions.md
├── LICENSE
├── .gitignore
├── pytest.ini
└── requirements.txt
```

## Prerequisites

- Python 3.11
- Git
- Ollama
- Sufficient memory and disk space to run the selected local models

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/LambdaJedi/security-triage-agent.git
cd security-triage-agent
```

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Download the required Ollama models

```powershell
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
```

### 5. Start Ollama

```powershell
ollama serve
```

The application currently connects to Ollama at:

```text
http://localhost:11434
```

The model names and connection address are currently configured directly in the Python source code.

## Running the Tests

Run the automated test suite:

```powershell
python -m pytest tests/ -v
```

## Evaluation

The project includes a labelled evaluation dataset covering different vulnerability scenarios, including:

- SQL injection
- Cross-site scripting
- Path traversal
- Cross-Site Request Forgery
- Authentication weaknesses
- Incomplete and ambiguous findings
- False-positive scenarios
- Demonstrated exploitation

Run the evaluation script:

```powershell
python evaluation\evaluate.py
```

The evaluation script uses the configured local LLM, so Ollama must be running and the required models must be available.

Evaluation results are generated locally and are not committed to the repository.

## Workflow Execution

The LangGraph workflow is defined in `src/triage_agent/graph.py`.

It coordinates the following stages:

1. Retrieve relevant historical reports.
2. Analyse the submitted finding using the local LLM and available tools.
3. Validate the generated assessment.
4. Pause execution for human approval if validation succeeds.
5. Generate a mock disclosure only after approval.

The approval stage uses LangGraph's interrupt mechanism. `triage_graph` checkpoints in memory. For storage that survives restarts, use `create_persistent_graph`, which adds the SQL recording nodes described below:

```python
from langgraph.types import Command
from src.triage_agent.graph import create_persistent_graph

graph, db, close = create_persistent_graph("data/triage.sqlite3")
config = {"configurable": {"thread_id": "case-001"}}

graph.invoke({"finding": "..."}, config)       # runs until the approval gate
# ... the application can exit here and be started again later ...
graph.invoke(Command(resume={"decision": "approve"}), config)

close()
```

## Database

All relational data lives in one SQLite file (`*.sqlite3` is git-ignored). The same file also holds LangGraph's checkpoint tables.

```text
findings 1───* assessments 1───* tool_calls
    │               │
    │               ├───1 approvals            (one human decision per assessment)
    │               │
    └───* validation_results 1───* validation_errors

audit_log   (append-only record of every step)
```

| Table | Purpose |
|---|---|
| `findings` | Redacted finding text, SHA-256 fingerprint, LangGraph `thread_id` |
| `assessments` | Typed columns (CWE, severity, confidence) plus the full redacted assessment as JSON |
| `tool_calls` | Tools the agent ran for each assessment |
| `validation_results` / `validation_errors` | Outcome of deterministic validation, one row per error message |
| `approvals` | The human decision; `UNIQUE (assessment_id)` allows only one |
| `audit_log` | Every lifecycle event; a trigger rejects `UPDATE` |

**Integrity:** foreign keys are enforced with `ON DELETE CASCADE`; `CHECK` constraints restrict severity, confidence (0 to 1), and decision values; indexes cover the columns used for joins and reports; every query is parameterised. The schema is versioned with `PRAGMA user_version` and numbered migrations in `database.py`.

**Reports:**

```powershell
python -m src.triage_agent.report data/triage.sqlite3
```

This prints approval rate by severity (a `LEFT JOIN` with conditional aggregation), a CWE breakdown, assessments awaiting approval, the most common validation failures, and duplicate submissions.

## Privacy and Data Handling

- **Local only:** inference, retrieval, and storage all run on the local machine.
- **Redaction before storage:** `privacy.py` replaces private keys, JWTs, AWS and API keys, bearer tokens, `password=`/`secret=` style values, emails, IPv4 addresses, and phone numbers with `[REDACTED:<TYPE>]` before any text reaches the relational tables, audit log, or tool-call records.
- **No raw text for deduplication:** duplicates are found with a SHA-256 fingerprint of the normalised text.
- **Retention:** `python -m src.triage_agent.report <db> --purge-days 90` deletes older findings and everything linked to them, then records the purge in the audit log.
- **Known gap:** LangGraph checkpoints contain the original, unredacted workflow state while a thread exists. They stay in the local database file, which is git-ignored. To remove a case's checkpoints, call `graph.checkpointer.delete_thread(thread_id)`.
- **Redaction is pattern-based** and conservative, not a guarantee. Treat the database as sensitive and do not use real confidential reports with this prototype.

## AI Assistance

AI tools were used in this project. The SQLite persistence layer (`database.py`, `privacy.py`, `report.py`), the graph changes that record results, and their tests were written with Claude (Anthropic), then reviewed and run by the author. The tests, including a restart-and-resume test, are in `tests/`.

## Design Principles

1. **Evidence over assumptions:** The agent must distinguish demonstrated behaviour from hypothetical impact.
2. **Abstention is valid:** Insufficient evidence should not automatically result in a vulnerability classification.
3. **Separation of responsibilities:** LLM reasoning and deterministic validation are separate stages.
4. **Human oversight:** The workflow cannot proceed to mock disclosure without approval.
5. **Local-first processing:** Model inference and report retrieval are designed to run locally.

## Limitations

- The CWE lookup tool currently uses a curated subset rather than the complete MITRE CWE database.
- The severity assessment uses a preliminary project-specific matrix and is not CVSS.
- Deterministic CWE classification uses pattern-based rules and does not replace expert security review.
- LLM-generated assessments may contain errors and require independent verification.
- The default `triage_graph` uses in-memory checkpointing; use `create_persistent_graph` to keep state across restarts.
- SQLite suits a single-user local tool. Concurrent multi-user use would need a client/server database such as PostgreSQL.
- The mock disclosure workflow does not submit reports to real vulnerability disclosure programs.

## Security Notice

This project is intended for educational, research, and defensive security triage purposes.

All sample findings should be synthetic or appropriately sanitised. Do not add confidential vulnerability reports, credentials, API keys, or private disclosure information to the public repository.

## Author

**Njabulo Ncube**

GitHub: https://github.com/LambdaJedi