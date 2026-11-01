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
- **Checkpointing:** Uses LangGraph's in-memory checkpointing to preserve workflow state during execution.
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
| nomic-embed-text | Text embeddings |
| Pydantic | Structured assessment validation |
| Pytest | Automated testing |

## Project Structure

```text
triage-agent/
├── data/
│   ├── reports/              # Local historical security reports
│   ├── cwe/
│   └── owasp/
├── evaluation/
│   ├── dataset.json          # Labelled evaluation findings
│   └── evaluate.py           # Evaluation runner
├── src/
│   └── triage_agent/
│       ├── agent.py          # LLM reasoning and tool calling
│       ├── approval.py       # Approval decisions
│       ├── graph.py          # LangGraph workflow
│       ├── memory.py         # Memory functionality
│       ├── retrieval.py      # RAG and vector search
│       ├── schemas.py        # Pydantic assessment schema
│       ├── state.py          # Workflow state
│       ├── tools.py          # CWE and severity tools
│       └── validation.py     # Deterministic validation
├── tests/
│   ├── test_schemas.py
│   ├── test_tools.py
│   └── test_validation.py
├── .env.example
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

The approval stage uses LangGraph's interrupt mechanism. Workflow state is checkpointed using `InMemorySaver`, which provides in-memory checkpointing rather than persistent storage across application restarts.

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
- In-memory checkpointing does not preserve workflow state across application restarts.
- The mock disclosure workflow does not submit reports to real vulnerability disclosure programs.

## Security Notice

This project is intended for educational, research, and defensive security triage purposes.

All sample findings should be synthetic or appropriately sanitised. Do not add confidential vulnerability reports, credentials, API keys, or private disclosure information to the public repository.

## Author

**Njabulo Ncube**

GitHub: https://github.com/LambdaJedi