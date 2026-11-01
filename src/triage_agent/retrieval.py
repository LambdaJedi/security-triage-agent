
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings


# Initialise the local embedding model
embeddings = OllamaEmbeddings(
    model="nomic-embed-text",
    base_url="http://localhost:11434"
)


# Initialise the vector database
vector_store = Chroma(
    collection_name="security_reports",
    embedding_function=embeddings,
    persist_directory="./chroma_db"
)


def load_reports():
    """Load security reports from the reports directory."""

    reports_directory = Path("data/reports")

    documents = []

    for file_path in reports_directory.glob("*.txt"):

        content = file_path.read_text(encoding="utf-8")

        document = Document(
            page_content=content,
            metadata={
                "source": file_path.name
            }
        )

        documents.append(document)

    return documents


def index_reports():
    """Index reports using stable IDs to prevent duplicates."""

    documents = load_reports()

    if not documents:
        print("No security reports found.")
        return

    # Use each filename as its stable document ID
    document_ids = [
        document.metadata["source"]
        for document in documents
    ]

    # Remove existing versions before re-indexing
    vector_store.delete(ids=document_ids)

    vector_store.add_documents(
        documents,
        ids=document_ids
    )

    print(f"Successfully indexed {len(documents)} reports.")


def search_reports(query: str, k: int = 3):
    """Find the most relevant reports for a security finding."""

    results = vector_store.similarity_search(
        query,
        k=k
    )

    return results
