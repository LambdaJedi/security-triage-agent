"""Print SQL summaries from a triage database.

Usage:
    python -m src.triage_agent.report data/triage.sqlite3
    python -m src.triage_agent.report data/triage.sqlite3 --purge-days 90
"""

import argparse

from src.triage_agent.database import TriageDatabase


def _table(title: str, rows: list[dict]) -> None:
    print(f"\n{title}")
    print("-" * len(title))

    if not rows:
        print("(no data)")
        return

    headers = list(rows[0])
    cells = [[str(row[h]) if row[h] is not None else "-" for h in headers] for row in rows]
    widths = [max(len(h), *(len(line[i]) for line in cells)) for i, h in enumerate(headers)]

    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    for line in cells:
        print("  ".join(value.ljust(w) for value, w in zip(line, widths)))


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage database report")
    parser.add_argument("database", help="Path to the SQLite database file")
    parser.add_argument(
        "--purge-days",
        type=int,
        help="Delete findings and linked records older than this many days",
    )
    args = parser.parse_args()

    with TriageDatabase(args.database) as db:

        if args.purge_days is not None:
            result = db.purge_older_than(args.purge_days)
            print(f"Purged {result['findings']} findings and {result['audit_rows']} audit rows.")

        _table("Approval summary by severity", db.approval_summary_by_severity())
        _table("CWE breakdown", db.cwe_breakdown())
        _table("Awaiting human approval", db.pending_approvals())
        _table("Most common validation failures", db.top_validation_errors())
        _table("Duplicate submissions", db.duplicate_findings())


if __name__ == "__main__":
    main()
