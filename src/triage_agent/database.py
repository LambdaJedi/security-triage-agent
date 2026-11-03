"""SQLite persistence for triage results, approvals, and the audit trail.

Design notes
------------
* Standard library ``sqlite3`` only, so no new dependency.
* Every query is parameterised. No SQL is built by string formatting
  with user or model supplied values.
* Foreign keys are enforced and child rows cascade on delete, so a
  retention purge cannot leave orphaned rows behind.
* ``CHECK`` constraints reject invalid severities, confidences and
  decisions even if application code is bypassed.
* Free text is redacted (see ``privacy.py``) before it is written. Only a
  SHA-256 fingerprint of the original finding is kept for duplicate
  detection.
* The audit log is append-only: a trigger rejects any UPDATE. Rows only
  leave the table through the documented retention purge.
* The schema is versioned with ``PRAGMA user_version`` so later changes
  can be added as numbered migrations.
"""

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from src.triage_agent.privacy import fingerprint, redact, redact_structure


SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
DECISIONS = ("approve", "reject")

# Each entry upgrades the database by one version. Never edit an
# existing migration after release; append a new one instead.
MIGRATIONS: list[str] = [
    # --- version 1 -------------------------------------------------
    """
    CREATE TABLE findings (
        id                INTEGER PRIMARY KEY,
        thread_id         TEXT,
        fingerprint       TEXT NOT NULL,
        finding_redacted  TEXT NOT NULL,
        redaction_summary TEXT NOT NULL DEFAULT '{}',
        created_at        TEXT NOT NULL
    );
    CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
    CREATE INDEX idx_findings_created_at  ON findings(created_at);
    CREATE INDEX idx_findings_thread_id   ON findings(thread_id);

    CREATE TABLE assessments (
        id                INTEGER PRIMARY KEY,
        finding_id        INTEGER NOT NULL
                          REFERENCES findings(id) ON DELETE CASCADE,
        title             TEXT NOT NULL,
        vulnerability_type TEXT NOT NULL,
        cwe               TEXT,
        severity          TEXT NOT NULL
                          CHECK (severity IN
                            ('Critical','High','Medium','Low','Informational')),
        confidence        REAL NOT NULL
                          CHECK (confidence BETWEEN 0.0 AND 1.0),
        assessment_json   TEXT NOT NULL,
        created_at        TEXT NOT NULL
    );
    CREATE INDEX idx_assessments_finding_id ON assessments(finding_id);
    CREATE INDEX idx_assessments_cwe        ON assessments(cwe);
    CREATE INDEX idx_assessments_severity   ON assessments(severity);

    CREATE TABLE tool_calls (
        id             INTEGER PRIMARY KEY,
        assessment_id  INTEGER NOT NULL
                       REFERENCES assessments(id) ON DELETE CASCADE,
        tool           TEXT NOT NULL,
        arguments_json TEXT NOT NULL,
        created_at     TEXT NOT NULL
    );
    CREATE INDEX idx_tool_calls_assessment_id ON tool_calls(assessment_id);

    CREATE TABLE validation_results (
        id             INTEGER PRIMARY KEY,
        finding_id     INTEGER NOT NULL
                       REFERENCES findings(id) ON DELETE CASCADE,
        assessment_id  INTEGER
                       REFERENCES assessments(id) ON DELETE CASCADE,
        passed         INTEGER NOT NULL CHECK (passed IN (0, 1)),
        created_at     TEXT NOT NULL
    );
    CREATE INDEX idx_validation_results_finding_id
        ON validation_results(finding_id);

    CREATE TABLE validation_errors (
        id                    INTEGER PRIMARY KEY,
        validation_result_id  INTEGER NOT NULL
                              REFERENCES validation_results(id)
                              ON DELETE CASCADE,
        message               TEXT NOT NULL
    );
    CREATE INDEX idx_validation_errors_result_id
        ON validation_errors(validation_result_id);

    CREATE TABLE approvals (
        id             INTEGER PRIMARY KEY,
        assessment_id  INTEGER NOT NULL UNIQUE
                       REFERENCES assessments(id) ON DELETE CASCADE,
        decision       TEXT NOT NULL CHECK (decision IN ('approve','reject')),
        message        TEXT,
        decided_at     TEXT NOT NULL
    );

    CREATE TABLE audit_log (
        id             INTEGER PRIMARY KEY,
        ts             TEXT NOT NULL,
        event          TEXT NOT NULL,
        finding_id     INTEGER,
        assessment_id  INTEGER,
        detail         TEXT
    );
    CREATE INDEX idx_audit_log_ts ON audit_log(ts);

    CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END;
    """,
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TriageDatabase:
    """Thin repository around a SQLite file (or ``:memory:``)."""

    def __init__(
        self,
        path: str | Path = ":memory:",
        clock: Callable[[], datetime] = _utc_now,
    ):
        self.path = str(path)
        self._clock = clock
        self._lock = threading.RLock()

        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        # LangGraph may run nodes on worker threads, so the connection
        # is shared and every write is serialised with a lock.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")

        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")

        self._migrate()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    @property
    def schema_version(self) -> int:
        return self._conn.execute("PRAGMA user_version").fetchone()[0]

    def _migrate(self) -> None:
        with self._lock:
            current = self.schema_version

            for version, script in enumerate(MIGRATIONS, start=1):

                if version <= current:
                    continue

                # executescript commits first, so run each migration and
                # its version bump together inside an explicit transaction.
                try:
                    self._conn.executescript(
                        "BEGIN;\n"
                        f"{script}\n"
                        f"PRAGMA user_version = {version};\n"
                        "COMMIT;"
                    )
                except sqlite3.Error:
                    # Leave the database at its previous version.
                    if self._conn.in_transaction:
                        self._conn.rollback()
                    raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "TriageDatabase":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def _now(self) -> str:
        return _iso(self._clock())

    def _audit(
        self,
        event: str,
        finding_id: int | None = None,
        assessment_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        """Insert an audit row. Call inside an open transaction."""

        safe_detail = redact(detail)[0] if detail else None

        self._conn.execute(
            "INSERT INTO audit_log (ts, event, finding_id, assessment_id, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (self._now(), event, finding_id, assessment_id, safe_detail),
        )

    def log_event(
        self,
        event: str,
        finding_id: int | None = None,
        assessment_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._audit(event, finding_id, assessment_id, detail)

    def add_finding(self, text: str, thread_id: str | None = None) -> int:
        """Store a redacted copy of a submitted finding."""

        redacted, counts = redact(text)

        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO findings "
                "(thread_id, fingerprint, finding_redacted, "
                " redaction_summary, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    thread_id,
                    fingerprint(text),
                    redacted,
                    json.dumps(counts, sort_keys=True),
                    self._now(),
                ),
            )
            finding_id = cursor.lastrowid

            self._audit(
                "finding_received",
                finding_id=finding_id,
                detail=f"redactions={json.dumps(counts, sort_keys=True)}",
            )

        return finding_id

    def add_assessment(
        self,
        finding_id: int,
        assessment: Any,
        tool_calls: Iterable[dict[str, Any]] = (),
    ) -> int:
        """Store an assessment (Pydantic model or dict) and its tool calls."""

        data = (
            assessment.model_dump()
            if hasattr(assessment, "model_dump")
            else dict(assessment)
        )

        # Redact every string value, then fill the typed columns from the
        # redacted copy so the columns and the JSON can never disagree.
        safe = redact_structure(data)
        redacted_json = json.dumps(safe, sort_keys=True)

        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO assessments "
                "(finding_id, title, vulnerability_type, cwe, severity, "
                " confidence, assessment_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    safe["title"],
                    safe["vulnerability_type"],
                    safe.get("cwe"),
                    safe["severity"],
                    safe["confidence"],
                    redacted_json,
                    self._now(),
                ),
            )
            assessment_id = cursor.lastrowid

            for call in tool_calls:
                args_json = json.dumps(
                    redact_structure(call.get("arguments", {})),
                    sort_keys=True,
                    default=str,
                )
                self._conn.execute(
                    "INSERT INTO tool_calls "
                    "(assessment_id, tool, arguments_json, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (assessment_id, str(call.get("tool", "unknown")),
                     args_json, self._now()),
                )

            self._audit(
                "assessment_created",
                finding_id=finding_id,
                assessment_id=assessment_id,
                detail=f"severity={safe['severity']} cwe={safe.get('cwe')}",
            )

        return assessment_id

    def add_validation_result(
        self,
        finding_id: int,
        assessment_id: int | None,
        errors: Iterable[str],
    ) -> int:
        errors = list(errors)

        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO validation_results "
                "(finding_id, assessment_id, passed, created_at) "
                "VALUES (?, ?, ?, ?)",
                (finding_id, assessment_id, 0 if errors else 1, self._now()),
            )
            result_id = cursor.lastrowid

            self._conn.executemany(
                "INSERT INTO validation_errors (validation_result_id, message) "
                "VALUES (?, ?)",
                [(result_id, redact(message)[0]) for message in errors],
            )

            self._audit(
                "validation_failed" if errors else "validation_passed",
                finding_id=finding_id,
                assessment_id=assessment_id,
                detail=f"errors={len(errors)}",
            )

        return result_id

    def add_approval(
        self,
        assessment_id: int,
        decision: str,
        message: str | None = None,
    ) -> int:
        """Record the human decision. One decision per assessment."""

        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")

        with self._lock, self._conn:
            finding_id = self._conn.execute(
                "SELECT finding_id FROM assessments WHERE id = ?",
                (assessment_id,),
            ).fetchone()

            cursor = self._conn.execute(
                "INSERT INTO approvals "
                "(assessment_id, decision, message, decided_at) "
                "VALUES (?, ?, ?, ?)",
                (assessment_id, decision, message, self._now()),
            )

            self._audit(
                f"assessment_{'approved' if decision == 'approve' else 'rejected'}",
                finding_id=finding_id["finding_id"] if finding_id else None,
                assessment_id=assessment_id,
            )

        return cursor.lastrowid

    # ------------------------------------------------------------------
    # Reads and reporting
    # ------------------------------------------------------------------

    def _rows(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, params)]

    def get_assessment(self, assessment_id: int) -> dict[str, Any] | None:
        rows = self._rows(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        )

        if not rows:
            return None

        row = rows[0]
        row["assessment"] = json.loads(row.pop("assessment_json"))

        return row

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Assessments that passed validation and still await a decision."""

        return self._rows(
            """
            SELECT a.id AS assessment_id, a.title, a.cwe, a.severity,
                   a.confidence, a.created_at
            FROM assessments AS a
            JOIN validation_results AS v
                 ON v.assessment_id = a.id AND v.passed = 1
            LEFT JOIN approvals AS ap ON ap.assessment_id = a.id
            WHERE ap.id IS NULL
            ORDER BY a.created_at
            """
        )

    def approval_summary_by_severity(self) -> list[dict[str, Any]]:
        """Counts and approval rate for each severity level."""

        return self._rows(
            """
            SELECT a.severity,
                   COUNT(*)                                     AS assessed,
                   COALESCE(SUM(ap.decision = 'approve'), 0)    AS approved,
                   COALESCE(SUM(ap.decision = 'reject'), 0)     AS rejected,
                   COALESCE(SUM(ap.id IS NULL), 0)              AS undecided,
                   ROUND(
                       1.0 * SUM(ap.decision = 'approve')
                       / NULLIF(COUNT(ap.id), 0), 2
                   )                                            AS approval_rate
            FROM assessments AS a
            LEFT JOIN approvals AS ap ON ap.assessment_id = a.id
            GROUP BY a.severity
            ORDER BY CASE a.severity
                        WHEN 'Critical'      THEN 1
                        WHEN 'High'          THEN 2
                        WHEN 'Medium'        THEN 3
                        WHEN 'Low'           THEN 4
                        WHEN 'Informational' THEN 5
                     END
            """
        )

    def cwe_breakdown(self) -> list[dict[str, Any]]:
        """How often each CWE is assigned and how reviewers responded."""

        return self._rows(
            """
            SELECT COALESCE(a.cwe, 'Undetermined')   AS cwe,
                   COUNT(*)                          AS assessed,
                   ROUND(AVG(a.confidence), 2)       AS avg_confidence,
                   COALESCE(SUM(ap.decision = 'approve'), 0) AS approved,
                   COALESCE(SUM(ap.decision = 'reject'), 0)  AS rejected
            FROM assessments AS a
            LEFT JOIN approvals AS ap ON ap.assessment_id = a.id
            GROUP BY COALESCE(a.cwe, 'Undetermined')
            ORDER BY assessed DESC, cwe
            """
        )

    def top_validation_errors(self, limit: int = 5) -> list[dict[str, Any]]:
        """Most frequent deterministic-validation failures."""

        return self._rows(
            """
            SELECT message, COUNT(*) AS occurrences
            FROM validation_errors
            GROUP BY message
            ORDER BY occurrences DESC, message
            LIMIT ?
            """,
            (limit,),
        )

    def audit_trail(self, finding_id: int) -> list[dict[str, Any]]:
        """Everything that happened to one finding, oldest first."""

        return self._rows(
            "SELECT ts, event, assessment_id, detail FROM audit_log "
            "WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        )

    def duplicate_findings(self) -> list[dict[str, Any]]:
        """Findings submitted more than once (same fingerprint)."""

        return self._rows(
            """
            SELECT fingerprint, COUNT(*) AS submissions,
                   MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
            FROM findings
            GROUP BY fingerprint
            HAVING COUNT(*) > 1
            ORDER BY submissions DESC
            """
        )

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def purge_older_than(self, days: int) -> dict[str, int]:
        """Delete findings (and everything linked to them) older than ``days``.

        Child rows go with them through ``ON DELETE CASCADE``. Audit rows
        older than the cutoff are removed as well, then the purge itself is
        recorded so there is always evidence that data was deleted.
        """

        if days < 0:
            raise ValueError("days must be zero or greater")

        cutoff = _iso(self._clock() - timedelta(days=days))

        with self._lock, self._conn:
            findings = self._conn.execute(
                "DELETE FROM findings WHERE created_at < ?", (cutoff,)
            ).rowcount

            audit = self._conn.execute(
                "DELETE FROM audit_log WHERE ts < ?", (cutoff,)
            ).rowcount

            self._audit(
                "retention_purge",
                detail=f"cutoff={cutoff} findings={findings} audit_rows={audit}",
            )

        return {"findings": findings, "audit_rows": audit}
