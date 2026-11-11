"""Review history: every review run from the web UI is saved in a small SQLite database.

SQLite ships with Python, so the history needs no extra service. The database path comes
from the ``CONFIG_REVIEWER_DB`` environment variable (the Docker image points it at a volume),
falling back to ``~/.config_reviewer/history.db``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
MAX_STORED_SOURCE_BYTES = 2_000_000  # keep the file contents of a review only up to this size

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT    NOT NULL,
    label        TEXT    NOT NULL,
    file_count   INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    score        INTEGER NOT NULL,
    grade        TEXT    NOT NULL,
    critical     INTEGER NOT NULL DEFAULT 0,
    high         INTEGER NOT NULL DEFAULT 0,
    medium       INTEGER NOT NULL DEFAULT 0,
    low          INTEGER NOT NULL DEFAULT 0,
    info         INTEGER NOT NULL DEFAULT 0,
    ai_used      INTEGER NOT NULL DEFAULT 0,
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    result_json  TEXT    NOT NULL,
    sources_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at);
"""


def default_db_path() -> Path:
    env = os.environ.get("CONFIG_REVIEWER_DB")
    return Path(env) if env else Path.home() / ".config_reviewer" / "history.db"


def make_label(names: list[str]) -> str:
    """Short human label for a review, e.g. 'Dockerfile' or 'insecure/ (6 files)'."""
    if len(names) == 1:
        return names[0]
    prefixes = {n.split("/", 1)[0] for n in names if "/" in n}
    if len(prefixes) == 1 and all("/" in n for n in names):
        return f"{prefixes.pop()}/ ({len(names)} files)"
    return f"{len(names)} files"


class HistoryStore:
    """Thread-safe SQLite store for review results."""

    def __init__(self, path: Optional[Path | str] = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    # ------------------------------------------------------------------ writes
    def add(self, result: dict, sources: list[tuple[str, str]], ai_used: bool) -> int:
        counts = result.get("counts", {})
        names = [name for name, _ in sources]
        source_map = {name: text for name, text in sources}
        sources_json = json.dumps(source_map)
        if len(sources_json.encode("utf-8")) > MAX_STORED_SOURCE_BYTES:
            sources_json = None  # too big to keep; the findings are still stored
        row = (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            make_label(names),
            len(result.get("files", [])),
            sum(counts.values()),
            int(result["score"]),
            str(result["grade"]),
            *(int(counts.get(s, 0)) for s in SEVERITIES),
            1 if ai_used else 0,
            int(result.get("pipeline", {}).get("duration_ms", 0)),
            json.dumps(result),
            sources_json,
        )
        with self._lock, self._connect() as db:
            cur = db.execute(
                "INSERT INTO reviews (created_at, label, file_count, finding_count, score, grade, "
                "critical, high, medium, low, info, ai_used, duration_ms, result_json, sources_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )
            return int(cur.lastrowid)

    def delete(self, review_id: int) -> bool:
        with self._lock, self._connect() as db:
            return db.execute("DELETE FROM reviews WHERE id = ?", (review_id,)).rowcount > 0

    def clear(self) -> int:
        with self._lock, self._connect() as db:
            return db.execute("DELETE FROM reviews").rowcount

    # ------------------------------------------------------------------ reads
    @staticmethod
    def _summary(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "label": row["label"],
            "file_count": row["file_count"],
            "finding_count": row["finding_count"],
            "score": row["score"],
            "grade": row["grade"],
            "counts": {s: row[s.lower()] for s in SEVERITIES},
            "ai_used": bool(row["ai_used"]),
            "duration_ms": row["duration_ms"],
        }

    def list(self, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM reviews ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)
            ).fetchall()
        return [self._summary(r) for r in rows]

    def get(self, review_id: int) -> Optional[dict]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
        if row is None:
            return None
        data = self._summary(row)
        data["result"] = json.loads(row["result_json"])
        data["sources"] = json.loads(row["sources_json"]) if row["sources_json"] else {}
        return data

    def stats(self, trend_points: int = 30) -> dict:
        """Aggregates for the dashboard."""
        with self._connect() as db:
            totals = db.execute(
                "SELECT COUNT(*) AS reviews, COALESCE(SUM(file_count),0) AS files, "
                "COALESCE(SUM(finding_count),0) AS findings, AVG(score) AS avg_score, "
                "COALESCE(SUM(critical),0) AS critical, COALESCE(SUM(high),0) AS high, "
                "COALESCE(SUM(medium),0) AS medium, COALESCE(SUM(low),0) AS low, "
                "COALESCE(SUM(info),0) AS info, COALESCE(SUM(ai_used),0) AS ai_reviews FROM reviews"
            ).fetchone()
            trend = db.execute(
                "SELECT id, created_at, score, grade, label FROM reviews ORDER BY id DESC LIMIT ?",
                (trend_points,),
            ).fetchall()
            results = db.execute(
                "SELECT result_json FROM reviews ORDER BY id DESC LIMIT 200"
            ).fetchall()

        rules: Counter = Counter()
        rule_titles: dict[str, str] = {}
        rule_sev: dict[str, str] = {}
        types: Counter = Counter()
        categories: Counter = Counter()
        for (raw,) in results:
            data = json.loads(raw)
            for f in data.get("files", []):
                types[f.get("file_type", "unknown")] += 1
                for x in f.get("findings", []):
                    rules[x["rule_id"]] += 1
                    rule_titles[x["rule_id"]] = x["title"]
                    rule_sev[x["rule_id"]] = x["severity"]
                    categories[x["category"]] += 1

        return {
            "reviews": totals["reviews"],
            "files": totals["files"],
            "findings": totals["findings"],
            "avg_score": round(totals["avg_score"], 1) if totals["avg_score"] is not None else None,
            "ai_reviews": totals["ai_reviews"],
            "severity": {s: totals[s.lower()] for s in SEVERITIES},
            "trend": [
                {"id": r["id"], "created_at": r["created_at"], "score": r["score"],
                 "grade": r["grade"], "label": r["label"]}
                for r in reversed(trend)
            ],
            "top_rules": [
                {"rule_id": rid, "title": rule_titles[rid], "severity": rule_sev[rid], "count": n}
                for rid, n in rules.most_common(8)
            ],
            "file_types": dict(types.most_common()),
            "categories": dict(categories.most_common()),
        }
