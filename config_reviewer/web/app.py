"""Flask application that exposes the reviewer as a JSON API and serves the UI.

Endpoints
---------
GET  /                 the single-page frontend (static/index.html)
GET  /api/status       version, rule count, whether the AI review is available
GET  /api/rules        every built-in rule
GET  /api/examples     the bundled insecure/secure example files
POST /api/review       {"files": [{"name", "content"}], "ai": bool, "effort": str}
POST /api/export       {"format": "markdown"|"sarif"|"json", "result": <review result>}

Uploaded files are reviewed in memory only; nothing is written to disk.
"""

from __future__ import annotations

import argparse
import os
import time
from collections import Counter
from pathlib import Path
from typing import Callable, Optional

from flask import Flask, Response, jsonify, request, send_from_directory

from .. import __version__
from ..ai_reviewer import DEFAULT_EFFORT, DEFAULT_MODEL, AIReviewer, AIUnavailableError
from ..analyzers import ANALYZERS
from ..detector import ALL_TYPES, UNKNOWN, detect_file_type
from ..models import FileReport, Finding, ReviewResult, Severity
from ..reporters import render
from ..reviewer import review_sources

STATIC_DIR = Path(__file__).resolve().parent / "static"
EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"

MAX_FILES = 50
MAX_FILE_BYTES = 500_000
MAX_REQUEST_BYTES = 30 * 1024 * 1024
EFFORTS = ("low", "medium", "high", "xhigh", "max")

AIFactory = Callable[[str, str], object]


class BadRequest(Exception):
    """Invalid input from the browser; turned into a 400 JSON response."""


def ai_status() -> tuple[bool, str]:
    """Best-effort check whether the AI review can run (package + credentials)."""
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, "Install the 'anthropic' package to enable AI review."
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False, "Set ANTHROPIC_API_KEY before starting the server to enable AI review."
    return True, "AI review available."


def load_examples() -> dict[str, list[dict]]:
    sets: dict[str, list[dict]] = {}
    for name in ("insecure", "secure"):
        folder = EXAMPLES_DIR / name
        if not folder.is_dir():
            continue
        files = []
        for path in sorted(p for p in folder.rglob("*") if p.is_file()):
            rel = path.relative_to(folder).as_posix()
            if detect_file_type(rel) == UNKNOWN and detect_file_type(path) == UNKNOWN:
                continue
            files.append({"name": rel, "content": path.read_text(encoding="utf-8", errors="replace")})
        sets[name] = files
    return sets


def parse_sources(payload: dict) -> list[tuple[str, str]]:
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise BadRequest("Add at least one file to review.")
    if len(files) > MAX_FILES:
        raise BadRequest(f"Too many files: the limit is {MAX_FILES} per review.")
    sources, seen = [], Counter()
    for item in files:
        if not isinstance(item, dict):
            raise BadRequest("Each file must be an object with 'name' and 'content'.")
        name, content = item.get("name"), item.get("content")
        if not isinstance(name, str) or not name.strip() or len(name) > 300:
            raise BadRequest("Each file needs a name (max 300 characters).")
        if not isinstance(content, str):
            raise BadRequest(f"File '{name}' has no text content.")
        if len(content.encode("utf-8", errors="replace")) > MAX_FILE_BYTES:
            raise BadRequest(f"File '{name}' is larger than {MAX_FILE_BYTES // 1000} KB.")
        name = name.strip().replace("\\", "/").lstrip("/")
        seen[name] += 1
        if seen[name] > 1:  # keep duplicate names distinguishable in the report
            name = f"{name} ({seen[name]})"
        sources.append((name, content))
    return sources


def result_to_dict(result: ReviewResult) -> dict:
    return {
        "score": result.score,
        "grade": result.grade,
        "counts": result.counts(),
        "files": [
            {
                "path": r.path,
                "file_type": r.file_type,
                "error": r.error,
                "ai_summary": r.ai_summary,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in result.files
        ],
    }


def result_from_dict(data: dict) -> ReviewResult:
    """Rebuild a ReviewResult sent back by the browser (used for report export)."""
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        raise BadRequest("Missing review result to export.")
    files = []
    try:
        for f in data["files"]:
            report = FileReport(str(f["path"]), str(f.get("file_type", UNKNOWN)),
                                error=f.get("error"), ai_summary=f.get("ai_summary"))
            for x in f.get("findings", []):
                line = x.get("line")
                report.findings.append(Finding(
                    rule_id=str(x["rule_id"]), title=str(x["title"]), severity=Severity.parse(str(x["severity"])),
                    category=str(x["category"]), file=str(x.get("file", report.path)),
                    line=int(line) if isinstance(line, int) else None, message=str(x["message"]),
                    recommendation=str(x["recommendation"]), source=str(x.get("source", "rules")),
                ))
            files.append(report)
    except (KeyError, TypeError, ValueError) as exc:
        raise BadRequest(f"Invalid review result: {exc}") from exc
    return ReviewResult(files)


def create_app(ai_factory: Optional[AIFactory] = None) -> Flask:
    """Build the Flask app. ``ai_factory(model, effort)`` is injectable for tests."""
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    make_ai = ai_factory or (lambda model, effort: AIReviewer(model=model, effort=effort))

    @app.errorhandler(BadRequest)
    def _bad_request(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(413)
    def _too_large(_exc):
        return jsonify(error="Upload too large."), 413

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    @app.get("/api/status")
    def status():
        available, reason = ai_status() if ai_factory is None else (True, "AI review available.")
        return jsonify(
            version=__version__,
            rule_count=sum(len(a.rules) for a in ANALYZERS),
            file_types=list(ALL_TYPES),
            ai={"available": available, "reason": reason, "model": DEFAULT_MODEL, "effort": DEFAULT_EFFORT},
        )

    @app.get("/api/rules")
    def rules():
        return jsonify(rules=[
            {"id": r.id, "title": r.title, "severity": r.severity.name, "category": r.category,
             "recommendation": r.recommendation, "analyzer": a.name}
            for a in ANALYZERS for r in a.rules.values()
        ])

    @app.get("/api/examples")
    def examples():
        return jsonify(sets=load_examples())

    @app.post("/api/review")
    def review():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise BadRequest("Send a JSON body.")
        sources = parse_sources(payload)
        effort = payload.get("effort", DEFAULT_EFFORT)
        if effort not in EFFORTS:
            raise BadRequest(f"effort must be one of {', '.join(EFFORTS)}")

        messages: list[str] = []
        ai, ai_state = None, "off"
        if payload.get("ai"):
            try:
                ai = make_ai(DEFAULT_MODEL, effort)
                ai_state = "on"
            except AIUnavailableError as exc:
                messages.append(f"AI review disabled: {exc}")
                ai_state = "unavailable"

        started = time.perf_counter()
        result = review_sources(sources, ai_reviewer=ai, log=messages.append)
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        if ai_state == "on" and any(m.startswith("AI review disabled") for m in messages):
            ai_state = "unavailable"

        findings = result.findings
        data = result_to_dict(result)
        data["pipeline"] = {
            "files": len(result.files),
            "detected": dict(Counter(r.file_type for r in result.files if r.file_type != UNKNOWN)),
            "unsupported": sum(1 for r in result.files if r.file_type == UNKNOWN),
            "rule_findings": sum(1 for f in findings if f.source == "rules"),
            "ai_findings": sum(1 for f in findings if f.source == "ai"),
            "ai": ai_state,
            "messages": [m for m in messages if not m.startswith("AI reviewing")],
            "duration_ms": elapsed_ms,
        }
        return jsonify(data)

    @app.post("/api/export")
    def export():
        payload = request.get_json(silent=True) or {}
        fmt = payload.get("format")
        if fmt not in ("markdown", "sarif", "json"):
            raise BadRequest("format must be markdown, sarif or json")
        text = render(result_from_dict(payload.get("result")), fmt)
        ext, mime = {"markdown": ("md", "text/markdown"), "sarif": ("sarif", "application/json"),
                     "json": ("json", "application/json")}[fmt]
        return Response(text, mimetype=mime,
                        headers={"Content-Disposition": f'attachment; filename="config-review.{ext}"'})

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="config-reviewer-web", description="Start the web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1, local only)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    args = parser.parse_args(argv)
    if args.host not in ("127.0.0.1", "localhost"):
        print("warning: the server is reachable from other machines and has no login; "
              "anyone who can reach it can use your AI credits.")
    available, reason = ai_status()
    print(f"AI Config Reviewer {__version__} running at http://{args.host}:{args.port}  ({reason})")
    create_app().run(host=args.host, port=args.port, debug=False)
    return 0
