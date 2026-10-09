"""Orchestrates detection, static analysis and (optionally) the AI review."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, Optional

from .analyzers import analyzers_for
from .detector import UNKNOWN, detect_file_type, discover_files
from .models import FileReport, ReviewResult

Logger = Callable[[str], None]


def review_text(path: str, text: str, file_type: Optional[str] = None) -> FileReport:
    """Run every static analyzer that applies to ``file_type`` on ``text``."""
    file_type = file_type or detect_file_type(path, text)
    report = FileReport(path=path, file_type=file_type)
    if file_type == UNKNOWN:
        report.error = "Unsupported file type"
        return report
    for analyzer in analyzers_for(file_type):
        try:
            report.findings.extend(analyzer.analyze(path, text))
        except ValueError as exc:  # e.g. invalid YAML
            report.error = str(exc)
    report.findings.sort(key=lambda f: (f.line or 0, -f.severity))
    return report


def review_sources(
    sources: Iterable[tuple[str, str]],
    ai_reviewer=None,
    log: Logger = lambda _msg: None,
) -> ReviewResult:
    """Review in-memory ``(name, text)`` pairs. Used by the CLI and the web UI.

    ``ai_reviewer`` is an optional :class:`~config_reviewer.ai_reviewer.AIReviewer`.
    """
    from .ai_reviewer import AIReviewError, AIUnavailableError

    result = ReviewResult()
    for name, text in sources:
        file_type = detect_file_type(name, text)
        report = review_text(name, text, file_type)

        if ai_reviewer is not None and file_type != UNKNOWN:
            log(f"AI reviewing {name} ...")
            try:
                ai = ai_reviewer.review(name, file_type, text, report.findings)
                report.ai_summary = ai.summary
                report.findings.extend(ai.findings)
                report.findings.sort(key=lambda f: (f.line or 0, -f.severity))
            except AIUnavailableError as exc:
                log(f"AI review disabled: {exc}")
                ai_reviewer = None
            except AIReviewError as exc:
                log(f"AI review skipped for {name}: {exc}")

        result.files.append(report)
    return result


def review_paths(
    paths: list[str],
    ai_reviewer=None,
    log: Logger = lambda _msg: None,
) -> ReviewResult:
    """Review files/directories on disk."""
    sources: list[tuple[str, str]] = []
    unreadable: list[FileReport] = []
    for file_path in discover_files(paths):
        display = file_path.as_posix()
        try:
            sources.append((display, Path(file_path).read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            unreadable.append(FileReport(display, UNKNOWN, error=str(exc)))

    result = review_sources(sources, ai_reviewer=ai_reviewer, log=log)
    result.files.extend(unreadable)
    return result
