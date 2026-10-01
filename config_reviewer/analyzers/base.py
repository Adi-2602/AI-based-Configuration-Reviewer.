"""Shared building blocks for the static analyzers."""

from __future__ import annotations

import re
from typing import Iterable, Optional

from ..models import Finding, Rule


class Analyzer:
    """Base class: subclasses declare ``file_types`` + ``rules`` and implement ``analyze``."""

    name: str = "base"
    file_types: tuple[str, ...] = ()
    rules: dict[str, Rule] = {}

    def analyze(self, path: str, text: str) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def finding(self, rule_id: str, path: str, line: Optional[int], message: str) -> Finding:
        rule = self.rules[rule_id]
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            file=path,
            line=line,
            message=message,
            recommendation=rule.recommendation,
        )


def rule_table(*rules: Rule) -> dict[str, Rule]:
    return {r.id: r for r in rules}


def find_line(text: str, pattern: str, start: int = 1, end: Optional[int] = None) -> Optional[int]:
    """1-based line number of the first line (in [start, end]) matching ``pattern``."""
    rx = re.compile(pattern, re.IGNORECASE)
    for number, line in enumerate(text.splitlines(), 1):
        if number < start:
            continue
        if end is not None and number > end:
            break
        if rx.search(line):
            return number
    return None


def image_tag_problem(image: str) -> Optional[str]:
    """Return 'untagged' / 'latest' if a container image reference is not pinned."""
    image = str(image).strip()
    if not image or "$" in image or "@sha256:" in image or image == "scratch":
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "untagged"
    if last.split(":", 1)[1].lower() == "latest":
        return "latest"
    return None


def iter_lines(text: str) -> Iterable[tuple[int, str]]:
    return enumerate(text.splitlines(), 1)


def yaml_documents(text: str) -> list[tuple[int, int]]:
    """Return (start_line, end_line) for every document in a multi-doc YAML file."""
    lines = text.splitlines()
    spans, start = [], 1
    for number, line in enumerate(lines, 1):
        if line.strip() == "---" or line.startswith("--- "):
            if number > start:
                spans.append((start, number - 1))
            start = number + 1
    spans.append((start, max(start, len(lines))))
    return spans
