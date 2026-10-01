"""Core data models shared by every analyzer, the AI reviewer and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    """How bad a finding is. Higher value = more severe."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Choose one of: {choices}") from exc


class Category:
    """Finding categories (plain strings so they serialise cleanly)."""

    SECURITY = "security"
    MISCONFIGURATION = "misconfiguration"
    BEST_PRACTICE = "best-practice"
    RELIABILITY = "reliability"


@dataclass(frozen=True)
class Rule:
    """A static check. Every finding produced by the rule engine points to one."""

    id: str
    title: str
    severity: Severity
    category: str
    recommendation: str


@dataclass
class Finding:
    """A single problem found in a configuration file."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: Optional[int]
    message: str
    recommendation: str
    source: str = "rules"  # "rules" for the static engine, "ai" for Claude

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "recommendation": self.recommendation,
            "source": self.source,
        }


@dataclass
class FileReport:
    """Everything we learned about one file."""

    path: str
    file_type: str
    findings: list[Finding] = field(default_factory=list)
    ai_summary: Optional[str] = None
    error: Optional[str] = None


# Points subtracted from a perfect score of 100 for each finding.
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class ReviewResult:
    """The result of reviewing one or more files."""

    files: list[FileReport] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for report in self.files for f in report.findings]

    def counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    @property
    def score(self) -> int:
        """0-100 health score: 100 means no issues found."""
        penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        score = self.score
        for threshold, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
            if score >= threshold:
                return grade
        return "F"

    def filter(self, min_severity: Severity) -> "ReviewResult":
        """Return a copy that only keeps findings at or above ``min_severity``."""
        files = []
        for report in self.files:
            kept = [f for f in report.findings if f.severity >= min_severity]
            files.append(
                FileReport(report.path, report.file_type, kept, report.ai_summary, report.error)
            )
        return ReviewResult(files)
