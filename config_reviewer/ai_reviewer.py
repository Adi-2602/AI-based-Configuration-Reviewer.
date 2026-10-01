"""AI-powered deep review using Claude (Anthropic API).

The static rules catch well-known problems quickly and offline. The AI reviewer
reads the whole file in context, so it can catch things rules cannot: logic
errors, risky combinations of settings, environment-specific mistakes, and it
explains *why* something matters.

It is optional: install the ``anthropic`` package and provide credentials
(e.g. ``export ANTHROPIC_API_KEY=...``), then run the CLI with ``--ai``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .models import Category, Finding, Severity

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "high"
# Config files are small; anything larger is almost certainly generated/vendored.
MAX_FILE_CHARS = 200_000

SYSTEM_PROMPT = """You are a senior DevOps and cloud-security engineer performing a configuration review.

You receive one DevOps configuration file (with line numbers) plus the list of issues a static rule engine
has already reported for it. Your job is to find what the rules MISSED:
- security issues (exposed services, excessive privileges, injection risks, weak crypto, secrets handling)
- misconfigurations (settings that will break, conflict with each other, or not do what the author intended)
- reliability and operability problems (missing health checks, unsafe rollouts, no limits, single points of failure)
- violations of widely accepted best practices for this file type

Rules:
- Do NOT repeat issues already listed by the static engine.
- Only report issues you can tie to the actual file content. Do not speculate about files you cannot see.
- `line` must be the line number from the provided listing, or 0 if the issue is about the file as a whole.
- Keep `message` to one or two sentences and make `recommendation` concrete (show the corrected setting when useful).
- Severity guide: CRITICAL = directly exploitable or data-loss risk; HIGH = serious security/availability risk;
  MEDIUM = should be fixed soon; LOW = hardening/hygiene; INFO = suggestion.
- `summary` is a 2-3 sentence overall assessment of the file's quality and the most important fix.
It is fine to return an empty findings list if the file is in good shape."""

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "category": {"type": "string", "enum": [
                        Category.SECURITY, Category.MISCONFIGURATION, Category.BEST_PRACTICE, Category.RELIABILITY]},
                    "line": {"type": "integer"},
                    "message": {"type": "string"},
                    "recommendation": {"type": "string"},
                },
                "required": ["title", "severity", "category", "line", "message", "recommendation"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "findings"],
    "additionalProperties": False,
}


class AIUnavailableError(RuntimeError):
    """The AI reviewer cannot run (SDK missing, no credentials, ...)."""


class AIReviewError(RuntimeError):
    """A single AI review call failed."""


@dataclass
class AIReview:
    summary: str
    findings: list[Finding] = field(default_factory=list)


def build_prompt(path: str, file_type: str, text: str, existing: list[Finding]) -> str:
    numbered = "\n".join(f"{i:>4} | {line}" for i, line in enumerate(text.splitlines(), 1))
    if existing:
        known = "\n".join(f"- [{f.rule_id}] line {f.line or '-'}: {f.title} — {f.message}" for f in existing)
    else:
        known = "- (none)"
    return (
        f"File: {path}\nFile type: {file_type}\n\n"
        f"Issues already reported by the static rule engine:\n{known}\n\n"
        f"File content:\n```\n{numbered}\n```"
    )


class AIReviewer:
    def __init__(self, model: str = DEFAULT_MODEL, effort: str = DEFAULT_EFFORT):
        try:
            import anthropic
        except ImportError as exc:
            raise AIUnavailableError(
                "The 'anthropic' package is not installed. Run: pip install anthropic") from exc
        self._anthropic = anthropic
        self.model = model
        self.effort = effort
        try:
            # Resolves credentials from ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN / an `ant auth login` profile).
            self.client = anthropic.Anthropic()
        except Exception as exc:  # the SDK raises if it finds no credentials at all
            raise AIUnavailableError(
                f"Could not create the Anthropic client ({exc}). Set ANTHROPIC_API_KEY.") from exc

    def review(self, path: str, file_type: str, text: str, existing: list[Finding]) -> AIReview:
        if len(text) > MAX_FILE_CHARS:
            raise AIReviewError(f"file is larger than {MAX_FILE_CHARS} characters; skipped AI review")

        anthropic = self._anthropic
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": build_prompt(path, file_type, text, existing)}],
                output_config={
                    "effort": self.effort,
                    "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
                },
                # If a safety classifier declines the request, let the API retry on its recommended fallback model.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.AuthenticationError as exc:
            raise AIUnavailableError("Invalid or missing Anthropic API key (set ANTHROPIC_API_KEY).") from exc
        except anthropic.PermissionDeniedError as exc:
            raise AIUnavailableError(f"API key lacks permission: {exc.message}") from exc
        except anthropic.NotFoundError as exc:
            raise AIUnavailableError(f"Model '{self.model}' not found: {exc.message}") from exc
        except anthropic.RateLimitError as exc:
            raise AIReviewError("rate limited by the Anthropic API; try again later") from exc
        except anthropic.APIStatusError as exc:
            raise AIReviewError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise AIReviewError("could not reach the Anthropic API (network error)") from exc
        except TypeError as exc:
            # Raised by older SDK versions that don't know these parameters.
            raise AIUnavailableError(f"Your 'anthropic' package is too old ({exc}). Run: pip install -U anthropic") from exc

        if response.stop_reason == "refusal":
            raise AIReviewError("the model declined to review this file")
        if response.stop_reason == "max_tokens":
            raise AIReviewError("the AI response was cut off (max_tokens reached)")

        text_block = next((b.text for b in response.content if b.type == "text"), None)
        if not text_block:
            raise AIReviewError("the AI response contained no text")
        try:
            data = json.loads(text_block)
        except json.JSONDecodeError as exc:
            raise AIReviewError(f"could not parse AI response as JSON: {exc}") from exc

        line_count = len(text.splitlines())
        findings = []
        for i, item in enumerate(data.get("findings", []), 1):
            line = item.get("line") or None
            if line is not None and not 1 <= line <= line_count:
                line = None
            findings.append(Finding(
                rule_id=f"AI{i:03d}",
                title=item["title"],
                severity=Severity.parse(item["severity"]),
                category=item["category"],
                file=path,
                line=line,
                message=item["message"],
                recommendation=item["recommendation"],
                source="ai",
            ))
        return AIReview(summary=data.get("summary", "").strip(), findings=findings)
