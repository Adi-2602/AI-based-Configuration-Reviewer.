"""Command line interface: ``config-reviewer PATH [PATH ...]``."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .ai_reviewer import DEFAULT_EFFORT, DEFAULT_MODEL, AIReviewer, AIUnavailableError
from .analyzers import ANALYZERS
from .models import Severity
from .reporters import render, use_color, write
from .reviewer import review_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="config-reviewer",
        description="AI-powered reviewer for DevOps configuration files (Dockerfile, docker-compose, "
                    "Kubernetes, GitHub Actions, Terraform, .env).",
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to review")
    parser.add_argument("-f", "--format", choices=["text", "json", "markdown", "sarif"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("-o", "--output", help="Write the report to this file instead of stdout")
    parser.add_argument("--ai", action="store_true",
                        help="Also run an AI deep review with Claude (needs `pip install anthropic` and ANTHROPIC_API_KEY)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Claude model for --ai (default: {DEFAULT_MODEL})")
    parser.add_argument("--effort", default=DEFAULT_EFFORT, choices=["low", "medium", "high", "xhigh", "max"],
                        help=f"How hard the AI should think (default: {DEFAULT_EFFORT})")
    parser.add_argument("--min-severity", default="info", help="Hide findings below this severity (default: info)")
    parser.add_argument("--fail-on", default="high",
                        help="Exit with code 1 if any finding is at/above this severity, or 'never' (default: high)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--list-rules", action="store_true", help="List every built-in rule and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def list_rules() -> str:
    lines = []
    for analyzer in ANALYZERS:
        lines.append(f"\n[{analyzer.name}]")
        for rule in analyzer.rules.values():
            lines.append(f"  {rule.id:<7} {rule.severity.name:<8} {rule.category:<17} {rule.title}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print(list_rules())
        return 0
    if not args.paths:
        parser.error("at least one PATH is required")

    try:
        min_severity = Severity.parse(args.min_severity)
        fail_on = None if args.fail_on.lower() == "never" else Severity.parse(args.fail_on)
    except ValueError as exc:
        parser.error(str(exc))

    def log(msg: str) -> None:
        print(msg, file=sys.stderr)

    ai = None
    if args.ai:
        try:
            ai = AIReviewer(model=args.model, effort=args.effort)
        except AIUnavailableError as exc:
            log(f"warning: AI review disabled: {exc}")

    try:
        result = review_paths(args.paths, ai_reviewer=ai, log=log)
    except FileNotFoundError as exc:
        log(f"error: {exc}")
        return 2

    if not result.files:
        log("No supported configuration files found.")
        return 0

    shown = result.filter(min_severity)
    color = args.format == "text" and not args.no_color and not args.output and use_color(sys.stdout)
    write(render(shown, args.format, color=color), args.output)
    if args.output:
        log(f"Report written to {args.output}")

    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
