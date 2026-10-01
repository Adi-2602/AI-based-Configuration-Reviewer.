"""Output formats: colored text, JSON, Markdown and SARIF (for GitHub code scanning)."""

from __future__ import annotations

import json
import os
import sys

from . import __version__
from .analyzers import all_rules
from .models import ReviewResult, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;41;97m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def render(result: ReviewResult, fmt: str, color: bool = False) -> str:
    renderers = {"text": render_text, "json": render_json, "markdown": render_markdown, "sarif": render_sarif}
    if fmt == "text":
        return render_text(result, color)
    return renderers[fmt](result)


def render_text(result: ReviewResult, color: bool = False) -> str:
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda _code, s: s)
    out = []
    for report in result.files:
        out.append(c(BOLD, f"\n{report.path}") + c(DIM, f"  [{report.file_type}]"))
        if report.error:
            out.append(c(COLORS[Severity.MEDIUM], f"  ! {report.error}"))
        if not report.findings and not report.error:
            out.append("  ✓ No issues found")
        for f in report.findings:
            loc = f"L{f.line}" if f.line else "  - "
            tag = c(COLORS[f.severity], f" {f.severity.name:<8} ")
            src = c(DIM, " (AI)") if f.source == "ai" else ""
            out.append(f"  {loc:>5} {tag} {c(BOLD, f.rule_id)} {f.title}{src}")
            out.append(f"         {f.message}")
            out.append(c(DIM, f"         ↳ Fix: {f.recommendation}"))
        if report.ai_summary:
            out.append(c(BOLD, "  AI summary: ") + report.ai_summary)

    counts = result.counts()
    summary = ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n) or "no issues"
    out.append("")
    out.append(c(BOLD, "Summary: ") + f"{len(result.files)} file(s) reviewed, {len(result.findings)} finding(s): {summary}")
    out.append(c(BOLD, "Score:   ") + f"{result.score}/100 (grade {result.grade})")
    return "\n".join(out)


def render_json(result: ReviewResult) -> str:
    payload = {
        "tool": "ai-config-reviewer",
        "version": __version__,
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
    return json.dumps(payload, indent=2)


def render_markdown(result: ReviewResult) -> str:
    icons = {Severity.CRITICAL: "🟥", Severity.HIGH: "🟧", Severity.MEDIUM: "🟨", Severity.LOW: "🟦", Severity.INFO: "⬜"}
    lines = ["# Configuration Review Report", "",
             f"**Score:** {result.score}/100 (grade **{result.grade}**) · "
             f"**Files:** {len(result.files)} · **Findings:** {len(result.findings)}", "",
             "| Severity | Count |", "|---|---|"]
    lines += [f"| {icons[Severity[s]]} {s} | {n} |" for s, n in result.counts().items()]
    for report in result.files:
        lines += ["", f"## `{report.path}` ({report.file_type})", ""]
        if report.error:
            lines += [f"> ⚠️ {report.error}", ""]
        if report.ai_summary:
            lines += [f"> 🤖 **AI summary:** {report.ai_summary}", ""]
        if not report.findings:
            lines.append("✅ No issues found.")
            continue
        lines += ["| Line | Severity | Rule | Issue | Recommendation |", "|---|---|---|---|---|"]
        for f in report.findings:
            msg = f"**{f.title}**{' _(AI)_' if f.source == 'ai' else ''}<br>{f.message}".replace("|", "\\|")
            rec = f.recommendation.replace("|", "\\|")
            lines.append(f"| {f.line or '-'} | {icons[f.severity]} {f.severity.name} | `{f.rule_id}` | {msg} | {rec} |")
    return "\n".join(lines) + "\n"


def render_sarif(result: ReviewResult) -> str:
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
             Severity.LOW: "note", Severity.INFO: "note"}
    rules = {r.id: r for r in all_rules()}
    used = sorted({f.rule_id for f in result.findings})
    sarif_rules = []
    for rid in used:
        sample = next(f for f in result.findings if f.rule_id == rid)
        sarif_rules.append({
            "id": rid,
            "name": sample.title,
            "shortDescription": {"text": sample.title},
            "help": {"text": rules[rid].recommendation if rid in rules else sample.recommendation},
            "properties": {"tags": [sample.category], "problem.severity": level[sample.severity]},
        })
    results = []
    for f in result.findings:
        location = {"physicalLocation": {"artifactLocation": {"uri": f.file}}}
        if f.line:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id,
            "level": level[f.severity],
            "message": {"text": f"{f.message} Fix: {f.recommendation}"},
            "locations": [location],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ai-config-reviewer", "version": __version__, "rules": sarif_rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def write(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
