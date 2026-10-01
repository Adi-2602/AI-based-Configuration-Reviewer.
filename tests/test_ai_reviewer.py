"""Tests for the AI reviewer using a fake Anthropic client (no network, no API key)."""

import json
from types import SimpleNamespace

import pytest

from config_reviewer import ai_reviewer
from config_reviewer.ai_reviewer import AIReviewer, AIReviewError, build_prompt
from config_reviewer.models import Severity
from config_reviewer.reviewer import review_paths


class FakeMessages:
    def __init__(self, payload, stop_reason="end_turn"):
        self.payload, self.stop_reason, self.calls = payload, stop_reason, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        block = SimpleNamespace(type="text", text=json.dumps(self.payload))
        return SimpleNamespace(content=[block], stop_reason=self.stop_reason)


def make_reviewer(payload, stop_reason="end_turn"):
    reviewer = AIReviewer.__new__(AIReviewer)  # skip __init__ (no SDK client / credentials needed)
    pytest.importorskip("anthropic")
    import anthropic

    reviewer._anthropic = anthropic
    reviewer.model = ai_reviewer.DEFAULT_MODEL
    reviewer.effort = "high"
    messages = FakeMessages(payload, stop_reason)
    reviewer.client = SimpleNamespace(beta=SimpleNamespace(messages=messages))
    return reviewer, messages


PAYLOAD = {
    "summary": "Mostly fine, but the service is exposed without TLS.",
    "findings": [{
        "title": "No TLS termination", "severity": "HIGH", "category": "security", "line": 2,
        "message": "Traffic is served over plain HTTP.", "recommendation": "Terminate TLS at the ingress.",
    }, {
        "title": "Out of range line", "severity": "LOW", "category": "best-practice", "line": 999,
        "message": "x", "recommendation": "y",
    }],
}


def test_ai_review_parses_findings():
    reviewer, messages = make_reviewer(PAYLOAD)
    review = reviewer.review("Dockerfile", "dockerfile", "FROM a:1\nEXPOSE 80\n", [])
    assert review.summary.startswith("Mostly fine")
    assert [f.rule_id for f in review.findings] == ["AI001", "AI002"]
    assert review.findings[0].severity == Severity.HIGH and review.findings[0].source == "ai"
    assert review.findings[1].line is None  # invalid line numbers are dropped

    call = messages.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "   2 | EXPOSE 80" in call["messages"][0]["content"]


def test_ai_refusal_raises():
    reviewer, _ = make_reviewer(PAYLOAD, stop_reason="refusal")
    with pytest.raises(AIReviewError):
        reviewer.review("Dockerfile", "dockerfile", "FROM a:1\n", [])


def test_ai_findings_merged_into_report(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM a:1\nEXPOSE 80\n")
    reviewer, _ = make_reviewer(PAYLOAD)
    result = review_paths([str(tmp_path)], ai_reviewer=reviewer)
    report = result.files[0]
    assert report.ai_summary
    assert any(f.source == "ai" for f in report.findings)
    assert any(f.source == "rules" for f in report.findings)


def test_prompt_lists_known_issues():
    from config_reviewer.reviewer import review_text

    report = review_text("Dockerfile", "FROM ubuntu\n")
    prompt = build_prompt("Dockerfile", "dockerfile", "FROM ubuntu\n", report.findings)
    assert "DF001" in prompt
