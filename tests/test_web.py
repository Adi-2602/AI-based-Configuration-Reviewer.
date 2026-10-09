"""Tests for the Flask web API (no network, no API key)."""

import json

import pytest

flask = pytest.importorskip("flask")

from config_reviewer.ai_reviewer import AIReview, AIUnavailableError  # noqa: E402
from config_reviewer.models import Finding, Severity  # noqa: E402
from config_reviewer.web import create_app  # noqa: E402

DOCKERFILE = "FROM python:latest\nRUN curl https://x.sh | sh\nCMD python app.py\n"


class FakeAI:
    def review(self, path, file_type, text, existing):
        return AIReview("Looks risky.", [Finding("AI001", "Port mismatch", Severity.MEDIUM, "misconfiguration",
                                                 path, 1, "msg", "fix", source="ai")])


@pytest.fixture
def client():
    return create_app(ai_factory=lambda model, effort: FakeAI()).test_client()


def test_index_and_static(client):
    assert b"AI Config Reviewer" in client.get("/").data
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/../app.py").status_code == 404


def test_status_and_rules(client):
    status = client.get("/api/status").get_json()
    assert status["rule_count"] == 74
    rules = client.get("/api/rules").get_json()["rules"]
    assert len(rules) == 74 and {"id", "severity", "analyzer"} <= set(rules[0])


def test_examples(client):
    sets = client.get("/api/examples").get_json()["sets"]
    assert len(sets["insecure"]) == 6 and len(sets["secure"]) == 5


def test_review_rules_only(client):
    res = client.post("/api/review", json={"files": [{"name": "Dockerfile", "content": DOCKERFILE}]})
    data = res.get_json()
    assert res.status_code == 200
    assert data["files"][0]["file_type"] == "dockerfile"
    ids = {f["rule_id"] for f in data["files"][0]["findings"]}
    assert {"DF001", "DF002", "DF005"} <= ids
    assert data["pipeline"]["ai"] == "off" and data["pipeline"]["rule_findings"] >= len(ids)
    assert data["grade"] in "ABCDF"


def test_review_with_ai(client):
    data = client.post("/api/review", json={"files": [{"name": "Dockerfile", "content": DOCKERFILE}],
                                            "ai": True}).get_json()
    assert data["pipeline"]["ai"] == "on" and data["pipeline"]["ai_findings"] == 1
    assert data["files"][0]["ai_summary"] == "Looks risky."


def test_review_ai_unavailable():
    def boom(model, effort):
        raise AIUnavailableError("no key")

    c = create_app(ai_factory=boom).test_client()
    data = c.post("/api/review", json={"files": [{"name": "Dockerfile", "content": DOCKERFILE}], "ai": True}).get_json()
    assert data["pipeline"]["ai"] == "unavailable"
    assert any("no key" in m for m in data["pipeline"]["messages"])


@pytest.mark.parametrize("body,msg", [
    ({}, "at least one file"),
    ({"files": [{"name": "", "content": "x"}]}, "needs a name"),
    ({"files": [{"name": "a", "content": 1}]}, "no text content"),
    ({"files": [{"name": "a", "content": "x" * 600_000}]}, "larger than"),
    ({"files": [{"name": "Dockerfile", "content": "FROM a"}], "effort": "huge"}, "effort"),
])
def test_review_validation(client, body, msg):
    res = client.post("/api/review", json=body)
    assert res.status_code == 400 and msg in res.get_json()["error"]


def test_export_round_trip(client):
    result = client.post("/api/review", json={"files": [{"name": "Dockerfile", "content": DOCKERFILE}]}).get_json()
    md = client.post("/api/export", json={"format": "markdown", "result": result})
    assert md.status_code == 200 and md.data.startswith(b"# Configuration Review Report")
    sarif = json.loads(client.post("/api/export", json={"format": "sarif", "result": result}).data)
    assert sarif["version"] == "2.1.0"
    assert client.post("/api/export", json={"format": "pdf", "result": result}).status_code == 400
