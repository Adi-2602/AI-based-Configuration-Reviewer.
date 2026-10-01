import json

from config_reviewer.cli import main

from .conftest import EXAMPLES


def test_cli_insecure_fails(capsys):
    assert main([str(EXAMPLES / "insecure"), "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "Score:" in out and "CRITICAL" in out


def test_cli_secure_passes(capsys):
    assert main([str(EXAMPLES / "secure"), "--no-color"]) == 0


def test_cli_json_and_fail_never(capsys):
    assert main([str(EXAMPLES / "insecure"), "-f", "json", "--fail-on", "never"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] == "F" and data["counts"]["CRITICAL"] > 0


def test_cli_sarif_and_markdown(tmp_path):
    sarif = tmp_path / "out.sarif"
    md = tmp_path / "out.md"
    main([str(EXAMPLES / "insecure"), "-f", "sarif", "-o", str(sarif), "--fail-on", "never"])
    main([str(EXAMPLES / "insecure"), "-f", "markdown", "-o", str(md), "--fail-on", "never"])
    doc = json.loads(sarif.read_text())
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]
    assert md.read_text().startswith("# Configuration Review Report")


def test_cli_min_severity_filters(capsys):
    main([str(EXAMPLES / "insecure"), "-f", "json", "--min-severity", "critical", "--fail-on", "never"])
    data = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for file in data["files"] for f in file["findings"]}
    assert severities == {"CRITICAL"}


def test_cli_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    assert "DF001" in capsys.readouterr().out


def test_cli_missing_path(capsys):
    assert main(["does/not/exist"]) == 2
