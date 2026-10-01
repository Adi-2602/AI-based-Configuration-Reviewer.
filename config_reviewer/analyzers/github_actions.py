"""Rules for GitHub Actions workflows."""

from __future__ import annotations

import re

import yaml

from ..detector import GITHUB_ACTIONS
from ..models import Category, Finding, Rule, Severity
from .base import Analyzer, find_line, rule_table

# Attacker-controllable expressions that must never be interpolated into `run:` scripts.
UNTRUSTED_CONTEXTS = re.compile(
    r"\$\{\{\s*github\.(event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|"
    r"comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|commits\.[^}]*message|"
    r"head_commit\.message|head_commit\.author\.(email|name)|pull_request\.head\.ref|"
    r"pull_request\.head\.label|workflow_run\.head_branch)|head_ref)\s*\}\}"
)
FULL_SHA = re.compile(r"@[0-9a-f]{40}$")


class GitHubActionsAnalyzer(Analyzer):
    name = "github-actions"
    file_types = (GITHUB_ACTIONS,)
    rules = rule_table(
        Rule("GHA001", "Third-party action not pinned to a commit SHA", Severity.MEDIUM, Category.SECURITY,
             "Pin actions to a full 40-character commit SHA (add the version as a comment), e.g. uses: org/action@<sha> # v4."),
        Rule("GHA002", "Action pinned to a mutable branch", Severity.HIGH, Category.SECURITY,
             "Never reference @main/@master; anyone with push access to that repo can change what runs in your CI."),
        Rule("GHA003", "No explicit GITHUB_TOKEN permissions", Severity.MEDIUM, Category.SECURITY,
             "Add a top-level `permissions:` block (e.g. `contents: read`) and grant more per job only where needed."),
        Rule("GHA004", "Overly broad GITHUB_TOKEN permissions", Severity.HIGH, Category.SECURITY,
             "Replace `write-all` with the minimal per-scope permissions."),
        Rule("GHA005", "Untrusted input interpolated into a script", Severity.HIGH, Category.SECURITY,
             "Pass the value through an environment variable (env: TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\" in the script."),
        Rule("GHA006", "pull_request_target checks out untrusted code", Severity.CRITICAL, Category.SECURITY,
             "Do not check out the PR head in pull_request_target workflows, or split into a pull_request + workflow_run pair."),
        Rule("GHA007", "Job has no timeout", Severity.LOW, Category.RELIABILITY,
             "Set `timeout-minutes` so hung jobs do not burn runner minutes for 6 hours."),
        Rule("GHA008", "Remote script piped into a shell", Severity.HIGH, Category.SECURITY,
             "Download, verify a checksum, then execute."),
        Rule("GHA009", "Secret printed to the log", Severity.HIGH, Category.SECURITY,
             "Never echo secrets; GitHub masking is best-effort and is bypassed by encoding/transformations."),
        Rule("GHA010", "Self-hosted runner on a public trigger", Severity.MEDIUM, Category.SECURITY,
             "Avoid self-hosted runners for pull_request workflows from forks; use ephemeral, isolated runners."),
        Rule("GHA011", "Credentials persisted by actions/checkout", Severity.LOW, Category.SECURITY,
             "Set `persist-credentials: false` on actions/checkout unless later steps need to push."),
    )

    def analyze(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            wf = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc
        if not isinstance(wf, dict):
            return findings

        triggers = wf.get("on", wf.get(True, {}))
        trigger_names = self._trigger_names(triggers)
        jobs = wf.get("jobs") or {}

        top_perms = wf.get("permissions")
        if top_perms is None and not all(isinstance(j, dict) and "permissions" in j for j in jobs.values()):
            findings.append(self.finding("GHA003", path, find_line(text, r"^jobs\s*:"),
                                         "The workflow does not restrict GITHUB_TOKEN permissions."))
        if top_perms == "write-all":
            findings.append(self.finding("GHA004", path, find_line(text, r"^permissions\s*:"), "permissions: write-all"))

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            jstart = find_line(text, rf"^\s+{re.escape(str(job_id))}\s*:") or 1

            if job.get("permissions") == "write-all":
                findings.append(self.finding("GHA004", path, find_line(text, r"permissions\s*:", jstart) or jstart,
                                             f"Job '{job_id}' uses permissions: write-all"))
            if "timeout-minutes" not in job and "uses" not in job:
                findings.append(self.finding("GHA007", path, jstart, f"Job '{job_id}' has no timeout-minutes."))

            runs_on = job.get("runs-on", "")
            runs_on_text = " ".join(map(str, runs_on)) if isinstance(runs_on, list) else str(runs_on)
            if "self-hosted" in runs_on_text and trigger_names & {"pull_request", "pull_request_target"}:
                findings.append(self.finding("GHA010", path, find_line(text, r"runs-on", jstart) or jstart,
                                             f"Job '{job_id}' runs PR code on a self-hosted runner."))

            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    findings.extend(self._check_step(path, text, step, jstart, trigger_names))

            if "uses" in job:  # reusable workflow call
                findings.extend(self._check_uses(path, text, str(job["uses"]), jstart))
        return findings

    @staticmethod
    def _trigger_names(triggers) -> set[str]:
        if isinstance(triggers, str):
            return {triggers}
        if isinstance(triggers, list):
            return {str(t) for t in triggers}
        if isinstance(triggers, dict):
            return {str(t) for t in triggers}
        return set()

    def _check_uses(self, path, text, uses: str, start: int) -> list[Finding]:
        out = []
        if uses.startswith(("./", "docker://")):
            return out
        line = find_line(text, re.escape(uses), start) or start
        ref = uses.rsplit("@", 1)[-1] if "@" in uses else ""
        if ref.lower() in ("main", "master", "dev", "develop", "head") or not ref:
            out.append(self.finding("GHA002", path, line, f"`{uses}` follows a mutable branch."))
        elif not FULL_SHA.search(uses):
            out.append(self.finding("GHA001", path, line, f"`{uses}` is pinned to a tag, which can be moved."))
        return out

    def _check_step(self, path, text, step, jstart, triggers) -> list[Finding]:
        out: list[Finding] = []
        uses = step.get("uses")
        if uses:
            out.extend(self._check_uses(path, text, str(uses), jstart))
            if str(uses).startswith("actions/checkout"):
                with_ = step.get("with") or {}
                line = find_line(text, re.escape(str(uses)), jstart) or jstart
                if "pull_request_target" in triggers and "head" in str(with_.get("ref", "")):
                    out.append(self.finding("GHA006", path, line,
                                            f"Checks out `{with_.get('ref')}` in a pull_request_target workflow."))
                if with_.get("persist-credentials") is not False:
                    out.append(self.finding("GHA011", path, line, "actions/checkout keeps the token in .git/config."))

        script = step.get("run")
        if script:
            script = str(script)
            first = script.strip().splitlines()[0] if script.strip() else ""
            line = find_line(text, re.escape(first[:40]), jstart) if first else jstart
            for m in UNTRUSTED_CONTEXTS.finditer(script):
                out.append(self.finding("GHA005", path, line, f"`{m.group(0)}` is expanded directly inside `run:`."))
            if re.search(r"(curl|wget)[^|;&\n]*\|\s*(sudo\s+)?(ba|z)?sh\b", script):
                out.append(self.finding("GHA008", path, line, "Remote script piped into a shell."))
            if re.search(r"(echo|printf|cat)[^\n]*\$\{\{\s*secrets\.", script):
                out.append(self.finding("GHA009", path, line, "A secret is written to stdout."))
        return out
