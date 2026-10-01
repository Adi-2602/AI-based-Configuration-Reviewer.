"""Hard-coded secret detection. Runs on every supported file type."""

from __future__ import annotations

import re

from ..detector import ALL_TYPES
from ..models import Category, Finding, Rule, Severity
from .base import Analyzer, rule_table

_REC = ("Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime "
        "from a secret manager or CI secret store.")

TOKEN_PATTERNS = [
    ("SEC001", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key ID"),
    ("SEC002", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"), "private key"),
    ("SEC003", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub token"),
    ("SEC003", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("SEC003", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "Anthropic API key"),
    ("SEC003", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "Stripe live secret key"),
    ("SEC003", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    ("SEC005", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s:/@$]{3,}@[^\s/]+", re.IGNORECASE),
     "credentials embedded in a connection URL"),
]

SENSITIVE_KEY = re.compile(
    r"""(?ix)
    (?P<key>[\w.\-]*(password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|private[_\-]?key|
        auth[_\-]?token|access[_\-]?token|token|credentials?)[\w\-]*)
    ["']?\s*(=|:)\s*
    (?P<value>"[^"]*"|'[^']*'|[^\s#,}]+)
    """
)
PLACEHOLDER = re.compile(
    r"^(\$|\{\{|<|\*+$|x+$|changeme$|change_me$|example|your[_\-]|placeholder|dummy|redacted|none$|null$|"
    r"true$|false$|required$|optional$|enabled$|disabled$|\[\]$|\{\}$|todo$|secret$|password$|\.\.\.$|var\.|local\.|data\.|module\.|ref\(|\(\))",
    re.IGNORECASE,
)
# Keys that reference a secret rather than contain one.
REFERENCE_KEYS = re.compile(r"(_file|_path|_ref|_name|_arn|_id|secretkeyref|secretname|valuefrom|_env|_var)$", re.I)


class SecretsAnalyzer(Analyzer):
    name = "secrets"
    file_types = ALL_TYPES
    rules = rule_table(
        Rule("SEC001", "AWS access key in file", Severity.CRITICAL, Category.SECURITY, _REC),
        Rule("SEC002", "Private key in file", Severity.CRITICAL, Category.SECURITY, _REC),
        Rule("SEC003", "API token in file", Severity.CRITICAL, Category.SECURITY, _REC),
        Rule("SEC004", "Hard-coded password or secret", Severity.CRITICAL, Category.SECURITY, _REC),
        Rule("SEC005", "Credentials in connection URL", Severity.CRITICAL, Category.SECURITY, _REC),
    )

    def analyze(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            hit = False
            for rule_id, rx, label in TOKEN_PATTERNS:
                if rx.search(line) and "${" not in rx.search(line).group(0):
                    findings.append(self.finding(rule_id, path, number, f"Possible {label}: {mask(line)}"))
                    hit = True
                    break
            if hit:
                continue
            m = SENSITIVE_KEY.search(line)
            if m:
                key = m.group("key")
                value = m.group("value").strip().strip("\"'")
                if (len(value) >= 4 and not PLACEHOLDER.match(value) and "${" not in value
                        and not REFERENCE_KEYS.search(key) and not value.startswith(("$", "%"))):
                    findings.append(self.finding("SEC004", path, number,
                                                 f"`{key}` has a hard-coded value: {mask(line)}"))
        return findings


def mask(line: str) -> str:
    """Show enough of the line to locate it without leaking the full secret."""
    line = line.strip()
    if len(line) > 80:
        line = line[:77] + "..."

    def _mask(m: re.Match) -> str:
        s = m.group(0)
        return s[:4] + "*" * min(8, max(3, len(s) - 4))

    # Mask any long-ish token after an = or : and any embedded known token.
    line = re.sub(r"(?<=[=:]\s)[^\s\"']{4,}|(?<=[=:])[^\s\"']{4,}|(?<=[\"'])[^\"']{6,}(?=[\"'])", _mask, line)
    return line
