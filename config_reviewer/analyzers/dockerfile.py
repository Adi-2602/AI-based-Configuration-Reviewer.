"""Rules for Dockerfiles."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..detector import DOCKERFILE
from ..models import Category, Finding, Rule, Severity
from .base import Analyzer, image_tag_problem, rule_table


@dataclass
class Instruction:
    line: int
    keyword: str
    args: str


def parse_dockerfile(text: str) -> list[Instruction]:
    """Very small Dockerfile parser that understands comments and line continuations."""
    instructions: list[Instruction] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        stripped = line.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if buffer and stripped.startswith("#"):
            continue  # comment inside a continued instruction
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        parts = buffer.strip().split(None, 1)
        instructions.append(Instruction(start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buffer = ""
    if buffer.strip():
        parts = buffer.strip().split(None, 1)
        instructions.append(Instruction(start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return instructions


class DockerfileAnalyzer(Analyzer):
    name = "dockerfile"
    file_types = (DOCKERFILE,)
    rules = rule_table(
        Rule("DF001", "Base image is not pinned", Severity.MEDIUM, Category.BEST_PRACTICE,
             "Pin the base image to a specific version tag (e.g. python:3.12-slim) or, better, a sha256 digest."),
        Rule("DF002", "Container runs as root", Severity.HIGH, Category.SECURITY,
             "Create an unprivileged user and switch to it with `USER appuser` before CMD/ENTRYPOINT."),
        Rule("DF003", "ADD used instead of COPY", Severity.LOW, Category.BEST_PRACTICE,
             "Use COPY for local files. ADD has implicit tar-extraction and URL behaviour that is easy to misuse."),
        Rule("DF004", "Remote file downloaded with ADD", Severity.MEDIUM, Category.SECURITY,
             "Download with curl/wget inside RUN and verify a checksum, or use COPY with a vendored file."),
        Rule("DF005", "Piping a remote script into a shell", Severity.HIGH, Category.SECURITY,
             "Download the script, verify its checksum/signature, then execute it. Never `curl | sh` untrusted content."),
        Rule("DF006", "No HEALTHCHECK defined", Severity.LOW, Category.RELIABILITY,
             "Add a HEALTHCHECK so the orchestrator can detect and restart unhealthy containers."),
        Rule("DF007", "sudo used in a RUN instruction", Severity.MEDIUM, Category.SECURITY,
             "Build steps already run as root; drop sudo and avoid installing it in the image."),
        Rule("DF008", "SSH port exposed", Severity.HIGH, Category.SECURITY,
             "Do not run SSH inside containers. Use `docker exec` / `kubectl exec` for debugging."),
        Rule("DF009", "World-writable permissions (chmod 777)", Severity.HIGH, Category.SECURITY,
             "Grant the minimum permissions needed (e.g. 755 for directories, 644 for files) and set ownership with --chown."),
        Rule("DF010", "apt-get install without --no-install-recommends", Severity.LOW, Category.BEST_PRACTICE,
             "Use `apt-get install -y --no-install-recommends` to keep the image small and reduce attack surface."),
        Rule("DF011", "apt cache not cleaned", Severity.LOW, Category.BEST_PRACTICE,
             "Finish the same RUN with `&& rm -rf /var/lib/apt/lists/*`."),
        Rule("DF012", "apt-get update in its own RUN", Severity.MEDIUM, Category.RELIABILITY,
             "Combine `apt-get update && apt-get install ...` in a single RUN so the package index is never stale (layer cache)."),
        Rule("DF013", "pip install without --no-cache-dir", Severity.LOW, Category.BEST_PRACTICE,
             "Use `pip install --no-cache-dir` to avoid shipping pip's cache in the image."),
        Rule("DF014", "Multiple CMD/ENTRYPOINT instructions", Severity.LOW, Category.MISCONFIGURATION,
             "Only the last CMD/ENTRYPOINT in a stage takes effect; remove the others."),
        Rule("DF015", "Deprecated MAINTAINER instruction", Severity.INFO, Category.BEST_PRACTICE,
             "Use `LABEL org.opencontainers.image.authors=\"...\"` instead."),
        Rule("DF016", "Shell-form CMD/ENTRYPOINT", Severity.LOW, Category.RELIABILITY,
             "Use the JSON exec form, e.g. CMD [\"python\", \"app.py\"], so signals (SIGTERM) reach your process."),
        Rule("DF017", "WORKDIR uses a relative path", Severity.LOW, Category.BEST_PRACTICE,
             "Use an absolute path for WORKDIR (e.g. /app)."),
    )

    def analyze(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        instructions = parse_dockerfile(text)
        if not instructions:
            return findings

        stage_aliases: set[str] = set()
        final_user = None
        user_line = None
        has_healthcheck = False

        for ins in instructions:
            kw, args = ins.keyword, ins.args

            if kw == "FROM":
                tokens = [t for t in args.split() if not t.startswith("--")]
                image = tokens[0] if tokens else ""
                if len(tokens) >= 3 and tokens[1].lower() == "as":
                    stage_aliases.add(tokens[2].lower())
                if image.lower() not in stage_aliases:
                    problem = image_tag_problem(image)
                    if problem:
                        findings.append(self.finding(
                            "DF001", path, ins.line,
                            f"Base image '{image}' is {problem}; builds are not reproducible and may pull unexpected changes."))
                # A new stage resets USER tracking.
                final_user, user_line = None, None

            elif kw == "USER":
                final_user, user_line = args.strip(), ins.line

            elif kw == "ADD":
                if re.search(r"https?://", args):
                    findings.append(self.finding("DF004", path, ins.line, f"ADD fetches a remote URL: {args}"))
                elif not re.search(r"\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz)\b", args):
                    findings.append(self.finding("DF003", path, ins.line, f"`ADD {args}` can be replaced with COPY."))

            elif kw == "RUN":
                self._check_run(path, ins, findings)

            elif kw == "EXPOSE":
                ports = re.findall(r"\d+", args)
                if "22" in ports:
                    findings.append(self.finding("DF008", path, ins.line, "Port 22 (SSH) is exposed."))

            elif kw == "HEALTHCHECK":
                has_healthcheck = not args.strip().upper().startswith("NONE")

            elif kw in ("CMD", "ENTRYPOINT"):
                if not args.strip().startswith("["):
                    findings.append(self.finding(
                        "DF016", path, ins.line,
                        f"{kw} uses shell form; the process runs under /bin/sh -c and will not receive SIGTERM."))

            elif kw == "MAINTAINER":
                findings.append(self.finding("DF015", path, ins.line, "MAINTAINER is deprecated."))

            elif kw == "WORKDIR":
                target = args.strip().strip('"')
                if target and not target.startswith(("/", "$")):
                    findings.append(self.finding("DF017", path, ins.line, f"WORKDIR '{target}' is relative."))

        from_indexes = [i for i, ins in enumerate(instructions) if ins.keyword == "FROM"]
        final_stage = instructions[from_indexes[-1] + 1:] if from_indexes else instructions
        for group in (
            [i for i in final_stage if i.keyword == "CMD"],
            [i for i in final_stage if i.keyword == "ENTRYPOINT"],
        ):
            if len(group) > 1:
                findings.append(self.finding(
                    "DF014", path, group[0].line,
                    f"{len(group)} {group[0].keyword} instructions in the final stage; only line {group[-1].line} is used."))

        if final_user is None or final_user.split(":")[0] in ("root", "0"):
            line = user_line if final_user else None
            msg = ("The final stage switches to the root user." if final_user
                   else "No USER instruction in the final stage, so the container runs as root.")
            findings.append(self.finding("DF002", path, line, msg))

        if not has_healthcheck:
            findings.append(self.finding("DF006", path, None, "The image does not define a HEALTHCHECK."))

        return findings

    def _check_run(self, path: str, ins: Instruction, findings: list[Finding]) -> None:
        cmd = ins.args
        if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", cmd):
            findings.append(self.finding("DF005", path, ins.line, "Remote script piped directly into a shell."))
        if re.search(r"(^|[\s;&|])sudo\s", cmd):
            findings.append(self.finding("DF007", path, ins.line, "`sudo` used during the build."))
        if re.search(r"chmod\s+(-R\s+)?0?777\b", cmd):
            findings.append(self.finding("DF009", path, ins.line, "chmod 777 makes files writable by every user."))

        apt_install = re.search(r"apt(-get)?\s+(-\S+\s+)*install\b", cmd)
        if apt_install:
            if "--no-install-recommends" not in cmd:
                findings.append(self.finding("DF010", path, ins.line, "apt-get install pulls in recommended packages."))
            if "/var/lib/apt/lists" not in cmd:
                findings.append(self.finding("DF011", path, ins.line, "Package lists are left in the image layer."))
        elif re.search(r"apt(-get)?\s+update\b", cmd):
            findings.append(self.finding("DF012", path, ins.line, "`apt-get update` without an install in the same layer."))

        if re.search(r"\bpip3?\s+install\b", cmd) and "--no-cache-dir" not in cmd:
            findings.append(self.finding("DF013", path, ins.line, "pip cache is stored in the image layer."))
