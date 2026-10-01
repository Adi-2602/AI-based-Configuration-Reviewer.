"""Rules for docker-compose files."""

from __future__ import annotations

import re

import yaml

from ..detector import COMPOSE
from ..models import Category, Finding, Rule, Severity
from .base import Analyzer, find_line, image_tag_problem, rule_table

DATABASE_PORTS = {"3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB", "6379": "Redis",
                  "9200": "Elasticsearch", "11211": "Memcached", "5984": "CouchDB", "1433": "SQL Server"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"}


class ComposeAnalyzer(Analyzer):
    name = "docker-compose"
    file_types = (COMPOSE,)
    rules = rule_table(
        Rule("DC001", "Privileged container", Severity.CRITICAL, Category.SECURITY,
             "Remove `privileged: true`; grant only the specific capabilities the service needs with cap_add."),
        Rule("DC002", "Image is not pinned", Severity.MEDIUM, Category.BEST_PRACTICE,
             "Pin images to an explicit version tag or sha256 digest."),
        Rule("DC003", "Host network mode", Severity.HIGH, Category.SECURITY,
             "Use the default bridge/user-defined networks and publish only required ports."),
        Rule("DC004", "Docker socket mounted into a container", Severity.CRITICAL, Category.SECURITY,
             "Mounting /var/run/docker.sock gives the container root on the host. Remove it or use a socket proxy with an allow-list."),
        Rule("DC005", "Database port published on all interfaces", Severity.HIGH, Category.SECURITY,
             "Do not publish database ports, or bind them to localhost (\"127.0.0.1:5432:5432\")."),
        Rule("DC006", "No restart policy", Severity.LOW, Category.RELIABILITY,
             "Set `restart: unless-stopped` (or deploy.restart_policy) so the service recovers from crashes."),
        Rule("DC007", "No resource limits", Severity.LOW, Category.RELIABILITY,
             "Set deploy.resources.limits (cpus/memory) to stop one service starving the host."),
        Rule("DC008", "Dangerous Linux capability added", Severity.HIGH, Category.SECURITY,
             "Remove broad capabilities like SYS_ADMIN/ALL; add only narrowly scoped ones."),
        Rule("DC009", "No healthcheck", Severity.INFO, Category.RELIABILITY,
             "Add a healthcheck so dependants can use `depends_on: condition: service_healthy`."),
        Rule("DC010", "Obsolete `version` key", Severity.INFO, Category.BEST_PRACTICE,
             "The Compose Specification ignores `version`; remove it."),
        Rule("DC011", "Security options disabled", Severity.HIGH, Category.SECURITY,
             "Do not set seccomp/apparmor to `unconfined`."),
        Rule("DC012", "Sensitive host path mounted", Severity.HIGH, Category.SECURITY,
             "Avoid mounting host system directories (/, /etc, /root, /proc). Mount only application data directories."),
    )

    def analyze(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            return findings

        if "version" in data:
            findings.append(self.finding("DC010", path, find_line(text, r"^version\s*:"),
                                         "`version` is obsolete in the Compose Specification."))

        services = data.get("services") or {}
        if not isinstance(services, dict):
            return findings

        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            start = find_line(text, rf"^\s+{re.escape(str(name))}\s*:") or 1
            line_of = lambda pattern: find_line(text, pattern, start) or start  # noqa: E731
            label = f"Service '{name}'"

            if svc.get("privileged") is True:
                findings.append(self.finding("DC001", path, line_of(r"privileged\s*:"), f"{label} runs privileged."))

            image = svc.get("image")
            if image and not svc.get("build"):
                problem = image_tag_problem(image)
                if problem:
                    findings.append(self.finding("DC002", path, line_of(r"image\s*:"),
                                                 f"{label} uses image '{image}' which is {problem}."))

            if str(svc.get("network_mode", "")).lower() == "host":
                findings.append(self.finding("DC003", path, line_of(r"network_mode\s*:"), f"{label} uses the host network."))

            for volume in svc.get("volumes") or []:
                source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":")[0]
                if "docker.sock" in source:
                    findings.append(self.finding("DC004", path, line_of(r"docker\.sock"), f"{label} mounts {source}."))
                elif source in ("/", "/etc", "/root", "/proc", "/sys", "/var/run", "/boot"):
                    findings.append(self.finding("DC012", path, line_of(re.escape(source) + r"\s*:"),
                                                 f"{label} mounts host path '{source}'."))

            for port in svc.get("ports") or []:
                host_ip, container_port = self._parse_port(port)
                if container_port in DATABASE_PORTS and host_ip in ("", "0.0.0.0", "::"):
                    findings.append(self.finding(
                        "DC005", path, line_of(re.escape(container_port)),
                        f"{label} publishes {DATABASE_PORTS[container_port]} port {container_port} on all interfaces."))

            caps = {str(c).upper().replace("CAP_", "") for c in svc.get("cap_add") or []}
            for cap in sorted(caps & DANGEROUS_CAPS):
                findings.append(self.finding("DC008", path, line_of(r"cap_add"), f"{label} adds capability {cap}."))

            for opt in svc.get("security_opt") or []:
                if "unconfined" in str(opt):
                    findings.append(self.finding("DC011", path, line_of(r"unconfined"), f"{label} sets `{opt}`."))

            deploy = svc.get("deploy") or {}
            if not svc.get("restart") and not (isinstance(deploy, dict) and deploy.get("restart_policy")):
                findings.append(self.finding("DC006", path, start, f"{label} has no restart policy."))

            limits = deploy.get("resources", {}).get("limits") if isinstance(deploy, dict) else None
            if not limits and not svc.get("mem_limit") and not svc.get("cpus"):
                findings.append(self.finding("DC007", path, start, f"{label} has no CPU/memory limits."))

            if "healthcheck" not in svc:
                findings.append(self.finding("DC009", path, start, f"{label} has no healthcheck."))

        return findings

    @staticmethod
    def _parse_port(port) -> tuple[str, str]:
        """Return (host_ip, container_port) for short or long port syntax."""
        if isinstance(port, dict):
            return str(port.get("host_ip", "")), str(port.get("target", "")).split("/")[0]
        spec = str(port).split("/")[0]
        if spec.startswith("["):  # IPv6 host ip, e.g. [::1]:5432:5432
            host_ip, _, rest = spec[1:].partition("]:")
            return host_ip, rest.split(":")[-1]
        parts = spec.split(":")
        if len(parts) == 3:
            return parts[0], parts[2]
        if len(parts) == 2:
            return "", parts[1]
        return "", parts[0]  # only container port -> random host port on all interfaces
