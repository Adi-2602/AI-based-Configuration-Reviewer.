"""Rules for Kubernetes manifests."""

from __future__ import annotations

import yaml

from ..detector import KUBERNETES
from ..models import Category, Finding, Rule, Severity
from .base import Analyzer, find_line, image_tag_problem, rule_table, yaml_documents

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW"}


def pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return (spec.get("template") or {}).get("spec")


class KubernetesAnalyzer(Analyzer):
    name = "kubernetes"
    file_types = (KUBERNETES,)
    rules = rule_table(
        Rule("K8S001", "Privileged container", Severity.CRITICAL, Category.SECURITY,
             "Set securityContext.privileged: false (or remove it)."),
        Rule("K8S002", "Container may run as root", Severity.HIGH, Category.SECURITY,
             "Set securityContext.runAsNonRoot: true and a non-zero runAsUser."),
        Rule("K8S003", "Privilege escalation allowed", Severity.MEDIUM, Category.SECURITY,
             "Set securityContext.allowPrivilegeEscalation: false."),
        Rule("K8S004", "No resource limits", Severity.MEDIUM, Category.RELIABILITY,
             "Set resources.limits.memory and resources.limits.cpu to protect the node from noisy neighbours."),
        Rule("K8S005", "No resource requests", Severity.LOW, Category.RELIABILITY,
             "Set resources.requests so the scheduler can place the pod correctly."),
        Rule("K8S006", "Image is not pinned", Severity.MEDIUM, Category.BEST_PRACTICE,
             "Use an explicit version tag or sha256 digest instead of :latest / no tag."),
        Rule("K8S007", "Missing liveness/readiness probe", Severity.LOW, Category.RELIABILITY,
             "Define livenessProbe and readinessProbe so Kubernetes can restart and route traffic correctly."),
        Rule("K8S008", "Host namespace shared", Severity.HIGH, Category.SECURITY,
             "Remove hostNetwork / hostPID / hostIPC unless absolutely required."),
        Rule("K8S009", "hostPath volume", Severity.HIGH, Category.SECURITY,
             "Avoid hostPath volumes; use PersistentVolumeClaims, ConfigMaps or emptyDir."),
        Rule("K8S010", "Writable root filesystem", Severity.LOW, Category.SECURITY,
             "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir for writable paths."),
        Rule("K8S011", "Dangerous capability added", Severity.HIGH, Category.SECURITY,
             "Remove broad capabilities; drop ALL and add back only what is needed."),
        Rule("K8S012", "Capabilities not dropped", Severity.LOW, Category.SECURITY,
             "Add securityContext.capabilities.drop: [\"ALL\"]."),
        Rule("K8S013", "Workload in the default namespace", Severity.INFO, Category.BEST_PRACTICE,
             "Deploy workloads into a dedicated namespace for isolation and RBAC."),
        Rule("K8S014", "Single replica", Severity.LOW, Category.RELIABILITY,
             "Run at least 2 replicas (and a PodDisruptionBudget) for high availability."),
        Rule("K8S015", "Secret committed in a manifest", Severity.MEDIUM, Category.SECURITY,
             "Do not commit Secret manifests with data. Use Sealed Secrets, SOPS, or an external secrets manager."),
        Rule("K8S016", "Service exposed externally", Severity.INFO, Category.SECURITY,
             "Prefer ClusterIP + Ingress with TLS; restrict LoadBalancer with loadBalancerSourceRanges."),
        Rule("K8S017", "Default service account token mounted", Severity.LOW, Category.SECURITY,
             "Set automountServiceAccountToken: false unless the pod talks to the Kubernetes API."),
    )

    def analyze(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for start, end in yaml_documents(text):
            chunk = "\n".join(lines[start - 1:end])
            try:
                doc = yaml.safe_load(chunk)
            except yaml.YAMLError as exc:
                raise ValueError(f"Invalid YAML near line {start}: {exc}") from exc
            if isinstance(doc, dict) and doc.get("kind"):
                findings.extend(self._check_document(path, text, doc, start, end))
        return findings

    def _check_document(self, path, text, doc, start, end) -> list[Finding]:
        out: list[Finding] = []
        kind = doc.get("kind")
        meta = doc.get("metadata") or {}
        name = f"{kind}/{meta.get('name', '<unnamed>')}"

        def line(pattern):
            return find_line(text, pattern, start, end) or start

        if kind == "Secret" and (doc.get("data") or doc.get("stringData")):
            out.append(self.finding("K8S015", path, line(r"^(data|stringData)\s*:"), f"{name} contains secret values."))

        if kind == "Service" and (doc.get("spec") or {}).get("type") in ("LoadBalancer", "NodePort"):
            out.append(self.finding("K8S016", path, line(r"type\s*:"),
                                    f"{name} is of type {(doc.get('spec') or {}).get('type')}."))

        if kind not in WORKLOAD_KINDS:
            return out

        if meta.get("namespace") in (None, "default"):
            out.append(self.finding("K8S013", path, line(r"^metadata\s*:"), f"{name} has no namespace (uses 'default')."))

        if kind in ("Deployment", "StatefulSet") and (doc.get("spec") or {}).get("replicas", 1) == 1:
            out.append(self.finding("K8S014", path, line(r"replicas\s*:"), f"{name} runs a single replica."))

        spec = pod_spec(doc) or {}
        pod_sc = spec.get("securityContext") or {}

        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(key) is True:
                out.append(self.finding("K8S008", path, line(rf"{key}\s*:"), f"{name} sets {key}: true."))

        for vol in spec.get("volumes") or []:
            if isinstance(vol, dict) and "hostPath" in vol:
                host = (vol.get("hostPath") or {}).get("path", "?")
                out.append(self.finding("K8S009", path, line(r"hostPath\s*:"),
                                        f"{name} mounts hostPath '{host}' (volume '{vol.get('name')}')."))

        if spec.get("automountServiceAccountToken") is not False and not spec.get("serviceAccountName"):
            out.append(self.finding("K8S017", path, line(r"^\s*spec\s*:"),
                                    f"{name} uses the default service account with its token auto-mounted."))

        containers = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])
        for c in containers:
            if not isinstance(c, dict):
                continue
            cname = c.get("name", "<unnamed>")
            label = f"{name} container '{cname}'"
            cline = find_line(text, rf"name\s*:\s*['\"]?{cname}['\"]?\s*$", start, end) or start

            def cl(pattern, _cline=cline):
                return find_line(text, pattern, _cline, end) or _cline

            sc = c.get("securityContext") or {}

            if sc.get("privileged") is True:
                out.append(self.finding("K8S001", path, cl(r"privileged\s*:"), f"{label} is privileged."))

            run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
            run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
            if run_as_user == 0:
                out.append(self.finding("K8S002", path, cl(r"runAsUser\s*:"), f"{label} explicitly runs as UID 0."))
            elif run_as_non_root is not True and not run_as_user:
                out.append(self.finding("K8S002", path, cline, f"{label} does not set runAsNonRoot: true."))

            if sc.get("allowPrivilegeEscalation") is not False:
                out.append(self.finding("K8S003", path, cline, f"{label} does not set allowPrivilegeEscalation: false."))

            if sc.get("readOnlyRootFilesystem") is not True:
                out.append(self.finding("K8S010", path, cline, f"{label} has a writable root filesystem."))

            caps = sc.get("capabilities") or {}
            added = {str(x).upper() for x in caps.get("add") or []}
            for cap in sorted(added & DANGEROUS_CAPS):
                out.append(self.finding("K8S011", path, cl(r"add\s*:"), f"{label} adds capability {cap}."))
            if "ALL" not in {str(x).upper() for x in caps.get("drop") or []}:
                out.append(self.finding("K8S012", path, cline, f"{label} does not drop ALL capabilities."))

            image = c.get("image", "")
            problem = image_tag_problem(image)
            if problem:
                out.append(self.finding("K8S006", path, cl(r"image\s*:"), f"{label} uses image '{image}' which is {problem}."))

            resources = c.get("resources") or {}
            if not resources.get("limits"):
                out.append(self.finding("K8S004", path, cline, f"{label} has no resource limits."))
            if not resources.get("requests"):
                out.append(self.finding("K8S005", path, cline, f"{label} has no resource requests."))

            if c in (spec.get("containers") or []) and kind not in ("Job", "CronJob"):
                missing = [p for p in ("livenessProbe", "readinessProbe") if p not in c]
                if missing:
                    out.append(self.finding("K8S007", path, cline, f"{label} is missing {', '.join(missing)}."))
        return out
