"""Rules for Terraform (HCL) files.

HCL is parsed with lightweight block-aware regular expressions so the tool has
no heavy dependencies. It handles the common, flat resource shapes well.
"""

from __future__ import annotations

import re

from ..detector import TERRAFORM
from ..models import Category, Finding, Rule, Severity
from .base import Analyzer, rule_table

BLOCK_START = re.compile(r'^\s*(resource|data|module|provider|terraform)\s*("[^"]*"\s*)*\{')
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server",
                   6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}


def split_blocks(text: str) -> list[tuple[str, int, int, str]]:
    """Return (header, start_line, end_line, body) for top-level blocks."""
    blocks, lines = [], text.splitlines()
    i = 0
    while i < len(lines):
        if BLOCK_START.match(lines[i]):
            depth, j = 0, i
            while j < len(lines):
                code = re.sub(r'"(\\.|[^"\\])*"', '""', lines[j].split("#")[0])
                depth += code.count("{") - code.count("}")
                if depth <= 0:
                    break
                j += 1
            blocks.append((lines[i].strip(), i + 1, j + 1, "\n".join(lines[i:j + 1])))
            i = j + 1
        else:
            i += 1
    return blocks


class TerraformAnalyzer(Analyzer):
    name = "terraform"
    file_types = (TERRAFORM,)
    rules = rule_table(
        Rule("TF001", "Ingress open to the whole internet", Severity.HIGH, Category.SECURITY,
             "Restrict cidr_blocks to known IP ranges; put admin access behind a VPN/bastion or SSM."),
        Rule("TF002", "Sensitive port open to the internet", Severity.CRITICAL, Category.SECURITY,
             "Never expose SSH/RDP/database ports to 0.0.0.0/0."),
        Rule("TF003", "Public S3 bucket ACL", Severity.CRITICAL, Category.SECURITY,
             "Use `acl = \"private\"` and an aws_s3_bucket_public_access_block with all four settings true."),
        Rule("TF004", "Encryption disabled", Severity.HIGH, Category.SECURITY,
             "Enable encryption at rest (encrypted / storage_encrypted = true) with a KMS key."),
        Rule("TF005", "Resource is publicly accessible", Severity.HIGH, Category.SECURITY,
             "Set publicly_accessible / associate_public_ip_address = false and reach the resource through private networking (VPN, bastion, load balancer)."),
        Rule("TF006", "Deletion protection disabled", Severity.MEDIUM, Category.RELIABILITY,
             "Set deletion_protection = true for production data stores."),
        Rule("TF007", "Final snapshot skipped", Severity.LOW, Category.RELIABILITY,
             "Set skip_final_snapshot = false and a final_snapshot_identifier."),
        Rule("TF008", "Wildcard IAM policy", Severity.HIGH, Category.SECURITY,
             "Follow least privilege: list explicit actions and resources instead of \"*\"."),
        Rule("TF009", "Provider versions not pinned", Severity.LOW, Category.BEST_PRACTICE,
             "Add a terraform { required_providers { ... version = \"~> x.y\" } } block."),
        Rule("TF010", "Plain HTTP listener", Severity.MEDIUM, Category.SECURITY,
             "Use HTTPS listeners with a TLS certificate and redirect HTTP to HTTPS."),
        Rule("TF011", "Logging disabled", Severity.LOW, Category.SECURITY,
             "Enable access/audit logging so incidents can be investigated."),
        Rule("TF012", "Instance metadata v1 allowed", Severity.MEDIUM, Category.SECURITY,
             "Set metadata_options { http_tokens = \"required\" } to enforce IMDSv2."),
    )

    def analyze(self, path: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        blocks = split_blocks(text)

        for header, start, _end, body in blocks:
            label = " ".join(re.findall(r'"([^"]*)"', header)) or header.split()[0]
            body_lines = body.splitlines()

            def at(pattern, _start=start, _lines=body_lines):
                rx = re.compile(pattern, re.IGNORECASE)
                for offset, line in enumerate(_lines):
                    if rx.search(line.split("#")[0]):
                        return _start + offset
                return None

            if "0.0.0.0/0" in body or "::/0" in body:
                findings.extend(self._open_ingress(path, label, body, at))

            if m := re.search(r'\bacl\s*=\s*"(public-read|public-read-write|authenticated-read)"', body):
                findings.append(self.finding("TF003", path, at(r"\bacl\s*="), f"{label} uses ACL '{m.group(1)}'."))

            for key in ("encrypted", "storage_encrypted", "enable_encryption"):
                if re.search(rf"\b{key}\s*=\s*false\b", body):
                    findings.append(self.finding("TF004", path, at(rf"\b{key}\s*="), f"{label} sets {key} = false."))

            if re.search(r"\bpublicly_accessible\s*=\s*true\b", body):
                findings.append(self.finding("TF005", path, at(r"publicly_accessible"), f"{label} is publicly accessible."))
            if re.search(r"\bassociate_public_ip_address\s*=\s*true\b", body):
                findings.append(self.finding("TF005", path, at(r"associate_public_ip_address"),
                                             f"{label} gets a public IP address."))

            if re.search(r"\bdeletion_protection\s*=\s*false\b", body):
                findings.append(self.finding("TF006", path, at(r"deletion_protection"), f"{label} can be deleted accidentally."))

            if re.search(r"\bskip_final_snapshot\s*=\s*true\b", body):
                findings.append(self.finding("TF007", path, at(r"skip_final_snapshot"), f"{label} skips the final snapshot."))

            if (re.search(r'"Action"\s*[:=]\s*(\[\s*)?"\*"', body) or re.search(r'\bactions\s*=\s*\[\s*"\*"\s*\]', body)):
                findings.append(self.finding("TF008", path, at(r'(Action"?|actions)\s*[:=]'),
                                             f"{label} grants all actions (\"*\")."))

            if header.startswith("resource") and re.search(r'"aws_(lb|alb)_listener"', header):
                if re.search(r'\bprotocol\s*=\s*"HTTP"', body) and "redirect" not in body:
                    findings.append(self.finding("TF010", path, at(r"protocol"), f"{label} serves plain HTTP."))

            if re.search(r"\b(enable_logging|logging_enabled)\s*=\s*false\b", body):
                findings.append(self.finding("TF011", path, at(r"logging"), f"{label} disables logging."))

            if re.search(r'"aws_instance"|"aws_launch_template"', header):
                if not re.search(r'http_tokens\s*=\s*"required"', body):
                    findings.append(self.finding("TF012", path, start, f"{label} does not enforce IMDSv2."))

        has_provider = any(h.startswith("provider") for h, *_ in blocks) or re.search(r'^\s*resource\s+"', text, re.M)
        if has_provider and "required_providers" not in text:
            findings.append(self.finding("TF009", path, None, "No required_providers block with version constraints."))
        return findings

    def _open_ingress(self, path, label, body, at) -> list[Finding]:
        """Look at each ingress rule (or ingress-type security group rule) that allows 0.0.0.0/0."""
        out = []
        if "egress" in label.lower() or re.search(r'\btype\s*=\s*"egress"', body):
            return out
        segments = re.split(r"\bingress\s*\{", body)
        candidates = segments[1:] if len(segments) > 1 else [body]
        for seg in candidates:
            if "0.0.0.0/0" not in seg and "::/0" not in seg:
                continue
            ports = self._port_range(seg)
            exposed = [name for port, name in SENSITIVE_PORTS.items() if ports and ports[0] <= port <= ports[1]]
            if exposed:
                out.append(self.finding("TF002", path, at(r"0\.0\.0\.0/0|::/0"),
                                        f"{label} exposes {', '.join(exposed)} to the internet."))
            else:
                rng = f"ports {ports[0]}-{ports[1]}" if ports else "traffic"
                out.append(self.finding("TF001", path, at(r"0\.0\.0\.0/0|::/0"), f"{label} allows {rng} from 0.0.0.0/0."))
        return out

    @staticmethod
    def _port_range(seg: str):
        fp = re.search(r"\bfrom_port\s*=\s*(-?\d+)", seg)
        tp = re.search(r"\bto_port\s*=\s*(-?\d+)", seg)
        if not fp or not tp:
            return None
        lo, hi = int(fp.group(1)), int(tp.group(1))
        if lo <= 0 and hi <= 0:  # protocol -1 => all ports
            return (0, 65535)
        return (lo, hi)
