"""Static rule-based analyzers. Register new analyzers in ``ANALYZERS``."""

from .compose import ComposeAnalyzer
from .dockerfile import DockerfileAnalyzer
from .github_actions import GitHubActionsAnalyzer
from .kubernetes import KubernetesAnalyzer
from .secrets import SecretsAnalyzer
from .terraform import TerraformAnalyzer

ANALYZERS = [
    DockerfileAnalyzer(),
    ComposeAnalyzer(),
    KubernetesAnalyzer(),
    GitHubActionsAnalyzer(),
    TerraformAnalyzer(),
    SecretsAnalyzer(),
]


def analyzers_for(file_type: str):
    return [a for a in ANALYZERS if file_type in a.file_types]


def all_rules():
    return [rule for analyzer in ANALYZERS for rule in analyzer.rules.values()]


__all__ = ["ANALYZERS", "analyzers_for", "all_rules"]
