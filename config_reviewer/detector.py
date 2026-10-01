"""Figure out what kind of DevOps file we are looking at."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

DOCKERFILE = "dockerfile"
COMPOSE = "docker-compose"
KUBERNETES = "kubernetes"
GITHUB_ACTIONS = "github-actions"
TERRAFORM = "terraform"
ENV = "env"
UNKNOWN = "unknown"

ALL_TYPES = (DOCKERFILE, COMPOSE, KUBERNETES, GITHUB_ACTIONS, TERRAFORM, ENV)

YAML_SUFFIXES = {".yml", ".yaml"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", ".tox", "dist", "build"}

_COMPOSE_NAME = re.compile(r"^(docker-)?compose([.\-][\w.\-]+)?\.ya?ml$", re.IGNORECASE)


def _load_yaml_docs(text: str) -> list:
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError:
        return []


def detect_file_type(path: str | os.PathLike, text: str | None = None) -> str:
    """Return one of the type constants above (``UNKNOWN`` if not supported)."""
    p = Path(path)
    name = p.name
    lower = name.lower()

    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
        return DOCKERFILE
    if p.suffix.lower() == ".tf":
        return TERRAFORM
    if lower == ".env" or lower.startswith(".env.") or p.suffix.lower() == ".env":
        return ENV
    if p.suffix.lower() not in YAML_SUFFIXES:
        return UNKNOWN

    if _COMPOSE_NAME.match(name):
        return COMPOSE
    parts = [part.lower() for part in p.parts]
    if ".github" in parts and "workflows" in parts:
        return GITHUB_ACTIONS

    # Fall back to sniffing the YAML content.
    if text is None:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return UNKNOWN
    docs = [d for d in _load_yaml_docs(text) if isinstance(d, dict)]
    if not docs:
        return UNKNOWN
    if any("apiVersion" in d and "kind" in d for d in docs):
        return KUBERNETES
    first = docs[0]
    # PyYAML (YAML 1.1) parses the bare key `on:` as the boolean True.
    if "jobs" in first and ("on" in first or True in first):
        return GITHUB_ACTIONS
    if isinstance(first.get("services"), dict):
        return COMPOSE
    return UNKNOWN


def discover_files(paths: list[str]) -> list[Path]:
    """Expand files/directories into a sorted list of reviewable files."""
    found: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    candidate = Path(root) / name
                    if detect_file_type(candidate) != UNKNOWN:
                        found.append(candidate)
        else:
            raise FileNotFoundError(f"Path not found: {raw}")
    # De-duplicate while keeping order.
    seen, unique = set(), []
    for f in found:
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
