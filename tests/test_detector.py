from config_reviewer.detector import (COMPOSE, DOCKERFILE, ENV, GITHUB_ACTIONS, KUBERNETES, TERRAFORM, UNKNOWN,
                                      detect_file_type, discover_files)

from .conftest import EXAMPLES


def test_detect_by_name():
    assert detect_file_type("Dockerfile") == DOCKERFILE
    assert detect_file_type("api.dockerfile") == DOCKERFILE
    assert detect_file_type("Dockerfile.prod") == DOCKERFILE
    assert detect_file_type("main.tf") == TERRAFORM
    assert detect_file_type(".env") == ENV
    assert detect_file_type("docker-compose.prod.yml", "services: {}") == COMPOSE
    assert detect_file_type(".github/workflows/ci.yml", "x: 1") == GITHUB_ACTIONS
    assert detect_file_type("README.md") == UNKNOWN


def test_detect_by_content():
    assert detect_file_type("app.yaml", "apiVersion: v1\nkind: Pod\n") == KUBERNETES
    assert detect_file_type("build.yml", "on: push\njobs:\n  a: {}\n") == GITHUB_ACTIONS
    assert detect_file_type("stack.yml", "services:\n  web:\n    image: nginx:1\n") == COMPOSE
    assert detect_file_type("random.yml", "foo: bar\n") == UNKNOWN
    assert detect_file_type("broken.yml", "a: [\n") == UNKNOWN


def test_discover_examples():
    files = discover_files([str(EXAMPLES / "insecure")])
    names = {f.name for f in files}
    assert {"Dockerfile", "docker-compose.yml", "deployment.yaml", "main.tf", ".env", "ci.yml"} <= names
