from config_reviewer.reviewer import review_text


def ids(path, text):
    return {f.rule_id for f in review_text(path, text).findings}


# ---------------------------------------------------------------- Dockerfile
def test_dockerfile_bad():
    text = """FROM ubuntu
RUN apt-get update
RUN curl https://x.sh | sh
ADD app /app
CMD python app.py
"""
    found = ids("Dockerfile", text)
    assert {"DF001", "DF002", "DF003", "DF005", "DF006", "DF012", "DF016"} <= found


def test_dockerfile_good():
    text = """FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
USER 10001
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
"""
    assert ids("Dockerfile", text) == set()


def test_dockerfile_multistage_alias_not_flagged():
    text = """FROM golang:1.23 AS build
RUN go build -o /app
FROM build AS test
FROM gcr.io/distroless/static:nonroot
COPY --from=build /app /app
USER nonroot
HEALTHCHECK NONE
ENTRYPOINT ["/app"]
"""
    found = ids("Dockerfile", text)
    assert "DF001" not in found and "DF002" not in found


def test_dockerfile_root_user_in_final_stage():
    text = "FROM alpine:3.20\nUSER root\nHEALTHCHECK CMD true\nCMD [\"sh\"]\n"
    assert "DF002" in ids("Dockerfile", text)


# ---------------------------------------------------------------- Compose
def test_compose_rules():
    text = """services:
  app:
    image: redis
    privileged: true
    ports:
      - "6379:6379"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
    assert {"DC001", "DC002", "DC004", "DC005", "DC006", "DC007"} <= ids("docker-compose.yml", text)


def test_compose_localhost_port_ok():
    text = 'services:\n  db:\n    image: postgres:16\n    ports: ["127.0.0.1:5432:5432"]\n'
    assert "DC005" not in ids("docker-compose.yml", text)


# ---------------------------------------------------------------- Kubernetes
POD = """apiVersion: v1
kind: Pod
metadata:
  name: demo
  namespace: apps
spec:
  containers:
    - name: c
      image: nginx
"""


def test_kubernetes_insecure_pod():
    found = ids("pod.yaml", POD)
    assert {"K8S002", "K8S003", "K8S004", "K8S005", "K8S006", "K8S007", "K8S010", "K8S012"} <= found
    assert "K8S013" not in found  # namespace is set


def test_kubernetes_line_numbers_point_into_document():
    report = review_text("pod.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n---\n" + POD)
    image = next(f for f in report.findings if f.rule_id == "K8S006")
    assert image.line == 13


def test_kubernetes_secret_manifest():
    text = "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\ndata:\n  password: cGFzcw==\n"
    assert "K8S015" in ids("secret.yaml", text)


# ---------------------------------------------------------------- GitHub Actions
def test_actions_rules():
    text = """on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: foo/bar@master
      - run: echo "${{ github.event.issue.body }}"
"""
    found = ids(".github/workflows/x.yml", text)
    assert {"GHA001", "GHA002", "GHA003", "GHA005", "GHA007", "GHA011"} <= found


def test_actions_sha_pinned_ok():
    text = """on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with: {persist-credentials: false}
"""
    assert ids(".github/workflows/x.yml", text) == set()


# ---------------------------------------------------------------- Terraform
def test_terraform_rules():
    text = """resource "aws_security_group" "sg" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "b" {
  acl = "public-read-write"
}
resource "aws_rds_cluster" "db" {
  storage_encrypted = false
}
"""
    found = ids("main.tf", text)
    assert {"TF002", "TF003", "TF004", "TF009"} <= found


def test_terraform_egress_not_flagged():
    text = """terraform { required_providers {} }
resource "aws_security_group_rule" "out" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
"""
    assert ids("main.tf", text) == set()


# ---------------------------------------------------------------- Secrets
def test_secrets_detected_and_masked():
    report = review_text(".env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter2hunter\n")
    found = {f.rule_id for f in report.findings}
    assert {"SEC001", "SEC004"} <= found
    assert all("hunter2hunter" not in f.message for f in report.findings)


def test_secret_references_ignored():
    text = "DB_PASSWORD=${DB_PASSWORD}\nPASSWORD_FILE=/run/secrets/db\nTOKEN=changeme\nAPI_KEY=\n"
    assert ids(".env", text) == set()


def test_invalid_yaml_reports_error():
    report = review_text("docker-compose.yml", "services:\n  web: [\n")
    assert report.error and "Invalid YAML" in report.error
