# 🤖 AI-based Configuration Reviewer

An **AI-powered DevOps configuration reviewer** written in Python. Point it at a file or a whole repository and it finds
**misconfigurations**, **security issues** and **best-practice violations** in your DevOps files, explains each problem,
and tells you how to fix it.

It works in two layers:

1. **Rule engine (offline, instant, free)**: 74 built-in checks across 6 file types. It needs no API key or network.
2. **AI deep review (optional, `--ai`)**: sends each file to **Claude** (Anthropic), which reads the whole file in
   context and reports what fixed rules can't see: risky combinations of settings, logic mistakes, missing pieces. It
   also writes a short summary of each file.

| Supported file | Detected by |
|---|---|
| 🐳 **Dockerfile** | `Dockerfile`, `Dockerfile.*`, `*.dockerfile` |
| 🧩 **docker-compose** | `docker-compose*.yml`, `compose*.yaml`, or any YAML with `services:` |
| ☸️ **Kubernetes manifests** | any YAML with `apiVersion` + `kind` (multi-document files supported) |
| ⚙️ **GitHub Actions** | files in `.github/workflows/`, or YAML with `on:` + `jobs:` |
| 🌍 **Terraform** | `*.tf` |
| 🔑 **.env files** | `.env`, `.env.*`, `*.env` |

All of them are also scanned for **hard-coded secrets**: AWS keys, private keys, GitHub/Slack/Stripe/Google/Anthropic
tokens, passwords, and credentials inside URLs.

---

## 📑 Table of contents

1. [Quick start](#-quick-start)
2. [How it works](#-how-it-works)
3. [Usage](#-usage)
4. [Enabling the AI review](#-enabling-the-ai-review)
5. [Output formats & score](#-output-formats--score)
6. [Built-in rules](#-built-in-rules)
7. [Using it in CI/CD](#-using-it-in-cicd)
8. [Project structure](#-project-structure)
9. [Adding your own rule](#-adding-your-own-rule)
10. [Running the tests](#-running-the-tests)
11. [FAQ](#-faq)

---

## 🚀 Quick start

```bash
# 1. Get the code (from GitHub, or unzip the provided archive)
git clone https://github.com/adi-2602/AI-based-configuration-Reviewer.git
cd AI-based-configuration-Reviewer

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install
pip install -r requirements.txt     # or: pip install -e ".[ai]"

# 4. Review the deliberately insecure examples
python -m config_reviewer examples/insecure

# 5. ...and the hardened versions of the same files (no issues)
python -m config_reviewer examples/secure
```

Requires **Python 3.10+**. After `pip install -e .` you can also use the short command `config-reviewer`.

Example output (shortened):

```text
examples/insecure/Dockerfile  [dockerfile]
     -   HIGH      DF002 Container runs as root
         No USER instruction in the final stage, so the container runs as root.
         ↳ Fix: Create an unprivileged user and switch to it with `USER appuser` before CMD/ENTRYPOINT.
     L2  MEDIUM    DF001 Base image is not pinned
         Base image 'python:latest' is latest; builds are not reproducible and may pull unexpected changes.
         ↳ Fix: Pin the base image to a specific version tag (e.g. python:3.12-slim) or, better, a sha256 digest.
     L5  CRITICAL  SEC004 Hard-coded password or secret
         `DB_PASSWORD` has a hard-coded value: ENV DB_PASSWORD=Supe********
         ↳ Fix: Remove the secret from the file, rotate it immediately (it is in git history), ...
    L14  HIGH      DF005 Piping a remote script into a shell
         Remote script piped directly into a shell.
         ↳ Fix: Download the script, verify its checksum/signature, then execute it.

Summary: 6 file(s) reviewed, 78 finding(s): 16 critical, 22 high, 13 medium, 21 low, 6 info
Score:   0/100 (grade F)
```

Full sample reports are in [`docs/sample-output.txt`](docs/sample-output.txt) and
[`docs/sample-report.md`](docs/sample-report.md).

---

## 🧠 How it works

```
                 ┌──────────────────┐
  paths ───────▶ │  detector.py     │  walks directories, decides each file's type
                 └────────┬─────────┘  (by file name first, then by sniffing YAML content)
                          ▼
                 ┌──────────────────┐
                 │  reviewer.py     │  orchestrates everything for each file
                 └───┬──────────┬───┘
                     │          │
        (always)     ▼          ▼   (only with --ai)
   ┌─────────────────────┐  ┌─────────────────────────┐
   │ analyzers/*         │  │ ai_reviewer.py          │
   │  rule engine:       │  │  sends file + the rule  │
   │  Dockerfile,        │─▶│  findings to Claude and │
   │  Compose, K8s, GHA, │  │  asks only for issues   │
   │  Terraform, Secrets │  │  the rules MISSED       │
   └─────────┬───────────┘  └───────────┬─────────────┘
             └──────────┬───────────────┘
                        ▼
              ┌──────────────────┐
              │  models.py       │  Finding / FileReport / ReviewResult + score & grade
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  reporters.py    │  text · json · markdown · sarif
              └──────────────────┘
```

**Step by step:**

1. **Detection.** `detector.py` maps every file to a type (`dockerfile`, `docker-compose`, `kubernetes`,
   `github-actions`, `terraform`, `env`). Unsupported files are skipped.
2. **Static analysis.** Each analyzer in `config_reviewer/analyzers/` parses its file type and runs its checks:
   - Dockerfiles go through a small instruction parser that understands line continuations and multi-stage builds.
   - YAML files are parsed with PyYAML. Kubernetes multi-document files are split so every finding points to the right line.
   - Terraform is read with a lightweight block-aware HCL scanner, so there are no heavy dependencies.
   - The **secrets** analyzer runs on every file and masks secret values in its output, so the report never leaks them.
3. **AI review (optional).** `ai_reviewer.py` sends Claude the file with line numbers, plus the issues the rules already
   found, and asks for *additional* issues only. The response is constrained to a strict JSON schema (structured
   outputs), so it always parses into the same `Finding` objects as the rule engine. AI findings are tagged `(AI)` and get
   IDs like `AI001`.
4. **Scoring & reporting.** All findings are merged and sorted, then a 0–100 health score and an A–F grade are computed.
   The report is printed in the format you chose.

---

## 🛠 Usage

```text
config-reviewer [PATHS ...] [options]

positional arguments:
  paths                    Files or directories to review

options:
  -f, --format {text,json,markdown,sarif}   Output format (default: text)
  -o, --output FILE                         Write report to a file instead of stdout
  --ai                                      Also run the AI deep review with Claude
  --model MODEL                             Claude model for --ai (default: claude-opus-5-5)
  --effort {low,medium,high,xhigh,max}      How hard the AI should think (default: high)
  --min-severity LEVEL                      Hide findings below this severity (default: info)
  --fail-on LEVEL|never                     Exit 1 if any finding >= LEVEL (default: high)
  --no-color                                Disable colors
  --list-rules                              Print every built-in rule and exit
  --version                                 Show version
```

Common examples:

```bash
# Review the current repository
python -m config_reviewer .

# Review one file, only show HIGH and CRITICAL problems
python -m config_reviewer k8s/deployment.yaml --min-severity high

# Generate a Markdown report you can attach to a PR
python -m config_reviewer . -f markdown -o review.md --fail-on never

# Machine-readable JSON
python -m config_reviewer . -f json > review.json

# See every rule the tool knows about
python -m config_reviewer --list-rules
```

**Exit codes:** `0` means OK, `1` means at least one finding at or above `--fail-on`, and `2` means a path was not found.
This lets you use the tool as a CI gate.

---

## ✨ Enabling the AI review

The AI layer uses the official [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python) and
the Claude model **`claude-opus-5-5`** by default.

```bash
pip install anthropic                     # already included in requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."     # Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."

python -m config_reviewer examples/insecure --ai
```

Get an API key at <https://console.anthropic.com/>. Without a key (or without the package), the tool prints a warning
and continues with the rule engine only, so it never crashes.

What the AI adds on top of the rules:

- **Context-aware findings**, for example: "the readiness probe hits port 8080 but the container listens on 3000", "this
  CronJob's `concurrencyPolicy: Allow` can run overlapping database migrations", or "the workflow deploys on every
  branch push".
- **A per-file summary** of overall quality and the most important fix.
- **No duplicates**: the rule findings are passed in and the model is told not to repeat them.

Implementation notes (see `config_reviewer/ai_reviewer.py`):

- **Structured outputs** (`output_config.format` with a JSON schema) guarantee machine-parseable responses.
- **`effort`** controls how deeply Claude reasons. Use `--effort medium` for faster, cheaper runs and `xhigh` for the
  most thorough review.
- **Refusal fallback**: the request opts into server-side fallbacks (`fallbacks="default"`). If a safety classifier
  declines a request, the API retries it on a recommended fallback model instead of failing.
- **Error handling**: authentication, permission, rate-limit, API and network errors are handled separately. A bad key
  disables AI for the rest of the run, while a one-off error only skips that file.

> 💡 **Cost tip:** AI review sends file contents to the Anthropic API. It is billed per token, so run it on the files you
> care about, or use `--effort medium`. **Don't** send files containing real secrets. Rotate those first, which the rule
> engine will tell you to do anyway.

---

## 📊 Output formats & score

| Format | Use it for |
|---|---|
| `text` (default) | Humans in a terminal (colored when attached to a TTY; respects `NO_COLOR`) |
| `json` | Scripts, dashboards, further processing |
| `markdown` | PR comments, wiki pages, reports (see `docs/sample-report.md`) |
| `sarif` | GitHub **Code Scanning** / any SARIF viewer: findings show up inline in PRs |

**Severity levels:** `CRITICAL` › `HIGH` › `MEDIUM` › `LOW` › `INFO`

**Health score:** start at 100 and subtract per finding: critical −25, high −10, medium −5, low −2, info 0
(minimum 0). Grades: **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 40 · **F** below 40.

---

## 📋 Built-in rules

Run `python -m config_reviewer --list-rules` for the live list (also saved in [`docs/rules.txt`](docs/rules.txt)).

<details>
<summary><b>🐳 Dockerfile (DF001–DF017)</b></summary>

| ID | Severity | Check |
|---|---|---|
| DF001 | MEDIUM | Base image untagged or `:latest` |
| DF002 | HIGH | No `USER` / runs as root in the final stage |
| DF003 | LOW | `ADD` used where `COPY` is enough |
| DF004 | MEDIUM | `ADD` downloading a remote URL |
| DF005 | HIGH | `curl … \| sh` |
| DF006 | LOW | No `HEALTHCHECK` |
| DF007 | MEDIUM | `sudo` in `RUN` |
| DF008 | HIGH | `EXPOSE 22` |
| DF009 | HIGH | `chmod 777` |
| DF010 | LOW | `apt-get install` without `--no-install-recommends` |
| DF011 | LOW | apt lists not removed |
| DF012 | MEDIUM | `apt-get update` in its own layer |
| DF013 | LOW | `pip install` without `--no-cache-dir` |
| DF014 | LOW | Multiple `CMD`/`ENTRYPOINT` in the final stage |
| DF015 | INFO | Deprecated `MAINTAINER` |
| DF016 | LOW | Shell-form `CMD`/`ENTRYPOINT` (signals not forwarded) |
| DF017 | LOW | Relative `WORKDIR` |
</details>

<details>
<summary><b>🧩 docker-compose (DC001–DC012)</b></summary>

| ID | Severity | Check |
|---|---|---|
| DC001 | CRITICAL | `privileged: true` |
| DC002 | MEDIUM | Image untagged or `:latest` |
| DC003 | HIGH | `network_mode: host` |
| DC004 | CRITICAL | `/var/run/docker.sock` mounted |
| DC005 | HIGH | Database port published on all interfaces |
| DC006 | LOW | No restart policy |
| DC007 | LOW | No CPU/memory limits |
| DC008 | HIGH | Dangerous `cap_add` (SYS_ADMIN, ALL, …) |
| DC009 | INFO | No healthcheck |
| DC010 | INFO | Obsolete `version:` key |
| DC011 | HIGH | `seccomp/apparmor:unconfined` |
| DC012 | HIGH | Sensitive host path mounted (`/`, `/etc`, `/root`, …) |
</details>

<details>
<summary><b>☸️ Kubernetes (K8S001–K8S017)</b></summary>

| ID | Severity | Check |
|---|---|---|
| K8S001 | CRITICAL | Privileged container |
| K8S002 | HIGH | May run as root / `runAsUser: 0` |
| K8S003 | MEDIUM | `allowPrivilegeEscalation` not false |
| K8S004 | MEDIUM | No resource limits |
| K8S005 | LOW | No resource requests |
| K8S006 | MEDIUM | Image untagged or `:latest` |
| K8S007 | LOW | Missing liveness/readiness probes |
| K8S008 | HIGH | `hostNetwork` / `hostPID` / `hostIPC` |
| K8S009 | HIGH | `hostPath` volume |
| K8S010 | LOW | Writable root filesystem |
| K8S011 | HIGH | Dangerous capability added |
| K8S012 | LOW | Capabilities not dropped (`drop: [ALL]`) |
| K8S013 | INFO | Workload in `default` namespace |
| K8S014 | LOW | Single replica Deployment/StatefulSet |
| K8S015 | MEDIUM | `Secret` manifest with data committed |
| K8S016 | INFO | `LoadBalancer` / `NodePort` Service |
| K8S017 | LOW | Default service-account token auto-mounted |
</details>

<details>
<summary><b>⚙️ GitHub Actions (GHA001–GHA011)</b></summary>

| ID | Severity | Check |
|---|---|---|
| GHA001 | MEDIUM | Action pinned to a tag instead of a commit SHA |
| GHA002 | HIGH | Action pinned to a branch (`@main`/`@master`) |
| GHA003 | MEDIUM | No `permissions:` block |
| GHA004 | HIGH | `permissions: write-all` |
| GHA005 | HIGH | Script injection: untrusted `${{ github.event.* }}` inside `run:` |
| GHA006 | CRITICAL | `pull_request_target` checking out PR head code |
| GHA007 | LOW | Job without `timeout-minutes` |
| GHA008 | HIGH | `curl … \| bash` |
| GHA009 | HIGH | Secret echoed to the log |
| GHA010 | MEDIUM | Self-hosted runner on PR triggers |
| GHA011 | LOW | `actions/checkout` without `persist-credentials: false` |
</details>

<details>
<summary><b>🌍 Terraform (TF001–TF012)</b></summary>

| ID | Severity | Check |
|---|---|---|
| TF001 | HIGH | Ingress from `0.0.0.0/0` |
| TF002 | CRITICAL | SSH/RDP/DB port open to the internet |
| TF003 | CRITICAL | Public S3 ACL |
| TF004 | HIGH | Encryption disabled |
| TF005 | HIGH | `publicly_accessible` / public IP |
| TF006 | MEDIUM | `deletion_protection = false` |
| TF007 | LOW | `skip_final_snapshot = true` |
| TF008 | HIGH | Wildcard IAM `Action: "*"` |
| TF009 | LOW | No `required_providers` version pinning |
| TF010 | MEDIUM | Plain HTTP load-balancer listener |
| TF011 | LOW | Logging disabled |
| TF012 | MEDIUM | EC2 IMDSv2 not enforced |
</details>

<details>
<summary><b>🔑 Secrets (SEC001–SEC005), all file types</b></summary>

| ID | Severity | Check |
|---|---|---|
| SEC001 | CRITICAL | AWS access key ID |
| SEC002 | CRITICAL | Private key block |
| SEC003 | CRITICAL | GitHub / Slack / Stripe / Google / Anthropic token |
| SEC004 | CRITICAL | Hard-coded `password`, `secret`, `api_key`, `token`, … |
| SEC005 | CRITICAL | Credentials inside a URL (`scheme://user:pass@host`) |

References such as `${DB_PASSWORD}`, `*_FILE`, `secretKeyRef`, `var.x` and placeholders like `changeme` are ignored.
</details>

---

## 🔄 Using it in CI/CD

### GitHub Actions: fail the build on HIGH+ issues and upload SARIF

```yaml
name: Config review
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  review:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/adi-2602/AI-based-configuration-Reviewer.git
      - name: Review configs
        run: config-reviewer . -f sarif -o results.sarif --fail-on high
      - name: Upload to GitHub code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

To add the AI review in CI, store your key as a repository secret and add
`env: ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}` plus `--ai` to the review step.

### pre-commit / local git hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
python -m config_reviewer . --min-severity high --fail-on high
```

---

## 📁 Project structure

```
AI-based-configuration-Reviewer/
├── config_reviewer/              # the Python package
│   ├── __init__.py               # version
│   ├── __main__.py               # enables `python -m config_reviewer`
│   ├── cli.py                    # argument parsing, exit codes
│   ├── detector.py               # file discovery + file-type detection
│   ├── reviewer.py               # orchestrates rules + AI for each file
│   ├── ai_reviewer.py            # Claude integration (prompt, JSON schema, error handling)
│   ├── models.py                 # Severity, Rule, Finding, FileReport, ReviewResult (score/grade)
│   ├── reporters.py              # text / json / markdown / sarif output
│   └── analyzers/
│       ├── __init__.py           # analyzer registry
│       ├── base.py               # Analyzer base class + helpers (line lookup, image tag check)
│       ├── dockerfile.py         # DF rules
│       ├── compose.py            # DC rules
│       ├── kubernetes.py         # K8S rules
│       ├── github_actions.py     # GHA rules
│       ├── terraform.py          # TF rules
│       └── secrets.py            # SEC rules (runs on every file)
├── examples/
│   ├── insecure/                 # deliberately broken files: try the tool on these
│   └── secure/                   # hardened versions: should produce no findings
├── tests/                        # pytest suite (30 tests, AI layer tested with a fake client)
├── docs/                         # sample outputs + rule list
├── .github/workflows/tests.yml   # CI for this repo
├── pyproject.toml                # packaging + `config-reviewer` command
├── requirements.txt / requirements-dev.txt
└── LICENSE (MIT)
```

---

## 🧩 Adding your own rule

Example: flag Dockerfiles that use `ENV DEBUG=true`.

1. Open `config_reviewer/analyzers/dockerfile.py` and add a `Rule` to the `rules = rule_table(...)` list:

   ```python
   Rule("DF018", "Debug mode enabled", Severity.MEDIUM, Category.SECURITY,
        "Do not ship images with debug mode on; set it at runtime only for development."),
   ```

2. Add the check inside `analyze()`:

   ```python
   elif kw == "ENV" and re.search(r"\bDEBUG\s*=\s*(1|true)\b", args, re.I):
       findings.append(self.finding("DF018", path, ins.line, "DEBUG is enabled in the image."))
   ```

3. Add a test in `tests/test_analyzers.py` and run `pytest`.

**New file type?** Create `analyzers/my_tool.py` with a subclass of `Analyzer` (set `name`, `file_types`, `rules`,
implement `analyze(path, text)`), add a type constant and detection logic in `detector.py`, and register the
analyzer in `analyzers/__init__.py`.

---

## 🧪 Running the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The AI tests use a fake Anthropic client, so they need **no API key and no network**.

---

## ❓ FAQ

**Does it send my files anywhere?**
Only when you pass `--ai`. Then each file's content goes to the Anthropic API. Without `--ai`, everything runs locally.

**Why does it report a finding I consider acceptable?**
Use `--min-severity` to hide low-priority classes, or adjust or remove the rule in `analyzers/`. Every rule is a few
lines of plain Python.

**Why are some lines shown as `-`?**
Those findings are about the whole file (e.g. "no HEALTHCHECK anywhere"), so there is no single line to point at.

**This repo's own `tests.yml` gets GHA001 findings. Why?**
On purpose: it uses readable tags (`@v4`) to keep the example approachable. Pinning to commit SHAs is the stricter
production practice the rule recommends.

**Is the Terraform parser complete?**
No. It's a lightweight scanner for the common resource shapes, chosen to avoid heavy dependencies. Use it alongside
`terraform validate` and `tflint`. The `--ai` review covers many cases the regex rules can't.

---

## 📜 License

MIT. See [LICENSE](LICENSE).
