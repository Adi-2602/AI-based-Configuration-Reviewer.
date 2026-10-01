# Configuration Review Report

**Score:** 0/100 (grade **F**) · **Files:** 6 · **Findings:** 78

| Severity | Count |
|---|---|
| 🟥 CRITICAL | 16 |
| 🟧 HIGH | 22 |
| 🟨 MEDIUM | 13 |
| 🟦 LOW | 21 |
| ⬜ INFO | 6 |

## `examples/insecure/.env` (env)

| Line | Severity | Rule | Issue | Recommendation |
|---|---|---|---|---|
| 2 | 🟥 CRITICAL | `SEC005` | **Credentials in connection URL**<br>Possible credentials embedded in a connection URL: DATABASE_URL=post******** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 3 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`STRIPE_SECRET_KEY` has a hard-coded value: STRIPE_SECRET_KEY=demo******** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 4 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`JWT_SECRET` has a hard-coded value: JWT_SECRET=my-j******** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |

## `examples/insecure/Dockerfile` (dockerfile)

| Line | Severity | Rule | Issue | Recommendation |
|---|---|---|---|---|
| - | 🟧 HIGH | `DF002` | **Container runs as root**<br>No USER instruction in the final stage, so the container runs as root. | Create an unprivileged user and switch to it with `USER appuser` before CMD/ENTRYPOINT. |
| - | 🟦 LOW | `DF006` | **No HEALTHCHECK defined**<br>The image does not define a HEALTHCHECK. | Add a HEALTHCHECK so the orchestrator can detect and restart unhealthy containers. |
| 2 | 🟨 MEDIUM | `DF001` | **Base image is not pinned**<br>Base image 'python:latest' is latest; builds are not reproducible and may pull unexpected changes. | Pin the base image to a specific version tag (e.g. python:3.12-slim) or, better, a sha256 digest. |
| 3 | ⬜ INFO | `DF015` | **Deprecated MAINTAINER instruction**<br>MAINTAINER is deprecated. | Use `LABEL org.opencontainers.image.authors="..."` instead. |
| 5 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`DB_PASSWORD` has a hard-coded value: ENV DB_PASSWORD=Supe******** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 6 | 🟥 CRITICAL | `SEC001` | **AWS access key in file**<br>Possible AWS access key ID: ENV AWS_ACCESS_KEY_ID=AKIA******** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 8 | 🟦 LOW | `DF017` | **WORKDIR uses a relative path**<br>WORKDIR 'app' is relative. | Use an absolute path for WORKDIR (e.g. /app). |
| 9 | 🟦 LOW | `DF003` | **ADD used instead of COPY**<br>`ADD . /app` can be replaced with COPY. | Use COPY for local files. ADD has implicit tar-extraction and URL behaviour that is easy to misuse. |
| 10 | 🟨 MEDIUM | `DF004` | **Remote file downloaded with ADD**<br>ADD fetches a remote URL: https://example.com/install.sh /tmp/install.sh | Download with curl/wget inside RUN and verify a checksum, or use COPY with a vendored file. |
| 12 | 🟨 MEDIUM | `DF012` | **apt-get update in its own RUN**<br>`apt-get update` without an install in the same layer. | Combine `apt-get update && apt-get install ...` in a single RUN so the package index is never stale (layer cache). |
| 13 | 🟦 LOW | `DF010` | **apt-get install without --no-install-recommends**<br>apt-get install pulls in recommended packages. | Use `apt-get install -y --no-install-recommends` to keep the image small and reduce attack surface. |
| 13 | 🟦 LOW | `DF011` | **apt cache not cleaned**<br>Package lists are left in the image layer. | Finish the same RUN with `&& rm -rf /var/lib/apt/lists/*`. |
| 14 | 🟧 HIGH | `DF005` | **Piping a remote script into a shell**<br>Remote script piped directly into a shell. | Download the script, verify its checksum/signature, then execute it. Never `curl \| sh` untrusted content. |
| 15 | 🟧 HIGH | `DF009` | **World-writable permissions (chmod 777)**<br>chmod 777 makes files writable by every user. | Grant the minimum permissions needed (e.g. 755 for directories, 644 for files) and set ownership with --chown. |
| 15 | 🟨 MEDIUM | `DF007` | **sudo used in a RUN instruction**<br>`sudo` used during the build. | Build steps already run as root; drop sudo and avoid installing it in the image. |
| 16 | 🟦 LOW | `DF013` | **pip install without --no-cache-dir**<br>pip cache is stored in the image layer. | Use `pip install --no-cache-dir` to avoid shipping pip's cache in the image. |
| 18 | 🟧 HIGH | `DF008` | **SSH port exposed**<br>Port 22 (SSH) is exposed. | Do not run SSH inside containers. Use `docker exec` / `kubectl exec` for debugging. |
| 19 | 🟦 LOW | `DF016` | **Shell-form CMD/ENTRYPOINT**<br>CMD uses shell form; the process runs under /bin/sh -c and will not receive SIGTERM. | Use the JSON exec form, e.g. CMD ["python", "app.py"], so signals (SIGTERM) reach your process. |

## `examples/insecure/deployment.yaml` (kubernetes)

| Line | Severity | Rule | Issue | Recommendation |
|---|---|---|---|---|
| 3 | ⬜ INFO | `K8S013` | **Workload in the default namespace**<br>Deployment/payments-api has no namespace (uses 'default'). | Deploy workloads into a dedicated namespace for isolation and RBAC. |
| 5 | 🟦 LOW | `K8S017` | **Default service account token mounted**<br>Deployment/payments-api uses the default service account with its token auto-mounted. | Set automountServiceAccountToken: false unless the pod talks to the Kubernetes API. |
| 6 | 🟦 LOW | `K8S014` | **Single replica**<br>Deployment/payments-api runs a single replica. | Run at least 2 replicas (and a PodDisruptionBudget) for high availability. |
| 15 | 🟧 HIGH | `K8S008` | **Host namespace shared**<br>Deployment/payments-api sets hostNetwork: true. | Remove hostNetwork / hostPID / hostIPC unless absolutely required. |
| 17 | 🟨 MEDIUM | `K8S003` | **Privilege escalation allowed**<br>Deployment/payments-api container 'api' does not set allowPrivilegeEscalation: false. | Set securityContext.allowPrivilegeEscalation: false. |
| 17 | 🟨 MEDIUM | `K8S004` | **No resource limits**<br>Deployment/payments-api container 'api' has no resource limits. | Set resources.limits.memory and resources.limits.cpu to protect the node from noisy neighbours. |
| 17 | 🟦 LOW | `K8S010` | **Writable root filesystem**<br>Deployment/payments-api container 'api' has a writable root filesystem. | Set securityContext.readOnlyRootFilesystem: true and mount emptyDir for writable paths. |
| 17 | 🟦 LOW | `K8S012` | **Capabilities not dropped**<br>Deployment/payments-api container 'api' does not drop ALL capabilities. | Add securityContext.capabilities.drop: ["ALL"]. |
| 17 | 🟦 LOW | `K8S005` | **No resource requests**<br>Deployment/payments-api container 'api' has no resource requests. | Set resources.requests so the scheduler can place the pod correctly. |
| 17 | 🟦 LOW | `K8S007` | **Missing liveness/readiness probe**<br>Deployment/payments-api container 'api' is missing livenessProbe, readinessProbe. | Define livenessProbe and readinessProbe so Kubernetes can restart and route traffic correctly. |
| 18 | 🟨 MEDIUM | `K8S006` | **Image is not pinned**<br>Deployment/payments-api container 'api' uses image 'mycompany/payments-api:latest' which is latest. | Use an explicit version tag or sha256 digest instead of :latest / no tag. |
| 20 | 🟥 CRITICAL | `K8S001` | **Privileged container**<br>Deployment/payments-api container 'api' is privileged. | Set securityContext.privileged: false (or remove it). |
| 21 | 🟧 HIGH | `K8S002` | **Container may run as root**<br>Deployment/payments-api container 'api' explicitly runs as UID 0. | Set securityContext.runAsNonRoot: true and a non-zero runAsUser. |
| 23 | 🟧 HIGH | `K8S011` | **Dangerous capability added**<br>Deployment/payments-api container 'api' adds capability SYS_ADMIN. | Remove broad capabilities; drop ALL and add back only what is needed. |
| 31 | 🟧 HIGH | `K8S009` | **hostPath volume**<br>Deployment/payments-api mounts hostPath '/' (volume 'host-root'). | Avoid hostPath volumes; use PersistentVolumeClaims, ConfigMaps or emptyDir. |
| 39 | ⬜ INFO | `K8S016` | **Service exposed externally**<br>Service/payments-api is of type LoadBalancer. | Prefer ClusterIP + Ingress with TLS; restrict LoadBalancer with loadBalancerSourceRanges. |

## `examples/insecure/docker-compose.yml` (docker-compose)

| Line | Severity | Rule | Issue | Recommendation |
|---|---|---|---|---|
| 1 | ⬜ INFO | `DC010` | **Obsolete `version` key**<br>`version` is obsolete in the Compose Specification. | The Compose Specification ignores `version`; remove it. |
| 4 | 🟦 LOW | `DC006` | **No restart policy**<br>Service 'web' has no restart policy. | Set `restart: unless-stopped` (or deploy.restart_policy) so the service recovers from crashes. |
| 4 | 🟦 LOW | `DC007` | **No resource limits**<br>Service 'web' has no CPU/memory limits. | Set deploy.resources.limits (cpus/memory) to stop one service starving the host. |
| 4 | ⬜ INFO | `DC009` | **No healthcheck**<br>Service 'web' has no healthcheck. | Add a healthcheck so dependants can use `depends_on: condition: service_healthy`. |
| 5 | 🟨 MEDIUM | `DC002` | **Image is not pinned**<br>Service 'web' uses image 'nginx' which is untagged. | Pin images to an explicit version tag or sha256 digest. |
| 6 | 🟥 CRITICAL | `DC001` | **Privileged container**<br>Service 'web' runs privileged. | Remove `privileged: true`; grant only the specific capabilities the service needs with cap_add. |
| 7 | 🟧 HIGH | `DC003` | **Host network mode**<br>Service 'web' uses the host network. | Use the default bridge/user-defined networks and publish only required ports. |
| 9 | 🟥 CRITICAL | `DC004` | **Docker socket mounted into a container**<br>Service 'web' mounts /var/run/docker.sock. | Mounting /var/run/docker.sock gives the container root on the host. Remove it or use a socket proxy with an allow-list. |
| 11 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`API_KEY` has a hard-coded value: - API_KEY=demo******** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 13 | 🟦 LOW | `DC006` | **No restart policy**<br>Service 'db' has no restart policy. | Set `restart: unless-stopped` (or deploy.restart_policy) so the service recovers from crashes. |
| 13 | 🟦 LOW | `DC007` | **No resource limits**<br>Service 'db' has no CPU/memory limits. | Set deploy.resources.limits (cpus/memory) to stop one service starving the host. |
| 13 | ⬜ INFO | `DC009` | **No healthcheck**<br>Service 'db' has no healthcheck. | Add a healthcheck so dependants can use `depends_on: condition: service_healthy`. |
| 14 | 🟨 MEDIUM | `DC002` | **Image is not pinned**<br>Service 'db' uses image 'postgres:latest' which is latest. | Pin images to an explicit version tag or sha256 digest. |
| 16 | 🟧 HIGH | `DC005` | **Database port published on all interfaces**<br>Service 'db' publishes PostgreSQL port 5432 on all interfaces. | Do not publish database ports, or bind them to localhost ("127.0.0.1:5432:5432"). |
| 18 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`POSTGRES_PASSWORD` has a hard-coded value: POSTGRES_PASSWORD: admi**** | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 19 | 🟧 HIGH | `DC008` | **Dangerous Linux capability added**<br>Service 'db' adds capability SYS_ADMIN. | Remove broad capabilities like SYS_ADMIN/ALL; add only narrowly scoped ones. |
| 22 | 🟧 HIGH | `DC011` | **Security options disabled**<br>Service 'db' sets `seccomp:unconfined`. | Do not set seccomp/apparmor to `unconfined`. |

## `examples/insecure/main.tf` (terraform)

| Line | Severity | Rule | Issue | Recommendation |
|---|---|---|---|---|
| - | 🟦 LOW | `TF009` | **Provider versions not pinned**<br>No required_providers block with version constraints. | Add a terraform { required_providers { ... version = "~> x.y" } } block. |
| 3 | 🟥 CRITICAL | `SEC001` | **AWS access key in file**<br>Possible AWS access key ID: access_key = "AKIA********" | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 4 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`secret_key` has a hard-coded value: secret_key = "wJal********" | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 14 | 🟥 CRITICAL | `TF002` | **Sensitive port open to the internet**<br>aws_security_group web exposes SSH to the internet. | Never expose SSH/RDP/database ports to 0.0.0.0/0. |
| 14 | 🟧 HIGH | `TF001` | **Ingress open to the whole internet**<br>aws_security_group web allows ports 80-80 from 0.0.0.0/0. | Restrict cidr_blocks to known IP ranges; put admin access behind a VPN/bastion or SSM. |
| 27 | 🟥 CRITICAL | `TF003` | **Public S3 bucket ACL**<br>aws_s3_bucket data uses ACL 'public-read'. | Use `acl = "private"` and an aws_s3_bucket_public_access_block with all four settings true. |
| 34 | 🟥 CRITICAL | `SEC004` | **Hard-coded password or secret**<br>`password` has a hard-coded value: password            = "chan********" | Remove the secret from the file, rotate it immediately (it is in git history), and load it at runtime from a secret manager or CI secret store. |
| 35 | 🟧 HIGH | `TF005` | **Resource is publicly accessible**<br>aws_db_instance main is publicly accessible. | Set publicly_accessible / associate_public_ip_address = false and reach the resource through private networking (VPN, bastion, load balancer). |
| 36 | 🟧 HIGH | `TF004` | **Encryption disabled**<br>aws_db_instance main sets storage_encrypted = false. | Enable encryption at rest (encrypted / storage_encrypted = true) with a KMS key. |
| 37 | 🟦 LOW | `TF007` | **Final snapshot skipped**<br>aws_db_instance main skips the final snapshot. | Set skip_final_snapshot = false and a final_snapshot_identifier. |
| 38 | 🟨 MEDIUM | `TF006` | **Deletion protection disabled**<br>aws_db_instance main can be deleted accidentally. | Set deletion_protection = true for production data stores. |
| 47 | 🟧 HIGH | `TF008` | **Wildcard IAM policy**<br>aws_iam_policy admin grants all actions ("*"). | Follow least privilege: list explicit actions and resources instead of "*". |
| 53 | 🟨 MEDIUM | `TF012` | **Instance metadata v1 allowed**<br>aws_instance app does not enforce IMDSv2. | Set metadata_options { http_tokens = "required" } to enforce IMDSv2. |
| 56 | 🟧 HIGH | `TF005` | **Resource is publicly accessible**<br>aws_instance app gets a public IP address. | Set publicly_accessible / associate_public_ip_address = false and reach the resource through private networking (VPN, bastion, load balancer). |

## `examples/insecure/.github/workflows/ci.yml` (github-actions)

| Line | Severity | Rule | Issue | Recommendation |
|---|---|---|---|---|
| 7 | 🟧 HIGH | `GHA004` | **Overly broad GITHUB_TOKEN permissions**<br>permissions: write-all | Replace `write-all` with the minimal per-scope permissions. |
| 10 | 🟦 LOW | `GHA007` | **Job has no timeout**<br>Job 'build' has no timeout-minutes. | Set `timeout-minutes` so hung jobs do not burn runner minutes for 6 hours. |
| 11 | 🟨 MEDIUM | `GHA010` | **Self-hosted runner on a public trigger**<br>Job 'build' runs PR code on a self-hosted runner. | Avoid self-hosted runners for pull_request workflows from forks; use ephemeral, isolated runners. |
| 13 | 🟥 CRITICAL | `GHA006` | **pull_request_target checks out untrusted code**<br>Checks out `${{ github.event.pull_request.head.sha }}` in a pull_request_target workflow. | Do not check out the PR head in pull_request_target workflows, or split into a pull_request + workflow_run pair. |
| 13 | 🟨 MEDIUM | `GHA001` | **Third-party action not pinned to a commit SHA**<br>`actions/checkout@v4` is pinned to a tag, which can be moved. | Pin actions to a full 40-character commit SHA (add the version as a comment), e.g. uses: org/action@<sha> # v4. |
| 13 | 🟦 LOW | `GHA011` | **Credentials persisted by actions/checkout**<br>actions/checkout keeps the token in .git/config. | Set `persist-credentials: false` on actions/checkout unless later steps need to push. |
| 16 | 🟧 HIGH | `GHA002` | **Action pinned to a mutable branch**<br>`some-org/deploy-action@main` follows a mutable branch. | Never reference @main/@master; anyone with push access to that repo can change what runs in your CI. |
| 19 | 🟧 HIGH | `GHA005` | **Untrusted input interpolated into a script**<br>`${{ github.event.issue.title }}` is expanded directly inside `run:`. | Pass the value through an environment variable (env: TITLE: ${{ github.event.issue.title }}) and use "$TITLE" in the script. |
| 21 | 🟧 HIGH | `GHA008` | **Remote script piped into a shell**<br>Remote script piped into a shell. | Download, verify a checksum, then execute. |
| 24 | 🟧 HIGH | `GHA009` | **Secret printed to the log**<br>A secret is written to stdout. | Never echo secrets; GitHub masking is best-effort and is bypassed by encoding/transformations. |
