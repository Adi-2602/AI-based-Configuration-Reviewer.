# Demo: review real, runnable Docker files

A tiny Flask web app with two versions of its container setup:

| File | What it is | Reviewer result |
|---|---|---|
| `Dockerfile.bad` | insecure on purpose (latest image, secret in ENV, root, chmod 777, SSH port…) | 14 issues, **21/100, grade F** |
| `docker-compose.bad.yml` | privileged container, passwords in plain text, database open to the network | **2/100, grade F** |
| `Dockerfile.good` | pinned image, no secrets, non-root user, health check | **100/100, grade A** |
| `docker-compose.good.yml` | port bound to localhost, restart policy, limits, health check | **100/100, grade A** |

Run every command below from the **project root folder** (the folder that contains `config_reviewer/`).

## 1. Review the files

```bash
python -m config_reviewer demo/Dockerfile.bad
python -m config_reviewer demo/Dockerfile.good
python -m config_reviewer demo/docker-compose.bad.yml demo/docker-compose.good.yml
```

Or in the web UI (`python -m config_reviewer.web`): **Upload** → drop the files from the `demo/` folder → **Run review**.

## 2. Run both apps to show the difference

```bash
cd demo
docker build -f Dockerfile.bad  -t demo-app:bad  .
docker build -f Dockerfile.good -t demo-app:good .
docker run -d --name demo-bad  -p 5001:5000 demo-app:bad
docker run -d --name demo-good -p 5002:5000 demo-app:good
```

Open http://127.0.0.1:5001 and http://127.0.0.1:5002: both apps work. Then compare:

```bash
docker exec demo-bad id -un      # root     <- runs as root
docker exec demo-good id -un     # appuser  <- runs as a normal user
docker ps                        # demo-good shows (healthy); demo-bad has no health check
docker images demo-app           # bad ≈ 1.66 GB, good ≈ 198 MB
```

Clean up: `docker rm -f demo-bad demo-good`

Or with Compose: `docker compose -f docker-compose.good.yml up --build` (Ctrl+C to stop).

## 3. With AI review

```bash
export ANTHROPIC_API_KEY="sk-ant-your-key"
python -m config_reviewer demo/Dockerfile.bad --ai
```

AI findings are labelled `(AI)` and get IDs `AI001`, `AI002`, …; each file also gets an AI summary.
