# Deploying the AI Config Reviewer

The web app ships as one Docker image (gunicorn, non-root user, health check at `/api/health`).
It reads these environment variables:

| Variable | Needed? | Purpose |
|---|---|---|
| `CONFIG_REVIEWER_USER`, `CONFIG_REVIEWER_PASSWORD` | **Yes, for any public deployment** | Turns on a login (HTTP Basic auth) for every page except `/api/health` |
| `ANTHROPIC_API_KEY` | Optional | Enables the AI review. Anyone who can log in can spend your credits |
| `PORT` | Set by the platform | Port to listen on (default 8000) |
| `CONFIG_REVIEWER_DB` | Optional | Path of the review-history database (default `/data/history.db` in the image) |

> ⚠️ Never put the API key or the password in a file in the repository. Enter them in the platform's
> environment-variable settings.

---

## Option A: Render.com (easiest, free, HTTPS included)

1. Sign in at <https://render.com> with your GitHub account.
2. **New → Web Service** → pick this GitHub repository.
3. Runtime / language: **Docker** (Render finds the `Dockerfile`). Instance type: **Free**.
4. Under **Advanced** (or the service settings): set **Health Check Path** to `/api/health`.
5. Add **Environment Variables**:
   - `CONFIG_REVIEWER_USER` = a username, e.g. `admin`
   - `CONFIG_REVIEWER_PASSWORD` = a strong password
   - `ANTHROPIC_API_KEY` = your key (only if you want AI review online)
6. Click **Create Web Service**. After the build, the app is at `https://<service-name>.onrender.com`.
   Your browser asks for the username and password.

Notes for the free plan: the service goes to sleep when idle, so the first visit after a break takes
up to a minute, and its disk is not permanent, so the review history resets when the service restarts
or redeploys. Render passes the port in `$PORT`, which the image already uses. Exact menu labels on
Render may change slightly over time.

---

## Option B: A cloud virtual machine (Azure for Students, AWS, GCP)

1. Create an **Ubuntu** VM (1–2 vCPU, 2 GB RAM is enough). In its network settings allow inbound
   **SSH (22) only from your IP** and **HTTP (80)**.
2. SSH into the VM and run:

```bash
sudo apt-get update && sudo apt-get install -y docker.io git
git clone <your-repository-URL> reviewer
cd reviewer
sudo docker build -t ai-config-reviewer .
sudo docker run -d --name reviewer --restart unless-stopped \
  -p 80:8000 -v review-history:/data \
  -e CONFIG_REVIEWER_USER=admin \
  -e CONFIG_REVIEWER_PASSWORD='choose-a-strong-password' \
  ai-config-reviewer
```

3. Open `http://<VM public IP>` and log in. History is kept in the `review-history` volume.

Plain HTTP sends the login unencrypted. For a real deployment put HTTPS in front, for example with
Caddy (`caddy reverse-proxy --from your-domain --to localhost:8000` obtains a certificate
automatically), and publish the container on `127.0.0.1:8000` instead of port 80.

To update after a new push: `git pull && sudo docker build -t ai-config-reviewer . && sudo docker rm -f reviewer`
then run the `docker run` command again.

---

## Option C: Any computer with Docker (local demo)

```bash
docker compose up --build
```

Open <http://127.0.0.1:8000>. Compose only publishes the port on `127.0.0.1`, so only your own
computer can reach it. To use a login or AI review, export the variables first:

```bash
export CONFIG_REVIEWER_USER=admin
export CONFIG_REVIEWER_PASSWORD='choose-a-password'
export ANTHROPIC_API_KEY='sk-ant-...'
docker compose up --build
```

---

## Checking a deployment

```bash
curl https://<your-app>/api/health                  # {"status":"ok"}  (no login needed)
curl -u admin:<password> https://<your-app>/api/status   # version, rule count, AI availability
```
