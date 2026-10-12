# DevSecOps Dashboard (React + FastAPI)

Interface required by the PFE cahier des charges (DASH-01 … DASH-06).

## Structure

- `frontend/` — React + Vite + Tailwind + Recharts
- `backend/` — FastAPI API (`/api/*`) + optional static hosting of the built UI

## Run locally

### 1. Security reports

After a pipeline run, download the `reports/` artifact, or generate a minimal summary:

```bash
mkdir -p reports
python scripts/ai-filter.py
python scripts/aggregate-reports.py
```

### 2. AI service (optional, port 8001)

```bash
cd ai-service
pip install -r requirements.txt
# Train once: python ../ai-training/train.py
uvicorn inference:app --reload --port 8001
```

### 3. Dashboard API (port 8080)

```bash
cd dashboard/backend
pip install -r requirements.txt
set REPORTS_DIR=../../reports
set AI_SERVICE_URL=http://127.0.0.1:8001
uvicorn main:app --reload --port 8080
```

### 4. React dev server (port 5173)

```bash
cd dashboard/frontend
npm install
npm run dev
```

Open http://localhost:5173 — API calls are proxied to port 8080.

### Docker (API + AI + reports)

From repo root:

```bash
docker compose -f docker-compose.dashboard.yml up --build
```

Dashboard: http://localhost:8080

## GitLab CI

| Job | Role |
|-----|------|
| `ai-filter` | Classify Semgrep findings → `reports/semgrep-ai-filtered.json` |
| `aggregate-dashboard` | Merge all scan JSON → `reports/dashboard-summary.json` |
| `build-dashboard` | Build Docker image for deployment |

Set CI variable `AI_SERVICE_URL` if the AI container is reachable from the runner during `ai-filter`.
