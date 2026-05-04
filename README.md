# NetIntel Backend API

Production-ready starter backend using FastAPI.

## Architecture

- **API Gateway Layer**: FastAPI app (`app/main.py`) exposes REST endpoints.
- **Service Layer**: Validation and orchestration logic (`app/services/pipeline.py`).
- **Provider Layer**: Optional external API adapters (`app/providers/`).
- **Observability**: Health endpoints and structured logging.

## Endpoints

- `GET /health` - liveness
- `POST /v1/analyze` - accepts input payload and returns normalized result

### Input format

```json
{
  "input": "text to analyze",
  "metadata": {
    "source": "web"
  }
}
```

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## GitHub Actions Deploy (Fly.io)

1. Create Fly app once:
   - `flyctl auth login`
   - `flyctl apps create netintel-backend-live`
2. Add GitHub repository secrets:
   - `FLY_API_TOKEN`
   - `FLY_APP_NAME` = `netintel-backend-live`
3. Push to `main`; workflow auto deploys.

After deployment, API base URL is:

`https://<FLY_APP_NAME>.fly.dev`

Example:

```bash
curl -X POST "https://netintel-backend-live.fly.dev/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{"input":"hello world","metadata":{"source":"test"}}'
```
