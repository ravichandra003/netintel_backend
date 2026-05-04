from fastapi import FastAPI

from app.models import AnalyzeRequest, AnalyzeResponse
from app.services.pipeline import run_pipeline

app = FastAPI(title="NetIntel Backend API", version="1.0.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    return run_pipeline(payload)
