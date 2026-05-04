from app.models import AnalyzeRequest, AnalyzeResponse


def run_pipeline(payload: AnalyzeRequest) -> AnalyzeResponse:
    normalized = " ".join(payload.input.strip().split())
    return AnalyzeResponse(
        normalized_input=normalized,
        word_count=len(normalized.split()) if normalized else 0,
        metadata=payload.metadata,
    )
