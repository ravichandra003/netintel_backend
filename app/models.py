from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    input: str = Field(..., min_length=1, description="User input text")
    metadata: dict[str, str] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    normalized_input: str
    word_count: int
    metadata: dict[str, str]
