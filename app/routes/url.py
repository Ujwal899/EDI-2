from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.url_service import analyze_url
from app.services.scan_history_service import scan_history_service


router = APIRouter(tags=["url"])


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(default="", max_length=5000)


class AnalyzeResponse(BaseModel):
    label: Literal["SAFE", "SUSPICIOUS", "PHISHING"]
    confidence: float
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: list[str]
    input_type: str | None = None
    analyzed_url: str | None = None
    analyzed_domain: str | None = None
    scan_id: int | None = None
    source: str | None = None


@router.post("/analyze-url", response_model=AnalyzeResponse)
async def analyze_url_route(payload: AnalyzeUrlRequest) -> AnalyzeResponse:
    try:
        result = analyze_url(payload.url)
        scan_id = scan_history_service.record_scan(
            source="manual",
            input_type="url",
            url=payload.url,
            result=result,
        )
        return AnalyzeResponse(
            label=str(result["label"]),
            confidence=float(result["confidence"]),
            risk_level=str(result["risk_level"]),
            reasons=list(result.get("reasons", [])),
            input_type="url",
            analyzed_url=str(result.get("analyzed_url", payload.url)),
            analyzed_domain=str(result.get("analyzed_domain", "")),
            scan_id=scan_id,
            source="manual",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to analyze url: {exc}") from exc
