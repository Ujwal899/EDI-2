from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.decision_engine import combine_email_and_url
from app.services.email_service import email_service
from app.services.multimodal_features import analyze_multimodal_features, merge_multimodal_result
from app.services.scan_history_service import scan_history_service
from app.services.url_service import analyze_url


router = APIRouter(tags=["combined"])


class AnalyzeFullRequest(BaseModel):
    subject: str = Field(default="", max_length=5000)
    body: str = Field(default="", max_length=500000)
    sender: str = Field(default="", max_length=1000)
    url: str = Field(default="", max_length=5000)
    links: list[str] = Field(default_factory=list)
    attachments: list[Any] = Field(default_factory=list)
    reply_to: str = Field(default="", max_length=1000)
    return_path: str = Field(default="", max_length=1000)
    webpage_text: str = Field(default="", max_length=500000)
    image_indicators: list[str] = Field(default_factory=list)
    image_payloads: list[Any] = Field(default_factory=list)
    qr_text: str = Field(default="", max_length=50000)


class AnalyzeResponse(BaseModel):
    label: Literal["SAFE", "SUSPICIOUS", "PHISHING"]
    confidence: float
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: list[str]
    input_type: str | None = None
    analyzed_url: str | None = None
    analyzed_domain: str | None = None
    url_label: str | None = None
    email_label: str | None = None
    scan_id: int | None = None
    source: str | None = None
    feature_summary: dict | None = None


@router.post("/analyze-full", response_model=AnalyzeResponse)
async def analyze_full(payload: AnalyzeFullRequest) -> AnalyzeResponse:
    try:
        email_result = email_service.predict_email(
            subject=payload.subject,
            body=payload.body,
            sender=payload.sender,
        )
        url_result = analyze_url(payload.url)
        result = combine_email_and_url(email_result=email_result, url_result=url_result)
        multimodal_result = analyze_multimodal_features(
            subject=payload.subject,
            body=payload.body,
            sender=payload.sender,
            url=payload.url,
            links=payload.links,
            attachments=payload.attachments,
            reply_to=payload.reply_to,
            return_path=payload.return_path,
            webpage_text=payload.webpage_text,
            image_indicators=payload.image_indicators,
            image_payloads=payload.image_payloads,
            qr_text=payload.qr_text,
        )
        result = merge_multimodal_result(result, multimodal_result)
        scan_id = scan_history_service.record_scan(
            source="manual",
            input_type="combined",
            subject=payload.subject,
            sender=payload.sender,
            body=payload.body,
            url=payload.url,
            result=result,
        )
        result["scan_id"] = scan_id
        result["source"] = "manual"
        result["input_type"] = "combined"
        result["analyzed_url"] = str(url_result.get("analyzed_url", payload.url))
        result["analyzed_domain"] = str(url_result.get("analyzed_domain", ""))
        result["url_label"] = str(url_result.get("label", ""))
        result["email_label"] = str(email_result.get("label", ""))
        return AnalyzeResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to analyze payload: {exc}") from exc
