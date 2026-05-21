from typing import Literal
import logging

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.services.email_service import email_service
from app.services.gmail_dashboard_service import gmail_dashboard_service
from app.services.multimodal_features import analyze_multimodal_features, merge_multimodal_result
from app.services.scan_history_service import scan_history_service


router = APIRouter(tags=["email"])
logger = logging.getLogger(__name__)


class AnalyzeEmailRequest(BaseModel):
    subject: str = Field(default="", max_length=5000)
    body: str = Field(default="", max_length=500000)
    sender: str = Field(default="", max_length=1000)
    url: str = Field(default="", max_length=5000)
    links: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)
    reply_to: str = Field(default="", max_length=1000)
    return_path: str = Field(default="", max_length=1000)
    webpage_text: str = Field(default="", max_length=500000)
    image_indicators: list[str] = Field(default_factory=list)
    qr_text: str = Field(default="", max_length=50000)


class AnalyzeResponse(BaseModel):
    label: Literal["SAFE", "SUSPICIOUS", "PHISHING"]
    confidence: float
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: list[str]
    input_type: str | None = None
    scan_id: int | None = None
    source: str | None = None
    feature_summary: dict | None = None


class DashboardEmailResponse(BaseModel):
    subject: str
    sender: str
    snippet: str
    label: Literal["SAFE", "SUSPICIOUS", "PHISHING"]
    confidence: float
    risk: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: list[str] = []


class DashboardErrorResponse(BaseModel):
    error: str
    details: str


@router.post("/analyze-email", response_model=AnalyzeResponse)
async def analyze_email(payload: AnalyzeEmailRequest) -> AnalyzeResponse:
    try:
        result = email_service.predict_email(
            subject=payload.subject,
            body=payload.body,
            sender=payload.sender,
        )
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
            qr_text=payload.qr_text,
        )
        result = merge_multimodal_result(result, multimodal_result)
        scan_id = scan_history_service.record_scan(
            source="manual",
            input_type="email",
            subject=payload.subject,
            sender=payload.sender,
            body=payload.body,
            result=result,
        )
        result["scan_id"] = scan_id
        result["source"] = "manual"
        result["input_type"] = "email"
        return AnalyzeResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to analyze email: {exc}") from exc


@router.get("/emails", response_model=list[DashboardEmailResponse] | DashboardErrorResponse)
async def get_emails(limit: int = Query(default=20, ge=1, le=100)) -> list[DashboardEmailResponse] | JSONResponse:
    logger.info("/emails request received with limit=%d", limit)
    try:
        emails = gmail_dashboard_service.fetch_analyzed_emails(limit=limit)
        logger.info("/emails returning %d analyzed emails", len(emails))
        return [DashboardEmailResponse(**item) for item in emails]
    except Exception as exc:
        logger.exception("/emails failed: %s", exc)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Failed to fetch emails",
                "details": str(exc),
            },
        )
