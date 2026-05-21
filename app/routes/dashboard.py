from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.scan_history_service import scan_history_service


router = APIRouter(tags=["dashboard"])


class FeedbackRequest(BaseModel):
    scan_id: int = Field(ge=1)
    verdict: Literal["SAFE", "SUSPICIOUS", "PHISHING"]
    note: str = Field(default="", max_length=2000)


@router.get("/scan-history")
async def scan_history(limit: int = Query(default=50, ge=1, le=200)) -> list[dict]:
    return scan_history_service.list_scans(limit=limit)


@router.get("/dashboard-summary")
async def dashboard_summary() -> dict:
    return scan_history_service.summary()


@router.post("/scan-feedback")
async def scan_feedback(payload: FeedbackRequest) -> dict:
    try:
        saved = scan_history_service.save_feedback(
            scan_id=payload.scan_id,
            verdict=payload.verdict,
            note=payload.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not saved:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return {"status": "ok", "scan_id": payload.scan_id, "verdict": payload.verdict}
