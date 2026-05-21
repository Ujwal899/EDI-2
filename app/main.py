import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import API_TITLE, API_VERSION
from app.routes.combined import router as combined_router
from app.routes.dashboard import router as dashboard_router
from app.routes.email import router as email_router
from app.routes.url import router as url_router
from app.services.email_service import email_service
from app.services.scan_history_service import scan_history_service


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("phishing-api")
FRONTEND_PATH = Path(__file__).resolve().parent.parent / "frontend" / "index.html"

app = FastAPI(title=API_TITLE, version=API_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(email_router)
app.include_router(url_router)
app.include_router(combined_router)
app.include_router(dashboard_router)


@app.get("/")
async def root() -> dict:
    return {
        "service": API_TITLE,
        "status": "ok",
        "endpoints": [
            "/emails",
            "/analyze-email",
            "/analyze-url",
            "/analyze-full",
            "/scan-history",
            "/scan-feedback",
            "/dashboard-summary",
            "/health",
            "/docs",
        ],
    }


@app.get("/dashboard-ui", include_in_schema=False)
async def dashboard_ui():
    if not FRONTEND_PATH.exists():
        return JSONResponse(status_code=404, content={"detail": "Dashboard file not found"})
    return FileResponse(FRONTEND_PATH)


@app.get("/health")
async def health() -> dict:
    model_loaded = email_service.model is not None and email_service.vectorizer is not None
    return {
        "status": "ok" if model_loaded else "starting",
        "model_loaded": bool(model_loaded),
    }


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled server error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.on_event("startup")
async def startup_load_artifacts() -> None:
    scan_history_service.init_db()
    email_service.load_artifacts()
    logger.info("Loaded email model artifacts")
