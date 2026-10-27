import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.database import SessionLocal, init_db
from app.errors import (
    dependency_unavailable_error,
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.routers import scans
from app.services.secrets import validate_settings
from app.services.zap_client import ZAPClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="ShieldScan",
    description="AI-Assisted Web Application Vulnerability Assessment Tool for Small Businesses",
    version="1.0.0",
)

app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(scans.router)


@app.on_event("startup")
def on_startup():
    init_db()
    validate_settings(get_settings())


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    settings = get_settings()
    return {
        "status": "ok",
        "service": "shieldscan",
        "phase": 1,
        "scanner_version": "3.0",
        "scan_phases": 5,
        "scanner_mode": settings.scanner_mode,
        "wave_program": "Stellar Wave 7",
        "checks": [
            "Crawl up to 80 pages, depth 4, DVWA/Juice Shop path seeding",
            "OWASP A01 — IDOR, admin paths, CSRF, open redirect, clickjacking",
            "OWASP A02 — HTTPS, TLS, cookie flags",
            "OWASP A03 — XSS, SQLi, command injection, SSTI, NoSQL (45+ params)",
            "OWASP A05 — Headers, disclosure, CORS, directory listing",
            "OWASP A06 — Outdated JS libraries on all crawled pages",
            "OWASP A07 — Login over HTTP, rate limiting, auth bypass surface",
            "OWASP A09 — Verbose error disclosure",
            "OWASP A10 — SSRF attack surface",
            "Deep probes — path traversal, LFI, sensitive files, API fuzzing",
            "OWASP ZAP — spider + AJAX spider + passive + active (when Docker on)",
        ],
    }


@app.get("/ready")
async def ready():
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "database": "error",
                "error": {"code": "SERVICE_UNAVAILABLE", "message": str(exc)},
            },
        )

    settings = get_settings()
    if settings.scanner_mode.strip().lower() == "zap":
        zap = ZAPClient(settings)
        if not await zap.is_available():
            return dependency_unavailable_error(
                dependency="zap",
                message=f"OWASP ZAP is unreachable at {settings.zap_api_url} while SCANNER_MODE=zap",
                details={"zap_api_url": settings.zap_api_url, "scanner_mode": "zap"},
            )
        return {"status": "ready", "database": "ok", "scanner_mode": "zap", "zap": "ok"}

    return {"status": "ready", "database": "ok", "scanner_mode": settings.scanner_mode, "zap": "not_required"}
