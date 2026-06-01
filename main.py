"""
LinkScout — web layer (FastAPI).

This file is intentionally thin. All the real work lives in checker/core.py.
This layer does exactly three things:
  1. Receives the HTTP request.
  2. Calls the checker core.
  3. Returns the result as JSON.

To call the checker without a web server at all, import check() directly:
    from checker import check
    result = check("https://example.com")
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# Load variables from a .env file into os.environ.
# This must happen before we import checker, which reads VIRUSTOTAL_API_KEY.
# load_dotenv() is a no-op if .env doesn't exist, so it's safe in production too.
load_dotenv()

from checker.core import check  # noqa: E402


app = FastAPI(
    title="LinkScout",
    description="URL threat intelligence checker — checks domains against VirusTotal and URLhaus.",
    version="0.1.0",
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
# Without this, browsers refuse to let JavaScript on one origin (localhost:5173)
# call an API on a different origin (localhost:8000). This is the Same-Origin Policy.
# CORSMiddleware adds the HTTP headers that tell the browser our API opts in.
#
# SECURITY: This allows only the local Vite dev server. Before deploying to EC2,
# replace "http://localhost:5173" with the real production frontend URL.
# Never use allow_origins=["*"] in production — it lets any website call your API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server — tighten before EC2 deploy
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/")
def health_check():
    """
    Health check endpoint.
    Returns 200 OK with a status message. Use this to confirm the service is running.
    """
    return {"status": "ok", "service": "linkscout", "version": "0.1.0"}


class CheckRequest(BaseModel):
    """Request body for POST /check."""
    # Accepts a full URL (https://evil.com/path) or a bare domain (evil.com).
    url: str


@app.post("/check")
def check_url(request: CheckRequest):
    """
    Check a URL or domain against VirusTotal and URLhaus.

    Why POST instead of GET?
    Passing a URL as a GET query parameter creates a URL-inside-a-URL, which
    causes percent-encoding headaches and confuses some proxies and log parsers.
    A JSON body in POST keeps it clean and unambiguous.

    Returns JSON with:
      verdict   — "malicious" | "suspicious" | "safe" | "unknown"
      sources   — per-source breakdown (VT engine counts, URLhaus hit/tags)
      from_cache — whether this result was served from the 1-hour cache
      checked_at — UTC timestamp of when the check ran
    """
    result = check(request.url)

    # If input validation failed, return 422 Unprocessable Entity with the reason.
    if result.get("error"):
        return JSONResponse(status_code=422, content=result)

    return result
