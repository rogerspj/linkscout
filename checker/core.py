"""
Checker core — the reusable judgment engine.

This is the heart of LinkScout. It is deliberately kept free of any web
framework or HTTP server code so that it can be called by:

  - main.py (the FastAPI web layer)     — this chunk
  - test_core.py (command-line test)    — this chunk
  - a DNS resolver                       — next week's brief

Public API:
    from checker import check

    result = check("https://evil.com/login")  # full URL — domain extracted automatically
    result = check("evil.com")                # bare domain — works the same way
"""

import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from .virustotal import check_domain as _vt_check
from .urlhaus import check_domain as _uh_check


# ─── Thresholds ────────────────────────────────────────────────────────────────
# These are the ONLY numbers you need to touch to tune how sensitive the tool is.
# Everything else auto-follows from these.
#
# VirusTotal pools results from 70+ security engines. Think of each number below
# as "how many of those 70 engines need to raise a flag before we take it seriously."

# Engines flagging "malicious" needed to call the overall verdict malicious.
# 3 out of 70+ is intentionally low — we'd rather warn than silently pass something.
VT_MALICIOUS_THRESHOLD = 3

# If at least this many engines flag "malicious" but fewer than VT_MALICIOUS_THRESHOLD,
# we call it suspicious rather than safe. Set to 1 so even a single flag is noted.
VT_SUSPICIOUS_MIN = 1

# VT also tracks a separate "suspicious" vote. If enough engines vote suspicious
# but none vote outright malicious, we still call it suspicious.
VT_SUSPICIOUS_VOTES_THRESHOLD = 5


# ─── In-memory cache ───────────────────────────────────────────────────────────
# A simple dictionary that lives in the running Python process.
# No Redis, no database — right-sized for local development.
#
# Key:   domain string, e.g. "evil.com"
# Value: {"result": <verdict dict>, "expires_at": <unix timestamp as float>}
#
# Why expire after 1 hour?
# A domain can be clean today and weaponised tonight. A stale "safe" answer is
# dangerous, so we keep the TTL short and re-query after an hour.
_cache: dict = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


# ─── Public API ────────────────────────────────────────────────────────────────

def check(target: str) -> dict:
    """
    Main entry point. Accepts a full URL or a bare domain.
    Returns a verdict dict — see _build_result() for the exact shape.

    This function is intentionally framework-agnostic. No FastAPI imports,
    no HTTP request objects. Any caller can use it directly.

    Steps, in order:
      1. Validate input and extract the domain.
      2. Return a cached result if one exists and hasn't expired.
      3. Query VirusTotal and URLhaus (in parallel — both are called regardless).
      4. Interpret each source's raw numbers into a per-source verdict.
      5. Combine into one top-line verdict (worst of the two wins).
      6. Cache the result for 1 hour.
      7. Return.
    """

    # Step 1 — Validate and extract the domain.
    domain, error_msg = _extract_domain(target)
    if domain is None:
        return {
            "error": True,
            "message": error_msg,
            "url": target,
            "domain": None,
            "verdict": None,
            "sources": None,
            "checked_at": _now_iso(),
            "from_cache": False,
        }

    # Step 2 — Cache hit?
    cached = _cache.get(domain)
    if cached and time.time() < cached["expires_at"]:
        result = dict(cached["result"])  # shallow copy so we can mutate from_cache
        result["from_cache"] = True
        return result

    # Step 3 — Query both sources.
    # Neither call visits the submitted URL — they look up the domain as a text
    # string against threat intel APIs that have already done the crawling.
    vt_raw = _vt_check(domain)
    uh_raw = _uh_check(domain)

    # Step 4 — Interpret raw data into per-source verdicts using the thresholds above.
    vt_verdict = _interpret_vt(vt_raw)
    uh_verdict = _interpret_uh(uh_raw)

    # Step 5 — Combine into one top-line verdict.
    overall = _combine(vt_verdict, uh_verdict)

    # Step 6 — Build the result dict.
    result = {
        "error": False,
        "url": target,
        "domain": domain,
        "verdict": overall,
        "sources": {
            "virustotal": {**vt_raw, "verdict": vt_verdict},
            "urlhaus": {**uh_raw, "verdict": uh_verdict},
        },
        "checked_at": _now_iso(),
        "from_cache": False,
    }

    # Step 7 — Cache for next time.
    _cache[domain] = {
        "result": result,
        "expires_at": time.time() + CACHE_TTL_SECONDS,
    }

    return result


# ─── Internal helpers ──────────────────────────────────────────────────────────

def _now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# Regex that matches valid hostnames like example.com and sub.domain.co.uk.
# Breaks down as:
#   one or more labels (letters/digits/hyphens), each followed by a dot
#   finished by a TLD of at least 2 letters
# This rejects raw IP addresses (last label must be letters, not digits).
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)


def _extract_domain(target: str) -> tuple[str | None, str | None]:
    """
    Return (domain, None) on success, or (None, error_message) on failure.

    Accepts:
      - Full URLs with http/https scheme:  https://evil.com/path?q=1
      - Bare hostnames:                    evil.com,  sub.evil.com

    Rejects:
      - Empty strings
      - Non-http/https schemes (ftp://, javascript://, etc.)
      - IP addresses
      - Strings that are clearly not a URL or domain
    """
    target = target.strip()

    if not target:
        return None, "Target cannot be empty."

    # ── Case 1: has a scheme separator (looks like a full URL) ──
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return None, (
                f"Only http and https URLs are accepted (got: '{parsed.scheme}://')."
            )
        hostname = parsed.hostname  # urlparse lower-cases this and strips the port
        if not hostname:
            return None, "Could not extract a hostname from the URL."
        return hostname, None

    # ── Case 2: no scheme — treat as a bare domain ──
    # Reject immediately if it contains characters that belong in URLs, not domains.
    if any(ch in target for ch in (" ", "/", "?", "#", "@", ":")):
        return None, (
            f"'{target}' doesn't look like a valid URL or domain. "
            "Submit a full URL (https://example.com) or a bare domain (example.com)."
        )

    domain = target.lower()
    if not _DOMAIN_RE.match(domain):
        return None, (
            f"'{target}' doesn't look like a valid domain name. "
            "Expected something like example.com or sub.example.com."
        )

    return domain, None


def _interpret_vt(raw: dict) -> str:
    """
    Turn VirusTotal raw numbers into one of: "malicious", "suspicious", "safe", "unknown".

    Applies the VT_* thresholds defined at the top of this file.
    "unknown" means we can't draw a conclusion — NOT that the domain is safe.
    """
    status = raw.get("status")

    # Source was unavailable — we don't know, so don't call it safe.
    if status in ("error", "rate_limited", "no_key"):
        return "unknown"

    # VT has never analysed this domain, or zero engines checked.
    if status == "not_found" or (raw.get("total_engines") or 0) == 0:
        return "unknown"

    malicious = raw.get("malicious") or 0
    suspicious = raw.get("suspicious") or 0

    if malicious >= VT_MALICIOUS_THRESHOLD:
        return "malicious"

    if malicious >= VT_SUSPICIOUS_MIN or suspicious >= VT_SUSPICIOUS_VOTES_THRESHOLD:
        return "suspicious"

    # VT checked with 70+ engines and found nothing bad.
    return "safe"


def _interpret_uh(raw: dict) -> str:
    """
    Turn URLhaus raw findings into one of: "malicious", "unknown".

    URLhaus is a malware-distribution feed, not a safe-list. A domain not in
    URLhaus means "we haven't catalogued malware there", not "definitely safe".
    So the only verdicts are malicious (found) or unknown (not found / error).
    """
    if raw.get("status") == "error":
        return "unknown"

    if raw.get("found"):
        # URLhaus is manually curated and focused — a hit here is reliable.
        return "malicious"

    return "unknown"


def _combine(vt_verdict: str, uh_verdict: str) -> str:
    """
    Combine the two per-source verdicts into one top-line verdict.
    The worst of the two always wins.

    Priority order (worst → best): malicious > suspicious > safe > unknown

    Important: "unknown" from a source means we don't have that data point.
    It does NOT count as a clean pass — it is neutral, not exculpatory.
    """
    if vt_verdict == "malicious" or uh_verdict == "malicious":
        return "malicious"

    if vt_verdict == "suspicious" or uh_verdict == "suspicious":
        return "suspicious"

    if vt_verdict == "safe" or uh_verdict == "safe":
        # At least one source checked and found nothing bad.
        return "safe"

    # Both sources returned "unknown" — no usable data from either.
    return "unknown"
