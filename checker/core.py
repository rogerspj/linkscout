"""
Checker core — the reusable judgment engine.

This is the heart of LinkScout. It is deliberately kept free of any web
framework or HTTP server code so that it can be called by:

  - main.py (the FastAPI web layer)     — this chunk
  - test_core.py (command-line test)    — this chunk
  - a DNS resolver                       — next week's brief

Public API:
    from checker import check

    result = check("https://evil.com/login")  # full URL — URLhaus checked at URL level
    result = check("evil.com")                # bare domain — URLhaus checked at host level
"""

import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from .virustotal import check_domain as _vt_check
from .urlhaus import check_url as _uh_check_url, check_domain as _uh_check_host


# ─── Thresholds ────────────────────────────────────────────────────────────────
# These are the ONLY numbers you need to touch to tune how sensitive the tool is.
# Everything else auto-follows from these.
#
# VirusTotal pools results from 70+ security engines. Think of each number below
# as "how many of those 70 engines need to raise a flag before we take it seriously."

# Engines voting "malicious" needed to call the VT verdict malicious.
# 3 out of 70+ is intentionally low — we'd rather warn than silently pass something.
VT_MALICIOUS_THRESHOLD = 3

# Minimum "malicious" engines to call the VT verdict suspicious
# (used when count is >= 1 but below VT_MALICIOUS_THRESHOLD).
VT_SUSPICIOUS_MIN = 1

# VT also tracks a separate "suspicious" vote. If enough engines vote suspicious
# but none vote outright malicious, we still call the VT verdict suspicious.
VT_SUSPICIOUS_VOTES_THRESHOLD = 5


# ─── In-memory cache ───────────────────────────────────────────────────────────
# A simple dictionary that lives in the running Python process.
# No Redis, no database — right-sized for local development.
#
# Key:   the stripped original target string (e.g. "https://evil.com/path" or "evil.com").
#        We key by the full input, not just the domain, because a URL-level URLhaus
#        check and a host-level check for the same domain give different results and
#        must cache independently.
#
# Value: {"result": <verdict dict>, "expires_at": <unix timestamp float>}
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
    Returns a verdict dict with these top-level fields:
      error, url, domain, verdict, explanation, sources, checked_at, from_cache

    Verdict values: "dangerous" | "disputed" | "suspicious" | "likely_safe" | "unknown"

    This function is intentionally framework-agnostic. No FastAPI imports,
    no HTTP request objects. Any caller — web layer, CLI, DNS resolver — can use it.

    Steps, in order:
      1. Validate input and extract the domain.
      2. Decide URLhaus lookup level: URL-level for full URLs, host-level for bare domains.
      3. Return a cached result if one exists and hasn't expired.
      4. Query VirusTotal (always domain-level) and URLhaus (level chosen above).
      5. Interpret each source's raw data into a per-source verdict.
      6. Combine into one of five headline verdicts.
      7. Generate a plain-English explanation.
      8. Cache the result for 1 hour.
      9. Return.
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
            "explanation": None,
            "sources": None,
            "checked_at": _now_iso(),
            "from_cache": False,
        }

    # Step 2 — Decide URLhaus lookup level.
    # Full URLs (https://example.com/path) → URL-level: checks that specific link.
    # Bare domains (example.com) → host-level: checks the whole host's history.
    # This matters because a clean path on a dirty host should NOT inherit the
    # host's reputation — that was the root cause of the google.com false positive.
    is_full_url = "://" in target.strip()

    # Step 3 — Cache check. Key includes the full original target so URL and host
    # lookups for the same domain cache as separate entries.
    cache_key = target.strip()
    cached = _cache.get(cache_key)
    if cached and time.time() < cached["expires_at"]:
        result = dict(cached["result"])  # shallow copy so we can flip from_cache
        result["from_cache"] = True
        return result

    # Step 4 — Query both sources.
    # Neither call visits the submitted URL — these are text lookups against threat
    # intel APIs that have already done the crawling.
    #
    # VirusTotal stays domain-level in both cases. URL-level VT lookup is a reasonable
    # future enhancement but is out of scope for this chunk.
    vt_raw = _vt_check(domain)
    uh_raw = _uh_check_url(target.strip()) if is_full_url else _uh_check_host(domain)

    # Step 5 — Interpret raw data into per-source verdicts.
    vt_verdict = _interpret_vt(vt_raw)
    uh_verdict = _interpret_uh(uh_raw)

    # Step 6 — Combine into one headline verdict.
    overall = _combine(vt_verdict, uh_verdict)

    # Step 7 — Generate the explanation.
    explanation = _explain(overall, vt_raw, vt_verdict, uh_raw, uh_verdict)

    # Step 8 — Build the result dict.
    result = {
        "error": False,
        "url": target,
        "domain": domain,
        "verdict": overall,
        "explanation": explanation,
        "sources": {
            "virustotal": {**vt_raw, "verdict": vt_verdict},
            "urlhaus": {**uh_raw, "verdict": uh_verdict},
        },
        "checked_at": _now_iso(),
        "from_cache": False,
    }

    # Step 9 — Cache.
    _cache[cache_key] = {
        "result": result,
        "expires_at": time.time() + CACHE_TTL_SECONDS,
    }

    return result


# ─── Internal helpers ──────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Matches valid hostnames: example.com, sub.domain.co.uk
# Rejects IPs (last label must be letters, not digits) and single-label names.
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)


def _extract_domain(target: str) -> tuple[str | None, str | None]:
    """
    Return (domain, None) on success, or (None, error_message) on failure.

    Accepts full URLs (https://evil.com/path) and bare domains (evil.com).
    Rejects empty strings, non-http/https schemes, IPs, and malformed input.
    """
    target = target.strip()

    if not target:
        return None, "Target cannot be empty."

    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return None, f"Only http and https URLs are accepted (got: '{parsed.scheme}://')."
        hostname = parsed.hostname  # urlparse lower-cases this and strips the port
        if not hostname:
            return None, "Could not extract a hostname from the URL."
        return hostname, None

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
    Map VirusTotal raw numbers to an internal per-source verdict.

    Returns one of: "malicious" | "suspicious" | "safe" | "unknown"

    "safe" means VT actively checked the domain and found nothing bad.
    "unknown" means VT has no data OR was unavailable — NOT a clean signal.
    """
    status = raw.get("status")

    if status in ("error", "rate_limited", "no_key"):
        return "unknown"

    if status == "not_found" or (raw.get("total_engines") or 0) == 0:
        return "unknown"

    malicious = raw.get("malicious") or 0
    suspicious = raw.get("suspicious") or 0

    if malicious >= VT_MALICIOUS_THRESHOLD:
        return "malicious"

    if malicious >= VT_SUSPICIOUS_MIN or suspicious >= VT_SUSPICIOUS_VOTES_THRESHOLD:
        return "suspicious"

    return "safe"  # VT checked with many engines and found nothing bad


def _interpret_uh(raw: dict) -> str:
    """
    Map URLhaus raw findings to an internal per-source verdict.

    Returns one of: "malicious" | "unknown"

    URLhaus is a malware-distribution feed, not a safe-list.
    "not found" in URLhaus means "not in our feed", not "definitely clean".
    So URLhaus can only ever contribute "malicious" (hit) or "unknown" (no data / error).
    """
    if raw.get("status") in ("error", "no_key"):
        return "unknown"

    return "malicious" if raw.get("found") else "unknown"


def _combine(vt_verdict: str, uh_verdict: str) -> str:
    """
    Map the two per-source verdicts to one of five headline verdicts.

    ┌─────────────────┬──────────────┬──────────────────────────────────────────┐
    │ uh_verdict      │ vt_verdict   │ headline                                 │
    ├─────────────────┼──────────────┼──────────────────────────────────────────┤
    │ malicious       │ safe         │ disputed  ← conflict: sources disagree   │
    │ malicious       │ malicious    │ dangerous                                │
    │ malicious       │ suspicious   │ dangerous                                │
    │ malicious       │ unknown      │ dangerous (URLhaus alone is high-signal) │
    │ unknown         │ malicious    │ dangerous                                │
    │ unknown         │ suspicious   │ suspicious (weak signal, silence from UH)│
    │ unknown         │ safe         │ likely_safe (VT checked, found nothing)  │
    │ unknown         │ unknown      │ unknown                                  │
    └─────────────────┴──────────────┴──────────────────────────────────────────┘

    Key distinction:
      disputed  = one source affirmatively BAD + other affirmatively CLEAN (real conflict)
      suspicious = weak/partial signal + the other source is SILENT (not disagreeing)

    Why disputed takes priority over dangerous for the URLhaus-hit + VT-clean case:
    If 70+ engines all say clean, that's a strong affirmative signal. Hiding that
    conflict behind "dangerous" would make the tool cry wolf (the google.com case).
    """
    # Conflict: URLhaus found a hit, but VT checked many engines and found nothing.
    if uh_verdict == "malicious" and vt_verdict == "safe":
        return "disputed"

    # Dangerous: at least one source has high-confidence bad signal.
    # URLhaus is manually curated — any hit qualifies on its own.
    # VT "malicious" means >= VT_MALICIOUS_THRESHOLD engines flagged it.
    if uh_verdict == "malicious" or vt_verdict == "malicious":
        return "dangerous"

    # Suspicious: weak VT signal, URLhaus has no data (not disagreeing, just silent).
    if vt_verdict == "suspicious":
        return "suspicious"

    # Likely safe: VT actively checked and found nothing, URLhaus has no record.
    # Phrased as a hedge — "no detections" is not the same as "verified clean."
    if vt_verdict == "safe":
        return "likely_safe"

    # Both sources have no data.
    return "unknown"


def _explain(
    verdict: str,
    vt_raw: dict,
    vt_verdict: str,
    uh_raw: dict,
    uh_verdict: str,
) -> str:
    """
    Generate a plain-English explanation of why this verdict was reached.
    Cites actual numbers and tags from the source data.

    The explanation is meant to be human-readable. The one-word verdict is
    for the DNS resolver to act on; this sentence is for the user to understand.
    """
    uh_level   = uh_raw.get("lookup_level", "host")
    uh_noun    = "URL" if uh_level == "url" else "host"
    uh_status  = uh_raw.get("status")
    uh_found   = uh_raw.get("found", False)
    uh_tags    = uh_raw.get("threat_tags", [])
    uh_count   = uh_raw.get("url_count", 0)

    vt_status   = vt_raw.get("status")
    vt_total    = vt_raw.get("total_engines") or 0
    vt_malicious = vt_raw.get("malicious") or 0
    vt_suspicious_count = vt_raw.get("suspicious") or 0

    # ── Build a compact phrase for each source ──

    if uh_status in ("error", "no_key"):
        uh_phrase = "URLhaus was unavailable"
    elif not uh_found:
        uh_phrase = f"URLhaus has no record of this {uh_noun}"
    else:
        tag_str = f" (tags: {', '.join(uh_tags)})" if uh_tags else ""
        if uh_level == "url":
            uh_phrase = f"URLhaus flags this exact URL as a known malware link{tag_str}"
        else:
            n = uh_count
            uh_phrase = f"URLhaus found {n} malware URL{'s' if n != 1 else ''} on this host{tag_str}"

    if vt_status in ("error", "rate_limited", "no_key"):
        vt_phrase = "VirusTotal was unavailable"
    elif vt_status == "not_found" or vt_total == 0:
        vt_phrase = "VirusTotal has no record of this domain"
    elif vt_malicious == 0 and vt_suspicious_count == 0:
        vt_phrase = f"VirusTotal's {vt_total} engines all returned clean"
    elif vt_verdict == "malicious":
        vt_phrase = f"{vt_malicious} of {vt_total} VirusTotal engines flag it as malicious"
    else:  # suspicious — VT has flags but below the malicious threshold
        flags = []
        if vt_malicious:
            flags.append(f"{vt_malicious} malicious")
        if vt_suspicious_count:
            flags.append(f"{vt_suspicious_count} suspicious")
        vt_phrase = f"{' and '.join(flags)} of {vt_total} VirusTotal engines raised flags"

    # ── Assemble verdict-specific sentence ──

    if verdict == "disputed":
        return (
            f"{uh_phrase}, but {vt_phrase.lower()}. "
            "Sources conflict — verify before trusting."
        )

    if verdict == "dangerous":
        if uh_found and vt_verdict == "malicious":
            return f"{uh_phrase.capitalize()}, and {vt_phrase.lower()}."
        if uh_found:
            # URLhaus hit; VT either has no data or was unavailable.
            return f"{uh_phrase.capitalize()}. {vt_phrase.capitalize()}."
        # VT malicious; URLhaus silent.
        return f"{vt_phrase.capitalize()}. {uh_phrase.capitalize()}."

    if verdict == "suspicious":
        return f"{vt_phrase.capitalize()}. {uh_phrase.capitalize()}. Treat with caution."

    if verdict == "likely_safe":
        return (
            f"{uh_phrase.capitalize()} and {vt_phrase.lower()}. "
            "No known threats detected, but this is not a guarantee."
        )

    # unknown — covers both "no data" and "both unavailable"
    if vt_status in ("error", "rate_limited", "no_key") or uh_status in ("error", "no_key"):
        return f"{vt_phrase.capitalize()}. {uh_phrase.capitalize()}. No verdict possible."

    return "Neither URLhaus nor VirusTotal has any record of this target."
