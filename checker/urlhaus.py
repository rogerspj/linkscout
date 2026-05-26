"""
URLhaus source module (abuse.ch).

Responsibility: fetch raw data from URLhaus and return it as a plain dict.
No verdict logic lives here — core.py decides what "found" means.

URLhaus is a community-curated feed of URLs used to distribute malware.
It supports two lookup modes, chosen by core.py based on what the caller submitted:
  - check_url(url)      — URL-level: checks a specific full URL
  - check_domain(domain) — host-level: checks all known malware URLs for a host
"""

import os

import httpx

URLHAUS_URL_API  = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
REQUEST_TIMEOUT_SECONDS = 10.0


def _auth_key() -> str | None:
    return os.environ.get("URLHAUS_AUTH_KEY")


def _empty(status: str, level: str, error_msg: str | None = None) -> dict:
    """Return a blank result dict with consistent structure."""
    return {
        "status": status,
        "lookup_level": level,
        "found": False,
        "url_count": 0,
        "threat_tags": [],
        "urlhaus_reference": None,
        "error_message": error_msg,
    }


def check_url(url: str) -> dict:
    """
    Query URLhaus at the URL level.

    Checks whether THIS SPECIFIC URL (e.g. https://example.com/evil.exe) is in
    URLhaus. Precise — a clean path on a dirty host comes back not-found, which
    is why https://www.google.com should not inherit the host's reputation here.

    Use this when the caller supplied a full URL.

    Returned fields:
      status          : "ok" | "error" | "no_key"
      lookup_level    : always "url"
      found           : bool   — True if this exact URL is in URLhaus
      url_count       : 1 if found, 0 otherwise
      threat_tags     : list[str] — tags on this specific URL
      urlhaus_reference: str or None
      error_message   : str or None
    """
    key = _auth_key()
    if not key:
        return _empty("no_key", "url", "URLHAUS_AUTH_KEY is not set. Add it to your .env file.")

    try:
        response = httpx.post(
            URLHAUS_URL_API,
            data={"url": url},
            headers={"Auth-Key": key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code != 200:
            return _empty("error", "url", f"URLhaus returned HTTP {response.status_code}.")

        data = response.json()
        if data.get("query_status") == "no_results":
            # This exact URL is not in URLhaus. Note: "not found" here is quite meaningful —
            # URLhaus URL-level is precise, so a miss is a real clean signal for that path.
            return _empty("ok", "url")

        # URL is in URLhaus — gather tags.
        tags = sorted(set(data.get("tags") or []))
        return {
            "status": "ok",
            "lookup_level": "url",
            "found": True,
            "url_count": 1,
            "threat_tags": tags,
            "urlhaus_reference": data.get("urlhaus_reference"),
            "error_message": None,
        }

    except httpx.TimeoutException:
        return _empty("error", "url", "URLhaus URL lookup timed out (10 s).")
    except Exception as exc:
        return _empty("error", "url", f"URLhaus URL lookup failed: {exc}")


def check_domain(domain: str) -> dict:
    """
    Query URLhaus at the host level.

    Returns all known malware URLs associated with this domain. Less precise than
    URL-level — the whole host's history is returned, not a specific path.

    Use this when the caller supplied a bare domain (which is exactly what the
    DNS resolver will supply next week).

    Returned fields: same shape as check_url(), with lookup_level always "host".
    """
    key = _auth_key()
    if not key:
        return _empty("no_key", "host", "URLHAUS_AUTH_KEY is not set. Add it to your .env file.")

    try:
        response = httpx.post(
            URLHAUS_HOST_API,
            data={"host": domain},
            headers={"Auth-Key": key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code != 200:
            return _empty("error", "host", f"URLhaus returned HTTP {response.status_code}.")

        data = response.json()
        if data.get("query_status") == "no_results":
            # Not in the URLhaus host feed — means "not in our malware feed", NOT "definitely safe".
            return _empty("ok", "host")

        # Host is in URLhaus — gather URL count and tags.
        urls = data.get("urls", [])
        tags: set[str] = set()
        for url_entry in urls:
            for tag in (url_entry.get("tags") or []):
                tags.add(tag)

        return {
            "status": "ok",
            "lookup_level": "host",
            "found": True,
            "url_count": len(urls),
            "threat_tags": sorted(tags),
            "urlhaus_reference": data.get("urlhaus_reference"),
            "error_message": None,
        }

    except httpx.TimeoutException:
        return _empty("error", "host", "URLhaus host lookup timed out (10 s).")
    except Exception as exc:
        return _empty("error", "host", f"URLhaus host lookup failed: {exc}")
