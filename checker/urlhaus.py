"""
URLhaus source module (abuse.ch).

Responsibility: fetch raw data from URLhaus and return it as a plain dict.
No verdict logic lives here — core.py decides what "found" means.

URLhaus is a community-curated feed of URLs used to distribute malware.
It requires no API key for lookups.
"""

import os

import httpx

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
REQUEST_TIMEOUT_SECONDS = 10.0


def check_domain(domain: str) -> dict:
    """
    Query URLhaus for a domain/host.

    Returns a dict with raw findings. This function never raises — errors come
    back as status="error" so core.py can handle them.

    Returned fields:
      status            : "ok" | "error" | "no_key"
      found             : bool   — True if URLhaus has malware URLs for this host
      url_count         : int    — number of malware URLs associated with this host
      threat_tags       : list   — unique threat labels collected across all URLs
                                   (e.g. "Emotet", "elf", "Mirai")
      urlhaus_reference : str or None — link to the URLhaus page for this host
      error_message     : str or None — explanation if status != "ok"
    """
    auth_key = os.environ.get("URLHAUS_AUTH_KEY")
    if not auth_key:
        return {
            "status": "no_key",
            "found": False,
            "url_count": 0,
            "threat_tags": [],
            "urlhaus_reference": None,
            "error_message": "URLHAUS_AUTH_KEY is not set. Add it to your .env file.",
        }

    try:
        # URLhaus uses form-encoded POST (not JSON).
        # The Auth-Key header is required since they introduced authentication.
        response = httpx.post(
            URLHAUS_API,
            data={"host": domain},
            headers={"Auth-Key": auth_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code != 200:
            return {
                "status": "error",
                "found": False,
                "url_count": 0,
                "threat_tags": [],
                "urlhaus_reference": None,
                "error_message": f"URLhaus returned HTTP {response.status_code}.",
            }

        data = response.json()
        query_status = data.get("query_status", "")

        if query_status == "no_results":
            # URLhaus doesn't have this domain in its malware feed.
            # Note: this means "not in our feed", NOT "definitely safe".
            # A brand-new phishing domain won't be in URLhaus yet.
            return {
                "status": "ok",
                "found": False,
                "url_count": 0,
                "threat_tags": [],
                "urlhaus_reference": None,
                "error_message": None,
            }

        # Domain is in the URLhaus database — gather the details.
        urls = data.get("urls", [])
        url_count = len(urls)

        # Collect unique threat tags from every URL entry.
        # tags can be null on some entries, so we guard with "or []".
        tags: set[str] = set()
        for url_entry in urls:
            for tag in (url_entry.get("tags") or []):
                tags.add(tag)

        return {
            "status": "ok",
            "found": True,
            "url_count": url_count,
            "threat_tags": sorted(tags),
            "urlhaus_reference": data.get("urlhaus_reference"),
            "error_message": None,
        }

    except httpx.TimeoutException:
        return {
            "status": "error",
            "found": False,
            "url_count": 0,
            "threat_tags": [],
            "urlhaus_reference": None,
            "error_message": "URLhaus request timed out (10 s).",
        }
    except Exception as exc:
        return {
            "status": "error",
            "found": False,
            "url_count": 0,
            "threat_tags": [],
            "urlhaus_reference": None,
            "error_message": f"URLhaus lookup failed: {exc}",
        }
