"""
VirusTotal source module.

Responsibility: fetch raw data from VirusTotal and return it as a plain dict.
No verdict logic lives here — core.py decides what the numbers mean.
This keeps the threshold tuning in one obvious place.
"""

import os
import httpx

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 10.0


def check_domain(domain: str) -> dict:
    """
    Query VirusTotal's domain report endpoint for the given domain.

    Returns a dict with raw stats. This function never raises — errors come back
    as status="error" or status="rate_limited" so core.py can handle them.

    Returned fields:
      status        : "ok" | "not_found" | "rate_limited" | "error" | "no_key"
      malicious     : int or None  — engines that flagged the domain as malicious
      suspicious    : int or None  — engines that flagged it as suspicious
      total_engines : int or None  — total engines that checked the domain
      permalink     : str or None  — link to the full report on the VT website
      error_message : str or None  — plain-English explanation if status != "ok"
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        # Tell the caller clearly rather than failing with a confusing HTTP 401.
        return {
            "status": "no_key",
            "malicious": None,
            "suspicious": None,
            "total_engines": None,
            "permalink": None,
            "error_message": "VIRUSTOTAL_API_KEY is not set. Add it to your .env file.",
        }

    url = f"{VIRUSTOTAL_API_BASE}/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = httpx.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)

        if response.status_code == 429:
            # The free tier allows roughly 4 requests/minute and 500/day.
            # The in-memory cache should prevent hitting this in normal use,
            # but it can happen on first-run bursts.
            return {
                "status": "rate_limited",
                "malicious": None,
                "suspicious": None,
                "total_engines": None,
                "permalink": None,
                "error_message": (
                    "VirusTotal rate limit reached (free tier: ~4 req/min). "
                    "Wait a moment and try again — or check a different URL first."
                ),
            }

        if response.status_code == 404:
            # VT has simply never analysed this domain. We return zeros so
            # core.py can tell "VT checked, found nothing" from "VT was unreachable".
            return {
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "total_engines": 0,
                "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
                "error_message": None,
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "malicious": None,
                "suspicious": None,
                "total_engines": None,
                "permalink": None,
                "error_message": f"VirusTotal returned unexpected HTTP {response.status_code}.",
            }

        # Happy path — parse the response
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)
        total = malicious + suspicious + harmless + undetected + timeout

        return {
            "status": "ok",
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
            "error_message": None,
        }

    except httpx.TimeoutException:
        return {
            "status": "error",
            "malicious": None,
            "suspicious": None,
            "total_engines": None,
            "permalink": None,
            "error_message": "VirusTotal request timed out (10 s). The service may be slow.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "malicious": None,
            "suspicious": None,
            "total_engines": None,
            "permalink": None,
            "error_message": f"VirusTotal lookup failed: {exc}",
        }
