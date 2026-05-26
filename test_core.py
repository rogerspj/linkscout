"""
Direct test of the checker core — no web server needed.

This script proves the architecture is correct: the checker core is a plain
Python function that can be called standalone, completely outside FastAPI.
It also proves a bare domain (like "example.com") works correctly, confirming
the DNS resolver can call check() next week with no changes to the core.

Run it:
    python test_core.py

Prerequisites:
    - .env file with VIRUSTOTAL_API_KEY and URLHAUS_AUTH_KEY set
    - pip install -r requirements.txt

─── Verdict reference ─────────────────────────────────────────────────────────

  dangerous   — high-confidence bad signal from at least one source
  disputed    — sources CONFLICT: one says bad, the other affirmatively says clean
  suspicious  — weak/partial signal from VT, URLhaus has no data (not disagreeing)
  likely_safe — VT checked many engines and found nothing; URLhaus has no record
  unknown     — neither source has any data on this target

─── Key distinction: disputed vs suspicious ───────────────────────────────────

  disputed   = real conflict  (one source says bad + other says clean)
  suspicious = thin evidence  (weak signal + the other source is simply silent)

─── How to test the malicious/dangerous path ──────────────────────────────────

  URLhaus publishes a live feed of confirmed malware at https://urlhaus.abuse.ch/browse/

  Because this tool NEVER visits URLs (only text lookups against threat APIs),
  it is safe to add a known-bad domain here. You are not fetching malware — you
  are asking "have others reported malware here?"

  To test:
    1. Visit https://urlhaus.abuse.ch/browse/ and copy any domain from "Host" column.
    2. Add it as a bare domain entry in TEST_TARGETS below.
    3. Run this script — expect verdict="dangerous", explanation citing URLhaus.

─── URL-level vs host-level URLhaus checks ────────────────────────────────────

  Full URL input  → URLhaus URL-level check  (precise: just that path)
  Bare domain     → URLhaus host-level check (broad: whole host's history)

  This is why "https://www.google.com" and "google.com" can produce different
  URLhaus results. The URL-level check for https://www.google.com/ finds no
  malware entry for that specific URL. The host-level check for google.com may
  find stale host entries. If VT is clean and URLhaus host-level has a hit,
  the verdict is "disputed" — sources disagree, not "dangerous".
"""

import json
from dotenv import load_dotenv

load_dotenv()  # must come before importing checker so the API keys are in os.environ

from checker.core import check  # noqa: E402

# ─── Test targets ──────────────────────────────────────────────────────────────
# Each entry is (target, expected_verdict_or_None, note)
# expected=None means "just show the result, don't assert"
TEST_TARGETS = [
    # Full URL — URLhaus checked at URL-level (precise path check)
    # Should NOT inherit the host's reputation. Expect: likely_safe or unknown.
    ("https://www.google.com",             None,  "full URL, URL-level URLhaus"),

    # Bare domain — URLhaus checked at host-level (whole-host reputation)
    # If URLhaus has a stale host entry and VT is clean → expect: disputed
    # If both clean → expect: likely_safe or unknown
    ("google.com",                         None,  "bare domain, host-level URLhaus"),

    # Same domain, two lookup levels → demonstrates URL vs host distinction.
    # Run both and compare the URLhaus lookup_level and verdict fields.

    # Made-up domain with no history anywhere → expect: unknown
    ("https://totally-fake-zzz999abc.xyz", None,  "made-up domain, full URL"),

    # Bare domain architecture check — proves the DNS resolver path works.
    # A bare domain must produce a verdict dict, not an error.
    ("example.com",                        None,  "bare domain, architecture check"),

    # Invalid inputs — must return error=True, not crash.
    ("not a url at all",                   None,  "junk input"),
    ("",                                   None,  "empty string"),

    # Known URLhaus malware URL — URL-level check, expect: dangerous
    # Safe to include: this tool never visits URLs, only looks them up as text.
    ("http://115.58.90.247:41590/bin.sh",  None,  "known URLhaus malware URL, dangerous expected"),

    # ── Add more from https://urlhaus.abuse.ch/browse/ as needed ──
    # ("some-host-from-urlhaus.com",        None,  "known-bad host"),
]

# ─── Run ───────────────────────────────────────────────────────────────────────
print("LinkScout — core layer direct test")
print("=" * 65)

for target, _expected, note in TEST_TARGETS:
    label = repr(target) if len(target) < 50 else repr(target[:47] + "...")
    print(f"\nTarget : {label}")
    print(f"Note   : {note}")
    print("-" * 45)

    result = check(target)
    print(json.dumps(result, indent=2))

print("\n" + "=" * 65)
print("Done.\n")
print("Key things to verify:")
print("  1. 'https://www.google.com' verdict is likely_safe or unknown,")
print("     NOT dangerous — URL-level URLhaus should not find that specific URL.")
print()
print("  2. 'google.com' (bare domain) — if URLhaus host-level has a stale")
print("     entry and VT is clean, verdict is 'disputed', NOT 'dangerous'.")
print("     The explanation names both sources and the conflict.")
print()
print("  3. 'example.com' (bare domain) produced a verdict dict, not an error.")
print("     That confirms check('evil.com') works — the DNS resolver is ready.")
print()
print("  4. Every successful result has an 'explanation' field with real numbers.")
print()
print("  5. sources.urlhaus.lookup_level is 'url' for full URLs, 'host' for domains.")
print()
print("  6. Run twice — second run should show from_cache: true for the same targets.")
