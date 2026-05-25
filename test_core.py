"""
Direct test of the checker core — no web server needed.

This script proves the architecture is correct: the checker core is a plain
Python function that can be called standalone, completely outside FastAPI.
It also proves a bare domain (like "example.com") works the same as a full URL,
which means the DNS resolver can call it next week with no changes to the core.

Run it:
    python test_core.py

Prerequisites:
    - You have created a .env file with VIRUSTOTAL_API_KEY=<your key>
    - You have installed dependencies:  pip install -r requirements.txt

─── How to test the malicious path ───────────────────────────────────────────

URLhaus publishes a live feed of confirmed malware domains. Any domain currently
listed there will return verdict="malicious". To find one safely:

  1. Visit https://urlhaus.abuse.ch/browse/ in your browser.
  2. Pick any domain shown in the "Host" column.
  3. Add it to TEST_TARGETS below (as a bare domain, e.g. "192.0.2.1" or "bad.example.com").
  4. Run this script.

Because this tool NEVER visits URLs (it only looks them up as text strings
against threat feed APIs), adding a known-bad domain to this test list is safe.
You are not fetching any malware — you are just asking "have others seen malware here?"
"""

import json
from dotenv import load_dotenv

load_dotenv()  # must come before importing checker so the API key is in os.environ

from checker.core import check  # noqa: E402

# ─── Test targets ──────────────────────────────────────────────────────────────
# Edit this list to add your own test cases.
TEST_TARGETS = [
    "https://www.google.com",             # well-known site          → expect: safe
    "https://totally-fake-zzz999abc.xyz", # made-up domain           → expect: unknown
    "example.com",                        # bare domain (no scheme)  → proves DNS-resolver path works
    "not a url at all",                   # junk input               → expect: error (422-style)
    "",                                   # empty string             → expect: error
    # Uncomment and replace with a real URLhaus domain to test the malicious path:
    # "some-domain-from-urlhaus.com",
]

# ─── Run ───────────────────────────────────────────────────────────────────────
print("LinkScout — core layer direct test")
print("=" * 60)

for target in TEST_TARGETS:
    label = repr(target) if len(target) < 55 else repr(target[:52] + "...")
    print(f"\nTarget: {label}")
    print("-" * 40)

    result = check(target)
    print(json.dumps(result, indent=2))

print("\n" + "=" * 60)
print("Done.")
print()
print("Key things to verify:")
print("  ✓ No Python exceptions above — errors came back as JSON dicts.")
print("  ✓ 'example.com' (bare domain) produced a verdict, not an error.")
print("    That confirms the DNS resolver can call check() next week.")
print("  ✓ 'from_cache: false' on first run; 'from_cache: true' if you run again.")
