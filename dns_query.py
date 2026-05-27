"""
dns_query.py — test client for the LinkScout resolver.

Sends DNS queries directly to the resolver's non-standard port and prints
the results. Run this from a second terminal while resolver.py is running.

Usage:
    python dns_query.py

No extra dependencies needed — dnslib is already in requirements.txt.
"""

import socket
import sys
from dnslib import DNSRecord, QTYPE

RESOLVER_HOST = "127.0.0.1"
RESOLVER_PORT = 5353
TIMEOUT       = 10   # seconds; first-time queries can be slow (live VT + UH calls)


def query(domain: str) -> None:
    """Send an A-record query to the resolver and print the answer."""
    request = DNSRecord.question(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(request.pack(), (RESOLVER_HOST, RESOLVER_PORT))
        data, _ = sock.recvfrom(4096)
        reply = DNSRecord.parse(data)

        answers = reply.rr
        print(f"\n{'─' * 55}")
        print(f"Query : {domain}")
        if answers:
            for rr in answers:
                print(f"Answer: {rr.rdata}")
            # Flag if we got the sinkhole address
            for rr in answers:
                if str(rr.rdata) in ("0.0.0.0", "::"):
                    print("*** BLOCKED by resolver (sinkhole address returned) ***")
        else:
            print("Answer: (empty — may be blocked for non-A type, or NXDOMAIN)")
    except socket.timeout:
        print(f"\nERROR: No response from {RESOLVER_HOST}:{RESOLVER_PORT} after {TIMEOUT}s.")
        print("Is resolver.py running?")
        sys.exit(1)
    finally:
        sock.close()


# ─── Test targets ──────────────────────────────────────────────────────────────
# Edit this list to try other domains.
TEST_DOMAINS = [
    # Clean domain — expect: real IP forwarded from upstream, verdict logged as
    # likely_safe or unknown. NOT 0.0.0.0.
    "example.com",

    # Well-known site — same expectation. If google.com has a stale URLhaus
    # host entry, the resolver log will show "disputed" but the query still
    # passes through (disputed is not blocked).
    "www.google.com",

    # Add a known-bad domain from https://urlhaus.abuse.ch/browse/ to verify
    # the block path. The resolver log should show BLOCK and you should get 0.0.0.0.
    # "some-host-from-urlhaus.com",

    # Tests the forced-block path. Make sure FORCE_BLOCK_DOMAINS = {"test-block.local"}
    # is set in resolver.py before querying this — otherwise it will just forward.
    "test-block.local",
]


if __name__ == "__main__":
    print(f"LinkScout DNS query test  →  {RESOLVER_HOST}:{RESOLVER_PORT}")
    print(f"(First query per domain can take a few seconds — live VT + URLhaus calls)")

    for domain in TEST_DOMAINS:
        query(domain)

    print(f"\n{'─' * 55}")
    print("Done. Check resolver.py's terminal for the verdict and log lines.")
    print()
    print("What to look for in the resolver log:")
    print("  ALLOW  example.com  likely_safe  ← forwarded, real IP returned")
    print("  ALLOW  google.com   disputed     ← gray area, forwarded but logged at WARNING")
    print("  BLOCK  bad-domain   dangerous    ← sinkhole, you get 0.0.0.0 here")
