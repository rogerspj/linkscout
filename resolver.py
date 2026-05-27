"""
resolver.py — LinkScout filtering DNS resolver.

Listens on a non-standard port (LISTEN_PORT, default 5353) and for every DNS
query calls the existing checker core, then either blocks or forwards:

  verdict "dangerous"              → BLOCK  (return 0.0.0.0 / ::)
  anything else, or check() error  → ALLOW  (forward to upstream DNS)

This is the architecture payoff: check() is imported unchanged from the same
package the FastAPI web layer uses. The resolver is just a second caller.

Usage:
    python resolver.py

DO NOT change LISTEN_PORT to 53 during development. Port 53 is the system DNS
port — binding to it requires admin rights and can break name resolution for
the whole machine. Use the non-standard port and query it explicitly (see below).

Test from a second PowerShell window while resolver.py is running:
    Resolve-DnsName -Name example.com -Server 127.0.0.1 -Port 5353
    python dns_query.py
"""

import logging
import os
import socket
import sys
import time

from dotenv import load_dotenv

# load_dotenv() must run before importing checker so the API keys are in os.environ.
load_dotenv()

from dnslib import DNSRecord, RR, QTYPE, A, AAAA
from dnslib.server import DNSServer, BaseResolver

from checker.core import check


# ─── Configuration ─────────────────────────────────────────────────────────────
# All tuneable knobs are here so they're easy to find.

# The port this resolver listens on. Use any free port >= 1024.
# DO NOT change to 53 during development — that's the system DNS port.
LISTEN_HOST  = "127.0.0.1"   # localhost only; not reachable from other machines
LISTEN_PORT  = 5353

# Where to forward allowed queries.
UPSTREAM_DNS  = "1.1.1.1"    # Cloudflare. Change to "8.8.8.8" for Google.
UPSTREAM_PORT = 53
FORWARD_TIMEOUT_SECONDS = 5  # how long to wait for upstream to reply

# TTL (seconds) on sinkhole records we synthesise for blocked domains.
# Short TTL so the block clears quickly if we change our mind.
BLOCK_TTL = 60

# Verdicts that are ALLOWED but logged at WARNING so you can see them passing.
# These are the "gray area" — real signal but not enough to block a whole domain.
GRAY_VERDICTS = {"disputed", "suspicious"}

# ── Test hook ──────────────────────────────────────────────────────────────────
# Add domain strings here to force them blocked without a live check() call.
# Use this to verify the block path when you don't have a real dangerous domain handy.
# Must be empty in production.
#
# Example to test blocking:
#   FORCE_BLOCK_DOMAINS = {"test-block.local"}
FORCE_BLOCK_DOMAINS: set[str] = set()


# ─── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("linkscout.resolver")


class _QuietDNSLogger:
    """
    No-op object passed to dnslib so its default print()-based output is
    suppressed. We do our own structured logging in LinkScoutResolver.
    """
    def log_recv(self, *a): pass
    def log_send(self, *a): pass
    def log_request(self, *a): pass
    def log_reply(self, *a): pass
    def log_truncated(self, *a): pass
    def log_error(self, *a): pass
    def log_data(self, *a): pass


# ─── Resolver ──────────────────────────────────────────────────────────────────

class LinkScoutResolver(BaseResolver):
    """
    dnslib BaseResolver subclass — the only place policy lives.

    Block policy (by design, from the brief):
      Only "dangerous" is blocked. Disputed, suspicious, unknown, and likely_safe
      all pass through. This is intentional: at the DNS layer we see the whole
      domain, never a specific path. A whole-domain block is a blunt instrument.
      We refuse to block on weak or conflicting evidence — that's how you nuke
      google.com over a stale URLhaus host entry.

    Latency note (MVP known limitation):
      The first lookup for any domain involves live HTTP calls to VirusTotal and
      URLhaus (up to ~10 s each). The checker core's 1-hour in-memory cache softens
      repeat lookups. Future optimisation: pre-load a static blocklist so the hot
      path never needs a live check.
    """

    def resolve(self, request, handler) -> DNSRecord:
        # DNS names carry a trailing dot ("example.com.") — strip it.
        domain = str(request.q.qname).rstrip(".")

        # ── Test hook: force a block without a live check() call ──────────────
        if domain in FORCE_BLOCK_DOMAINS:
            log.warning(
                "BLOCK  %-35s  forced via FORCE_BLOCK_DOMAINS (test hook)", domain
            )
            return self._block(request)

        # ── Call the checker core ─────────────────────────────────────────────
        # check() accepts a bare domain — URLhaus will do a host-level lookup,
        # which is exactly what a DNS resolver needs (it sees domains, not URLs).
        # check() never raises; errors come back as result dicts with error=True.
        try:
            result  = check(domain)
            verdict = result.get("verdict") or "unknown"
            errored = result.get("error", False)
        except Exception as exc:
            log.warning(
                "ALLOW  %-35s  check() raised unexpectedly (%s) — forwarding",
                domain, exc,
            )
            return self._forward(request)

        if errored:
            # Our URL validator rejected something the DNS system considers valid
            # (e.g. a single-label name like "localhost"). Allow it through.
            log.debug("ALLOW  %-35s  validator rejected — forwarding", domain)
            return self._forward(request)

        # ── Block or forward based on verdict ─────────────────────────────────
        if verdict == "dangerous":
            self._log_block(domain, result)
            return self._block(request)
        else:
            self._log_allow(domain, verdict, result)
            return self._forward(request)

    # ── Response builders ──────────────────────────────────────────────────────

    def _block(self, request) -> DNSRecord:
        """
        Return a DNS sinkhole response.
          A    queries → 0.0.0.0   (IPv4 null address)
          AAAA queries → ::        (IPv6 null address)
          Other types  → empty answer (MX, TXT, etc. just come back empty)
        The client tries to connect to the null address and immediately fails.
        This is the same technique used by Cloudflare 1.1.1.2 and Pi-hole.
        """
        reply = request.reply()
        qtype = request.q.qtype
        if qtype == QTYPE.A:
            reply.add_answer(
                RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=BLOCK_TTL)
            )
        elif qtype == QTYPE.AAAA:
            reply.add_answer(
                RR(request.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=BLOCK_TTL)
            )
        # Other query types: return an empty answer section — the client finds nothing.
        return reply

    def _forward(self, request) -> DNSRecord:
        """
        Forward the DNS query to the upstream resolver over UDP and return
        its parsed reply. Returns SERVFAIL if the upstream is unreachable.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(FORWARD_TIMEOUT_SECONDS)
        try:
            sock.sendto(request.pack(), (UPSTREAM_DNS, UPSTREAM_PORT))
            data, _ = sock.recvfrom(4096)
            return DNSRecord.parse(data)
        except socket.timeout:
            log.error("Upstream DNS (%s:%d) timed out", UPSTREAM_DNS, UPSTREAM_PORT)
        except Exception as exc:
            log.error("Upstream DNS error: %s", exc)
        finally:
            sock.close()
        # Reached only when an exception was caught above.
        reply = request.reply()
        reply.header.rcode = 2  # SERVFAIL — tell the client to retry
        return reply

    # ── Logging helpers ────────────────────────────────────────────────────────

    def _log_block(self, domain: str, result: dict) -> None:
        sources  = result.get("sources") or {}
        uh       = sources.get("urlhaus", {})
        vt       = sources.get("virustotal", {})
        tags     = uh.get("threat_tags") or []
        vt_mal   = vt.get("malicious") or 0
        vt_total = vt.get("total_engines") or 0
        tag_str  = f"UH tags=[{', '.join(tags)}]" if tags else "UH no tags"
        vt_str   = f"VT {vt_mal}/{vt_total}" if vt_total else "VT no data"
        log.warning("BLOCK  %-35s  dangerous  %s  %s", domain, tag_str, vt_str)

    def _log_allow(self, domain: str, verdict: str, result: dict) -> None:
        if verdict in GRAY_VERDICTS:
            # Real signal but not enough to block — log at WARNING so it's visible.
            explanation = result.get("explanation", "")
            log.warning("ALLOW  %-35s  %-12s  %s", domain, verdict, explanation)
        else:
            # likely_safe / unknown — routine, quiet log so it doesn't drown output.
            log.debug("ALLOW  %-35s  %s", domain, verdict)


# ─── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    resolver = LinkScoutResolver()
    server   = DNSServer(
        resolver,
        port=LISTEN_PORT,
        address=LISTEN_HOST,
        logger=_QuietDNSLogger(),
    )

    vt_key  = "set" if os.environ.get("VIRUSTOTAL_API_KEY") else "MISSING ← checks won't work"
    uh_key  = "set" if os.environ.get("URLHAUS_AUTH_KEY")  else "MISSING ← checks won't work"

    log.info("LinkScout DNS resolver")
    log.info("  Listen    %s:%d (UDP)", LISTEN_HOST, LISTEN_PORT)
    log.info("  Upstream  %s:%d", UPSTREAM_DNS, UPSTREAM_PORT)
    log.info("  Block     verdict=dangerous → 0.0.0.0 / ::")
    log.info("  Allow     all other verdicts → forwarded upstream")
    log.info("  VT key    %s", vt_key)
    log.info("  UH key    %s", uh_key)
    if FORCE_BLOCK_DOMAINS:
        log.info("  TEST HOOK ACTIVE: %s", FORCE_BLOCK_DOMAINS)
    log.info("─" * 60)

    server.start_thread()

    log.info("Resolver running. From a second PowerShell window:")
    log.info("  Resolve-DnsName -Name example.com -Server 127.0.0.1 -Port %d", LISTEN_PORT)
    log.info("  python dns_query.py")
    log.info("─" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.stop()
