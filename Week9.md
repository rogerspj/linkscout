# Week 9 - linkscout: Threat Intel Pipeline, Verdict Logic, and DNS Resolver

## What I Did

### Threat Intel Checker Core

Built the foundation of linkscout: a framework-agnostic checker core that takes a URL or bare domain, queries two threat intelligence sources, and returns a combined verdict with a human-readable explanation.

- VirusTotal integration: domain-level lookup returning detection counts across 90+ engines
- URLhaus integration: checks at URL level when given a full URL, host level when given a bare domain
- In-memory cache with a 1-hour TTL so repeated lookups of the same target are instant and don't burn API quota
- Input validation rejecting malformed inputs before any API call is made
- Graceful degradation: if either source fails, the tool marks that source as unavailable rather than treating silence as a clean bill of health

The core is deliberately separated from the web layer. It exports a single `check()` function that knows nothing about HTTP requests, FastAPI, or DNS. Any caller can import and use it.

### Five-Verdict Logic and Explanation Strings

Replaced the original "worst source wins" system with a verdict that reflects whether or not the two sources agree:

- `dangerous`: sources agree it's bad, or URLhaus has a confirmed hit (curated feed, high confidence)
- `disputed`: sources conflict, one flags it bad while the other says clean
- `suspicious`: weak signal from one source, silence from the other
- `unknown`: neither source has any data
- `likely_safe`: no detections, but hedged rather than a confident "safe"

Every result includes a human-readable explanation string citing real numbers and tags so users can see the reasoning, not just a verdict label. A one-word verdict is useful for a quick answer, but the explanation lets users actually evaluate whether they agree with the tool's reasoning.

### FastAPI Web Layer

Built a thin web layer on top of the core exposing a health check and a POST endpoint for on-demand URL checking. The web layer calls `check()` and returns the result as JSON. It knows nothing about threat feeds.

### Filtering DNS Resolver

Built a filtering DNS resolver using dnslib that reuses the same `check()` core. For each domain lookup it receives, it calls `check()` on the bare domain and applies a policy: block on `dangerous` (return `0.0.0.0`), allow everything else but log any non-clean verdict as a warning. Clean allows are logged quietly; gray-area decisions are logged at WARNING with the full explanation.

The resolver is a third independent caller of the same core, alongside the web layer and the test script.

All work committed and pushed to github.com/rogerspj/linkscout throughout the week. '.env' containing API keys for VirusTotal and URLhaus stayed local and was never tracked or pushed.

---

## Why I Did It This Way

- The DNS resolver was added as a suggestion from Spencer, who pointed out that filtering at the chokepoint would cover all channels at once. If the judgment logic had been tangled inside the FastAPI handler, extracting it later would have meant rework. Keeping `check()` as a standalone function meant the resolver was a clean addition rather than a refactor. 

- URLhaus tracks malicious URLs, not just domains. Querying at the host level when given a full URL would include any malicious path across the entire domain. When a user pastes a specific link, I want it to check that specific link. The resolver gets host-level queries because DNS sees domains, not paths. The tool picks the right level automatically.

- At the DNS layer, a block covers the entire domain. Blocking on weak or conflicting evidence would mean blocking legitimate domains that happen to share infrastructure with a malicious URL. The policy refuses to do this. Gray-area decisions pass through but are logged so nothing slips by invisibly. I prefer this method compared to the tool over-blocking and driving away users.

- Intentionally made the safest verdict read as "likely safe" rather than "safe." No detections isn't the same as verified clean, especially for new domains with no history.

- 1-hour cache. Caching indefinitely would recreate the staleness problem DNS filters are designed to avoid. A URL can be clean now and weaponized later. One hour is long enough to absorb bursts of repeated queries, but short enough that a freshly-armed domain gets re-checked soon.

---

## Connection to Learning Objectives

- Unit 6 - Personnel Security: linkscout is designed to help users who can't or don't reliably apply whatever security awareness training they have received. When this type of user receives a link they can use this tool if they don't know what to look for when they receive a suspicious-looking link. If they don't think to specifically check the URL, then the DNS resolver can make that decision for them at the chokepoint. 

- Unit 2 - Security on the OS: POLP applied at the application layer. The resolver and web layer are designed as separate services with separate concerns, following the same least-privilege thinking as the Bristle service account on Bristle's EC2. Neither component has access to more than it needs.

- Unit 3 - Logging and Auditing: Block decisions are always logged. Gray-area allows are logged at WARNING with the full explanation so they're visible. Clean allows are logged quietly at DEBUG. The goal is visibility into what's happening without noise drowning out the signal.


---

## What I Learned

- The biggest learning point happened early when something didn't go as planned. Google.com came back as `malicious` on the first test run because URLhaus had one stale host entry tagged AsyncRAT, while VirusTotal's 91 engines all said clean. The two sources contradicted each other on one of the most-visited domains on the internet. This result validated the design decision to show both sources separately rather than collapsing them into one number. A tool that had trusted either source alone would have been wrong. That entry disappeared from URLhaus the next day, reappeared the day after, and the `disputed` verdict I designed specifically to handle it never fired in testing because the data underneath kept shifting.

- The resolver correctly judged every domain and logged every decision, but couldn't return real IPs to the client because the upstream forward to 1.1.1.1 timed out. This is a constraint, not a code issue. A filtering resolver deployed in an environment that blocks outbound DNS needs to either run as the network's designated resolver or use DNS-over-HTTPS to forward queries over port 443 instead. This can be a future improvement.

- Two AI assistants gave me confident, contradictory answers about whether a bug was real. The `domain` field in the checker output appeared to contain markdown link syntax in pasted output. Claude flagged it as a bug. Clyde read the actual code, traced the execution path, and concluded it was a rendering artifact. Both AI assistants were confident that they were correct. I ran repr() and confirmed there was no bug. Claude's bug diagnosis was wrong while Clyde's confidence was right.

