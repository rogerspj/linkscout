# Week 10 - LinkScout: Domain Age, React Frontend, EC2 Deployment, Browser Extension

## What I Did

### Domain Age Signal

Added a domain registration age as a visible signal in every LinkScout result. The data comes from VirusTotal's existing domain report, which already returns a `creation_date` field (Unix timestamp from WHOIS) with no new API calls or new dependencies required. The checker core calculates age in days and maps it to one of four categories:

- Under 30 days: very new, note flags common use in phishing campaigns
- 30 days to 1 year: relatively new, note suggests extra caution
- Over 1 year: established, note treats as a reassuring signal but still no guarantee of safety 
- Unavailable: WHOIS data not collected or privacy-protected

Every result now includes `domain_age_days`, `domain_age_label`, and `domain_age_note` fields at the top level. The note is written for a non-technical user: instead of just showing a date, it explains what the age means in context. Domain age deliberately does not affect the verdict. A brand new domain that is otherwise clean stays `likely_safe`.

### React Web Frontend

Built the first user-facing interface for LinkScout. A single-page React app served from the same EC2 as the backend. A user pastes a URL into the input field, hits Check, and sees:

- Headline verdict color-coded by severity (red for dangerous, amber for disputed, yellow for suspicious, gray for unknown, green for likely_safe)
- Human-readable explanation string citing real numbers and tags
- Domain age displayed as a dedicated line with the contextual note
- Per-source breakdown showing what VirusTotal and URLhaus each said independently
- Cache indicator showing whether the result came from a live API call or the in-memory cache

All three error states confirmed working: invalid input caught client-side before any API call, graceful degradation when a source returns an error (the source shows as greyed-out with "no info" rather than silently affecting the verdict), and a retry prompt with a clear message when the backend is unreachable.

This was my first time doing web frontend work. 

### EC2 Deployment

Deployed LinkScout to the existing EC2 alongside Bristle, following the same hardening pattern:

- Dedicated `LinkScout` system user with no login shell and no home directory
- Files at `/opt/LinkScout/`, owned by the LinkScout user
- Python venv at `/opt/LinkScout/venv/`
- `.env` at `/opt/LinkScout/.env` with permissions set to 600 (readable only by the LinkScout user)
- systemd unit (`LinkScout.service`) with `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, and `PrivateTmp` directives
- FastAPI/Uvicorn listening on `127.0.0.1:8001` (not exposed directly to the internet)
- nginx routing `/api/` to port 8001 and serving the React static files from the root path
- Bristle moved to `/bristle/` to make room for LinkScout at the root

The React app is built locally with `npm run build` and deployed as static files via `scp`. The server does not need Node.js installed. nginx serves the built output directly.

Moving Bristle off the root path required updating the Flutter app's base URL constant and confirming the app still connected correctly to the backend. The Flutter app runs on a local emulator, so this was a local code change and rebuild rather than a server-side change.

### Browser Extension

Built a Chrome extension (Manifest V3) that adds "Check with LinkScout" to the right-click context menu on any link. The extension is vanilla JavaScript with no build step, directly loadable in Chrome via "Load unpacked."

User flow: right-click any link → "Check with LinkScout" → condensed popup appears near the link showing verdict (color-coded), explanation, and domain age → "See full details" link opens the deployed EC2 frontend in a new tab with the URL pre-filled and auto-submitted.

The key architecture constraint in Manifest V3: the fetch to the EC2 backend must happen in the background service worker (`background.js`), not the content script (`content.js`). Content scripts run in the page context and are subject to CORS restrictions that would block cross-origin requests. The background service worker does not have this restriction. The two communicate via `chrome.tabs.sendMessage` and `chrome.runtime.sendMessage`.

Firefox compatibility: the extension loads and runs in Firefox, but Firefox upgrades HTTP requests to HTTPS for extension background scripts due to Content Security Policy enforcement. Since the EC2 currently has no SSL certificate (which requires a domain name for Let's Encrypt), the fetch fails in Firefox. This is a documented constraint. The fix requires a domain name pointed at the EC2, which is outside the scope of this project.

All work committed and pushed to github.com/rogerspj/linkscout throughout the week.

---

## Why I Did It This Way

**Domain age as context, not verdict:** Displaying domain age was a cool idea from Spencer. I decided to keep the domain age separate from the overall verdict. A brand new domain can definitely be a sign of a phishing attack. However, a new domain is not automatically malicious. Similarly, an old domain can provide a false sense of security if an attacker is able to compromise an established domain. The contextual note gives the user enough to pause and double-check without the tool making a judgment call it can't defend.

**No new API for domain age:** VirusTotal already returns `creation_date` in the domain report that the checker was fetching. Adding domain age cost zero additional API calls and zero additional rate limit exposure. The data was already there, it just wasn't being used.

**Static file deployment for the React frontend:** The React app has no server-side rendering. Building it locally with Vite and deploying the static output means nginx serves HTML, CSS, and JavaScript files directly without any Node.js process running on the server. Simpler, more secure, and consistent with the principle of not running more processes than necessary.

**Vanilla JavaScript for the browser extension:** No build step, no npm, no bundler. Every file in the extension folder is human-readable. For a project where understanding what I built matters more than optimization, keeping it as plain as possible was the goal. The extension is loadable directly from the folder with no compilation.

**Background service worker for the API fetch:** Content scripts run in the context of the web page they're injected into, which means they're subject to the same restrictions as page JavaScript. Keeping the API call in the background service worker keeps it isolated from the page context entirely.

---

## Connection to Learning Objectives

**Unit 2 - Security on the OS:** The LinkScout deployment follows the same POLP pattern as Bristle. The service account has no login shell and no home directory. The `.env` file is readable only by the service account. The process listens on localhost only. The same discipline applied to the second project without having to figure it out again, which is the point of establishing patterns.

**Unit 3 - Logging and Auditing:** The browser extension deployment highlighted a logging gap. There is currently no centralized visibility into what the nginx, bristle, and LinkScout services are doing across the EC2. Running `journalctl -u LinkScout.service` shows that `137.184.222.119` was hitting the server at 4:47am requesting `/cmd.js`, `/error.save`, `/debug.bak`, `/cmd.log`, and `/docker-compose.rb` in rapid succession. Every one returned 404. The hardening held, but the only way to know that was to manually query the logs. The lack of aggregated, anomaly-aware log monitoring is the most visible gap in the current setup. Will develop a tool called LogScout to do this.

**Unit 6 - Personnel Security:** The browser extension is the most direct implementation of a security awareness training gap. A user who receives a suspicious link in a message doesn't need to remember a training slide. They can right-click before visiting and the tool tells them what the feeds say. The extension meets users at the moment of decision rather than expecting recalled training to guide behavior under pressure.

---

## What I Learned

**Deploying a second service to the same server requires thinking about blast radius before touching nginx.** Moving Bristle off the root path to make room for LinkScout had a downstream effect on the Flutter app that I almost missed. Any nginx change that affects existing routes needs to be traced to every client that depends on those routes before reloading. The `nginx -t` discipline from the Bristle deployment carried over, but the scope check of "who else depends on this?" was the new lesson.

**Chrome and Firefox handle extension network requests differently in ways that matter.** Chrome's Manifest V3 service worker does not send an `Origin` header, so CORS middleware never sees it. Firefox's background page does send an origin (`moz-extension://[uuid]`), and if that origin isn't in the CORS allowlist the request gets blocked. The same code that works in Chrome silently fails in Firefox for a reason that isn't obvious until you check the extension's background console. Beyond CORS, Firefox also enforces HTTPS upgrades for extension network requests, which means HTTP-only backends are blocked entirely regardless of CORS configuration. The fix (HTTPS with a real SSL certificate) requires a domain name. Creating the Chrome extension was easy enough that I wasn't expecting the challenge of getting a Firefox extension to work.

**A static public IP with no domain name is a real constraint that compounds over time.** No domain means no Let's Encrypt, no HTTPS, no Firefox extension support, no clean URLs to give people. Every project deployed to this EC2 inherits that constraint. The right time to think about this was before deploying anything, not after building a browser extension that half-works because of it. Infrastructure decisions made early echo through everything built on top of them.