# Nmap Command Center — sequential assessment edition

Dockerized Next.js / FastAPI workspace for authorization-scoped Nmap assessment sessions. Includes **up to three ordered Nmap commands per session**, an editable validated command-options field, reactive full-command previews, built-in NSE catalog browsing, admin-reviewed diagnostic script combinations, quarantined `.nse` / `.lua` uploads, scan history, status/log polling, cancellation, and exports.

## Start

```bash
cp .env.example .env
# Edit .env: set a unique ADMIN_TOKEN and authorized target scope.
# For private lab scripts, enable LAB_MODE_ENABLED and set LAB_ALLOWED_IPS.
docker compose up --build -d
```

Open **http://localhost:3000**. Docker builds the Next.js app and an Nmap-equipped scanner. Use `docker compose logs -f scanner` to inspect worker logs.

## Pages

- `/new` — input authorized IP / CIDR / DNS hostname / HTTP(S) URL, configure 1–3 steps, combine eligible NSE scripts, change validated Nmap flags, preview and launch sequential commands. Each step waits for the previous one and the session stops on failure.
- `/scripts` — all scripts found in the installed Nmap `script.db` plus installed nselib Lua modules (full catalog, filter by category, official NSEDoc links); enabled and individually reviewed checks can be selected in `/new`. Upload `.nse` and `.lua` files (up to 100 KB) for **quarantined administrative review**. Uploaded Lua is **not executed**.
- `/scan/<id>` — step-by-step status, logs, results, commands and per-step exports, plus passive references to Vulners, Exploit Database, NVD, OSV, GitHub advisories and CISA KEV.
- `/history` — saved sessions.
- `/settings` — effective scope, quotas, and administrator-approved target registration.

## Scope and command security

**The app does not scan arbitrary external hosts without authorization.** CIDRs are validated against `ALLOWED_CIDRS`; hostnames / HTTP(S) URLs are accepted when all resolved IP addresses fall inside those networks, or when the exact hostname is in `ALLOWED_HOSTNAMES`. Network administrators set these in `.env`. The scanner pins resolved addresses before running Nmap and does not feed URLs or arbitrary user text into a shell. URL paths are ignored.

The editable options field supports only limited Nmap scan flags: `-sT`, `-sU`, `-sV`, `-O`, `-sn`, `-Pn`, `-F`, `--reason`, `--traceroute`, `--open`, `--version-light`, `-T0`…`-T4`, `-p` with a validated port list, `--top-ports` (1…100), and `--script` with explicitly eligible script names. A command entered with a `nmap` prefix is also allowed; other programs, redirection, output paths, target overrides, shell operators, NSE script arguments, and dangerous flags are rejected. The server enforces `--max-rate 150`, `--max-retries 2` and an isolated output path.

The NSE catalog is read from Nmap's installed `script.db`, normally `/usr/share/nmap/scripts/script.db`. Scripts in `safe` or `default` categories without high-impact tags are enabled. Other diagnostic scripts can be individually approved by an administrator after review. Brute-force, exploit, DoS and fuzzing scripts can be approved for tightly scoped private labs, as described below. External, broadcast and target-expansion scripts remain reference-only; other intrusive scripts require explicit administrator review; malware-tagged scripts remain blocked. Some scripts have operational caveats even if marked safe; obtain written authorization and test against a staging system first.

Custom NSE/Lua uploads go to `./data/custom-quarantine` (inside the scanner volume). Those files are **never automatically loaded, compiled, imported, or promoted**. NSE scripts are not sandboxed by Nmap. Administrative code review and a separate approval mechanism would be required to permit custom execution.

## Limits and deployment notes

- Up to **3 steps per session**, executed serially; sessions may overlap up to **2 active sessions**.
- Default **256 addresses** and **30 minutes per step**, with enforced rate bounds. A nonzero step exit stops the session.
- The scanner holds job metadata in JSON and stores output in `./data`, but its job registry is in memory. Restarting the scanner disrupts active jobs. Production needs durable scheduling, database, SSO/RBAC, audit trail, encryption, network isolation and separate user permissions.
- Use an authenticated reverse proxy and trusted VPN before exposing the web service beyond localhost. Do not expose the scanner directly.
- References to Vulners, Exploit-DB, OSV, etc. are **passive links**, not automatic API integrations or exploit modules.

Official resources: [NSEDoc](https://nmap.org/nsedoc/), [NSE categories and safety](https://nmap.org/book/nse-usage.html), [NSE library layout](https://nmap.org/book/data-files-nse.html).


## Authorizations and private-learning labs

Configure a unique 16+-character `ADMIN_TOKEN` in `.env` (for example, generate one using `openssl rand -hex 24`); use `/settings` to register separately approved public hosts. A recorded scope note is required; this is an administrator assertion, not proof of ownership.

To enable lab-only NSE checks, set `LAB_MODE_ENABLED=true` and list **exact** addresses in `LAB_ALLOWED_IPS` (`127.0.0.1`, RFC1918 or IPv6 ULA addresses, not public IPs or CIDRs). Restart the scanner. In `/scripts`, use your administrator token and review note to approve individual installed NSE scripts, checking the lab-risk acknowledgement for categories `brute`, `dos`, `exploit`, and `fuzzer`.

In `/new`, select the approved script, toggle Private lab mode, enter the administrator token, confirm target authorization and the additional lab risk acknowledgement, and verify the live preview. The backend enforces one pinned, exact private IP that appears in `LAB_ALLOWED_IPS` for these categories, at most three lab-category NSE scripts per step, Nmap script timeout of 120 seconds, and up to three sequential commands per session. The target allowlist alone **does not isolate** the network: configure your hypervisor/firewall so the scanner reaches only intentionally disposable lab VMs, and expect a chance of data loss or service interruption.

Scripts in the `external` and `broadcast` categories and `targets-*` / `broadcast-*` scripts cannot be run from the app, because they may send traffic outside the authorized single-target scope. `version` scripts are invoked through `-sV`; NSE libraries are not directly executable. Custom `.nse`/`.lua` uploads remain quarantined and are never executed. Web app is bound to `127.0.0.1`; do not publicly expose it without authentication and network isolation.
# nmap-command-center-
# nmap-command-center
