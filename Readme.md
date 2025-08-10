# Why SolidBeamSolution (SBS) Exists

## The problem we ran into (over and over)

Running ClamAV across a bunch of Linux boxes sounds simple until you actually try it:

- CLI complexity & noisy output. clamscan options, excludes, recursion depth, file-size caps, and long streaming output make it easy to misconfigure and hard to follow what’s happening.
- Inconsistent installs. Different distros (apt/dnf/yum/pacman), different service names, missing deps, wrong paths every host feels a little different.
- Definition freshness drift. If freshclam isn’t set up correctly, you think you’re protected but you’re scanning with stale definitions.
- Permission surprises. Full-host scans as non-root hit “Permission denied” everywhere; running everything as root is risky if you don’t isolate.
- No simple UI. Operators just want: pick a path, start a scan, watch live output, see history, quarantine infected files, delete if needed without babysitting a terminal.
- No proof it’s working. Auditors and leads want evidence: When did we scan? What defs were used? Where’s the log? Is the weekly scan actually firing?

## What SBS delivers

SBS is a native, single-host web interface for ClamAV that installs the same way, every time, and makes day-to-day operation obvious:

- One installer, predictable layout. /opt/clamav-web/ with app.py, logs/, quarantine/, data/scanlog.db, venv/. Works on apt/dnf/yum/pacman.
- Clear, live output. A lightweight web UI with JSON polling + a bounded ring buffer, so you can see exactly what ClamAV is doing without hanging connections.
- Safe defaults. Sensible limits (--max-filesize/--max-scansize), recursion control, and excludes for pseudo-filesystems (/proc, /sys, /dev, /run, /mnt, /media, /snap).
- Quarantine with metadata. Infected uploads/files land in a 700 directory with 600 perms; each item gets a JSON sidecar with the why/when/what.
- History you can trust. SQLite (WAL) with a timestamp index; each scan row finalized as completed or stopped with duration and best-effort counts.
- Definitions handled by the OS. No “update” button in the UI clamav-freshclam service and/or root cron keep defs current the reliable way.
- Weekly scanning baked in. A cron entry runs a nice/ionice full scan (or your chosen path) and writes a compact [CRON][SCAN] summary to the app log.
- Operator-grade logging. Rotating file logs (10MB×5) with consistent tags: [BOOT][STATUS][SCAN][UPLOAD][QUARANTINE][METRICS][CRON][DB].

## Why these design choices (on purpose)

- Native only, no Docker. Fewer moving parts, easier debugging, no container runtime friction on minimal hosts.
- LAN-only, no auth. Keeps the app small and predictable. You control access with the network/firewall.
- Run as a dedicated user by default. Reduces blast radius. If you truly need full / coverage, you can adjust service identity but the safer default is non-root.
- JSON polling (not SSE). Works everywhere, easy to reason about, bounded memory, and resilient if the browser sleeps or the network blips.
- OS-managed definition updates. freshclam daemon and root cron are proven; removing UI-triggered updates avoids permission foot-guns and stalled DBs.
- Single active scan. Simpler concurrency, no race conditions, clear stop semantics (SIGTERM→SIGKILL) with DB finalization in all paths.
  

## Who this is for

- Ops/Sec/IT teams who need a reliable, repeatable way to run ClamAV on Linux hosts and see the results without tailing terminals.
- Small teams and labs who want one command to install, a simple UI, and weekly evidence without building their own plumbing.

## When not to use it

- If you need multi-tenant auth, RBAC, or remote fleet orchestration this is a single-host, LAN-only tool by design.
- If you require reverse proxies, TLS termination, or SIEM integration out of the box keep SBS simple and layer those controls externally if needed.

## The outcome you can expect

- Install to first scan in minutes same result across distros.
- Fewer mistakes (safe flags, excludes, stable updates).
- Clear situational awareness during scans and when something is infected.
- Evidence on demand (history, logs, weekly scan summaries) for audits and change tickets.

## TL;DR

We built SBS to make ClamAV understandable, repeatable, and trustworthy on real Linux machines without surprises, and without needing to be a ClamAV expert every time you hit “Scan.”
