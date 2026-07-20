# CVE-2026-42533: NGINX Map Regex Risk Review

Defensive research note on CVE-2026-42533, a heap buffer overflow in NGINX request processing tied to `map` directives with regex captures and certain variable evaluation patterns.

In plain English: NGINX is web server and reverse proxy software. It often sits in front of websites and APIs, accepts web requests, and decides where to send them. A `map` rule is an NGINX config feature that says "if this request value looks like X, set this variable to Y." Regex captures are the pieces of text pulled out of a pattern match.

This CVE matters because some older NGINX versions can handle a specific kind of `map` and variable-combination pattern incorrectly. That does not mean every NGINX server is exposed. The version matters, but the active config matters too.

This project is intentionally safe: it does not include exploit traffic, crash payloads, or production probing. The goal is to show how I would triage exposure, explain the risk, and hand defenders a repeatable validation path.

## Why This Matters

NGINX lists the issue as a major security advisory: vulnerable versions are `0.9.6-1.31.2`, fixed versions are `1.30.4+` and `1.31.3+`. The NGINX changelog describes a heap buffer overflow in a worker process when a `map` directive uses regex matching and the map variable is included in a string expression after a capture affected by that map.

NVD records the F5 description: an unauthenticated attacker may trigger the issue with crafted HTTP requests, but only when configuration and runtime conditions line up. The expected direct impact is NGINX worker restart and denial of service, with possible code execution if ASLR is disabled or bypassed.

## Exposure Triage

Defenders should answer four questions before treating an NGINX deployment as exposed. Put simply: first confirm the version, then confirm whether the risky config pattern is actually present.

1. Is the running NGINX binary in an affected upstream range, accounting for distro backports?
2. Does the active configuration use `map` with regex entries?
3. Do mapped regex captures feed later string expressions in an order that can change between length and copy phases?
4. Are suspicious worker restarts, crash loops, or the fixed-build error signal `no buffer space in script copy` visible in logs?

If those words are new: a worker is the NGINX process handling requests. A crash loop or restart signal means the process may be failing and starting again. A distro backport means Linux vendors sometimes patch an older-looking version without changing the version number to the newest upstream release.

## Repository Contents

- `scripts/audit_nginx_map_risk.py`  
  A defensive heuristic scanner for NGINX config files. It looks for regex `map` blocks, captures, and later string expressions that reference captures and map outputs. It does not prove a server is exploitable. It finds configs worth a human review.

- `detections/splunk_nginx_cve_2026_42533.spl`  
  Splunk searches for version inventory, crash/restart symptoms, and post-patch diagnostic strings.

- `detections/defender_hunting_notes.kql`  
  Microsoft Defender hunting notes for Linux hosts where NGINX logs and process activity are collected.

- `samples/nginx_map_patterns.conf`  
  Safe, schematic config examples for explaining the risk pattern. These are not exploit payloads.

- `lab/windows-quickstart.ps1`  
  Windows-friendly evidence runner that executes the scanner and saves output under `evidence/`.

- `lab/windows-nginx-validation.ps1`  
  Downloads the official fixed NGINX for Windows build, validates a local lab config with `nginx -t`, runs the scanner, and saves evidence.

- `lab/vmware-lab-notes.md`  
  Optional fuller lab path for a disposable Linux VM if a screenshot-based walkthrough is needed later.

## Evidence

Current local validation is stored in `evidence/`. The Windows quickstart runs the scanner against the included sample config and saves the transcript. The Windows NGINX validation downloads the official fixed NGINX build, confirms the lab config with `nginx -t`, and runs the scanner. The Kali VM validation runs the same scanner inside a disposable Kali VMware guest. This proves the repository is executable and reviewable across Windows and Linux while keeping the project inside a defensive boundary.

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\windows-quickstart.ps1
powershell -ExecutionPolicy Bypass -File .\lab\windows-nginx-validation.ps1
```

## Defensive Workflow

1. Inventory running NGINX versions.
2. Verify whether your vendor backported the fix.
3. Search active configs for regex `map` blocks.
4. Review whether captures and map outputs appear in later string expressions.
5. Patch to `1.30.4+` or `1.31.3+`, or the relevant NGINX Plus fixed release.
6. Restart or reload workers and confirm the fixed binary is actually running.
7. Monitor for worker restarts, request spikes, and `no buffer space in script copy` after patching.

## Notes For Interview Discussion

This is a good example of why vulnerability management is not only "is version less than fixed version." A version check finds candidate exposure, but the real risk depends on active configuration, reachable request paths, process hardening, and whether the patched workers are actually in memory.

The simple way I would explain it in an interview: NGINX is like traffic control for a website. This bug is tied to a specific traffic-control rule pattern. My project checks whether that pattern exists, shows how to validate a patched build, and gives defenders log searches to look for symptoms. It is not an exploit project. It is a safe exposure-review and detection project.

## Sources

- NGINX security advisory page: https://nginx.org/en/security_advisories.html
- NGINX changelog: https://nginx.org/en/CHANGES
- NVD CVE record: https://nvd.nist.gov/vuln/detail/CVE-2026-42533
- Penligent technical explainer: https://www.penligent.ai/hackinglabs/cve-2026-42533/
