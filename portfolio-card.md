# Portfolio Card

**Title:** CVE-2026-42533 NGINX Map Regex Risk Review

**Short copy:** Source-backed vulnerability triage project for CVE-2026-42533. NGINX is often the traffic controller in front of websites and APIs; this project checks for a risky config pattern tied to one recent NGINX bug. Built a safe config-audit heuristic, Splunk and Defender hunting notes, and a remediation workflow focused on version evidence, active config review, worker restart signals, and patch validation.

**Skills shown:** Vulnerability management, detection engineering, Splunk, Microsoft Defender hunting, Linux/NGINX exposure review, remediation handoff, source-based technical writing.

**LinkedIn draft:**

I put together a small defensive research note on CVE-2026-42533, the recent NGINX map/regex heap overflow.

If NGINX is new to you, it is commonly used as the traffic controller in front of websites and APIs. It receives web requests and decides how to route or handle them. This bug is tied to a specific kind of config rule, not every NGINX server on earth.

The interesting part is that it is not a plain "version is vulnerable, panic" issue. Version inventory matters, but exposure also depends on active NGINX config, regex map usage, capture variables, expression order, and whether patched workers are actually running after update.

I kept it safe: no exploit traffic, no crash payloads. Just source review, config-audit heuristics, Splunk/Defender hunting notes, and a patch-validation workflow.

That kind of gap between CVE headline and real operational exposure is exactly where security work gets interesting.
