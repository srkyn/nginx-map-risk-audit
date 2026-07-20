# Evidence

This folder stores local validation output for the defensive scanner and detection notes.

## Current Evidence

- `scanner-sample-output.txt`: Windows PowerShell run of the config-audit script against the included sample NGINX config.
- `windows-nginx-validation-output.txt`: Official NGINX for Windows `1.30.4` validation with `nginx -t` against the lab config, followed by the scanner output.
- `kali-vm-validation-output.txt`: VMware Kali guest validation showing the guest IP, Python runtime, and scanner output against the same lab config.

## Optional Next Evidence

- `docker-lab-output.txt`: output from an official NGINX container if Docker Desktop is installed later.
- Screenshots from Windows Terminal and the Kali VM if a fuller visual walkthrough is useful for the portfolio.

The current evidence is intentionally safe. It validates the review workflow and does not send exploit traffic or attempt to crash a worker process.
