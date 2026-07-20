# VMware Lab Notes

Use this only if a fuller lab screenshot is needed after the initial repo is public.

## Goal

Show the same defensive workflow in a local Linux VM:

1. Install NGINX in a disposable VM.
2. Copy in a schematic config that uses a regex `map` and capture reference.
3. Run `nginx -t` to validate config syntax.
4. Run `audit_nginx_map_risk.py` against `/etc/nginx`.
5. Save terminal output and screenshots under `evidence/`.

## Boundary

Do not send exploit traffic, fuzz production services, or attempt to crash NGINX. This lab is for exposure triage and configuration review only.

## Commands

```bash
python3 scripts/audit_nginx_map_risk.py /etc/nginx
nginx -v
nginx -t
```

## Evidence To Capture

- NGINX version output.
- `nginx -t` syntax validation.
- Scanner output.
- One terminal screenshot showing the commands and results.
