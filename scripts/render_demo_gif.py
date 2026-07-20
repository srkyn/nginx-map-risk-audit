#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont


ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "demo.gif"
SCANNER = ROOT / "scripts" / "audit_nginx_map_risk.py"


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        pathlib.Path("C:/Windows/Fonts/consola.ttf"),
        pathlib.Path("C:/Windows/Fonts/consolab.ttf"),
    ):
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def frame(lines: list[str], width: int = 1120, height: int = 500) -> Image.Image:
    image = Image.new("RGB", (width, height), "#0b1020")
    draw = ImageDraw.Draw(image)
    mono = font(24)
    small = font(18)
    draw.rounded_rectangle((18, 18, width - 18, height - 18), radius=18, fill="#111827", outline="#334155", width=2)
    draw.text((42, 34), "nginx-map-risk-audit", fill="#cbd5e1", font=small)
    y = 78
    for line in lines:
        color = "#e5e7eb"
        if line.startswith("$"):
            color = "#7dd3fc"
        elif line.startswith("[review]"):
            color = "#fde68a"
        elif "possible capture" in line:
            color = "#fca5a5"
        draw.text((42, y), line, fill=color, font=mono)
        y += 34
    return image


def main() -> int:
    result = subprocess.run(
        [sys.executable, str(SCANNER), "samples"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    lines = ["$ python scripts/audit_nginx_map_risk.py samples", *result.stdout.strip().splitlines()]

    frames = []
    for i in range(1, len(lines) + 1):
        frames.append(frame(lines[:i]))
    frames.extend([frames[-1]] * 8)

    OUT.parent.mkdir(exist_ok=True)
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=650, loop=0)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
