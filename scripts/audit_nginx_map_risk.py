#!/usr/bin/env python3
"""
Defensive heuristic scanner for CVE-2026-42533-style NGINX map patterns.

This does not prove exploitability. It highlights config blocks worth human
review: regex map entries with captures, plus later string expressions that
reference captures and map output variables.
"""

from __future__ import annotations

import argparse
import pathlib
import re
from dataclasses import dataclass


MAP_START = re.compile(r"^\s*map\s+(?P<src>\S+)\s+\$(?P<out>[A-Za-z0-9_]+)\s*\{")
REGEX_ENTRY = re.compile(r"^\s*~\*?\s*(?P<regex>\S+)")
CAPTURE_REF = re.compile(r"\$(?P<name>[1-9][0-9]*|[A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class MapBlock:
    file: pathlib.Path
    start: int
    end: int
    out_var: str
    regex_lines: list[int]
    capture_names: set[str]


def iter_conf_files(root: pathlib.Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {"", ".conf", ".inc"}:
            yield path


def parse_maps(path: pathlib.Path) -> tuple[list[str], list[MapBlock]]:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    maps: list[MapBlock] = []
    i = 0
    while i < len(lines):
        match = MAP_START.search(lines[i])
        if not match:
            i += 1
            continue
        depth = lines[i].count("{") - lines[i].count("}")
        out_var = match.group("out")
        regex_lines: list[int] = []
        captures: set[str] = set()
        start = i + 1
        i += 1
        while i < len(lines) and depth > 0:
            line = lines[i]
            depth += line.count("{") - line.count("}")
            regex = REGEX_ENTRY.search(line)
            if regex:
                regex_lines.append(i + 1)
                captures.update(re.findall(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>", line))
                if "(" in line:
                    captures.add("1")
            i += 1
        maps.append(MapBlock(path, start, i, out_var, regex_lines, captures))
    return lines, maps


def find_risky_uses(lines: list[str], block: MapBlock) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    out_ref = f"${block.out_var}"
    for number, line in enumerate(lines, start=1):
        if block.start <= number <= block.end:
            continue
        if out_ref not in line:
            continue
        refs = {m.group("name") for m in CAPTURE_REF.finditer(line)}
        if block.capture_names.intersection(refs):
            findings.append((number, line.strip()))
    return findings


def scan(root: pathlib.Path) -> int:
    total = 0
    for conf in iter_conf_files(root):
        lines, maps = parse_maps(conf)
        for block in maps:
            if not block.regex_lines:
                continue
            uses = find_risky_uses(lines, block)
            if not uses:
                continue
            total += 1
            print(f"[review] {conf}:{block.start} map output ${block.out_var}")
            print(f"  regex map lines: {', '.join(map(str, block.regex_lines))}")
            for line_no, text in uses:
                print(f"  possible capture/map expression at line {line_no}: {text}")
    if total == 0:
        print("No candidate regex map/capture expression patterns found.")
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit NGINX configs for CVE-2026-42533-style map regex risk patterns.")
    parser.add_argument("path", type=pathlib.Path, help="NGINX config file or directory")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit 1 when candidate patterns are found")
    args = parser.parse_args()
    findings = scan(args.path)
    return 1 if findings and args.fail_on_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
