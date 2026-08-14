"""
Basic log analysis module.
Works with common log files on Linux and provides a Windows Event Log stub.
"""

from __future__ import annotations

import os
import platform
import re
from collections import Counter
from typing import Dict, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

LINUX_LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/secure",
    "/var/log/messages",
]

SUSPICIOUS_PATTERNS = [
    r"Failed password",
    r"authentication failure",
    r"Invalid user",
    r"Connection closed by authenticating user",
    r"sudo:.*COMMAND=",
    r"session opened for user root",
    r"Accepted publickey",
    r"error: maximum authentication attempts exceeded",
]


def find_available_logs() -> List[str]:
    found = []
    if platform.system() == "Linux":
        for path in LINUX_LOG_CANDIDATES:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                found.append(path)
    return found


def read_log_tail(path: str, lines: int = 200) -> List[str]:
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.readlines()
            return content[-lines:]
    except Exception as e:
        console.print(f"[yellow]Could not read {path}: {e}[/yellow]")
        return []


def analyze_log_file(path: str, max_lines: int = 500) -> Dict:
    lines = read_log_tail(path, max_lines)
    hits: Counter = Counter()
    matched_lines: List[str] = []

    for line in lines:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                hits[pattern] += 1
                matched_lines.append(line.strip()[:120])
                break

    return {
        "path": path,
        "total_lines_scanned": len(lines),
        "suspicious_hits": dict(hits),
        "sample_matches": matched_lines[:10],
    }


def run_log_analysis(max_lines: int = 300) -> None:
    console.print(Panel.fit(
        "[bold cyan]MELISA Log Analysis[/bold cyan]\n"
        "[dim]Defensive scan of common system logs[/dim]",
        border_style="cyan"
    ))

    logs = find_available_logs()
    if not logs:
        console.print("[yellow]No readable system logs found on this host.[/yellow]")
        console.print("[dim]On Windows this module currently focuses on file-based logs.[/dim]")
        console.print("[dim]Windows Event Log support is available via the windows_events module.[/dim]")
        return

    for log_path in logs:
        result = analyze_log_file(log_path, max_lines)
        console.print(f"\n[bold]{result['path']}[/bold]  (scanned {result['total_lines_scanned']} lines)")

        if not result["suspicious_hits"]:
            console.print("  [green]No matching suspicious patterns found.[/green]")
            continue

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Pattern")
        table.add_column("Count", justify="right")
        for pattern, count in result["suspicious_hits"].items():
            table.add_row(pattern, str(count))
        console.print(table)

        if result["sample_matches"]:
            console.print("[dim]Sample matches:[/dim]")
            for sample in result["sample_matches"][:5]:
                console.print(f"  \u2022 {sample}")

    console.print("\n[green]\u2713 Log analysis completed[/green]")
