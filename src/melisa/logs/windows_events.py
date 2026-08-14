"""
Windows Event Log support.

Uses the Windows Event Log API when running on Windows.
On non-Windows platforms this module reports that it is unavailable.
"""

from __future__ import annotations

import platform
from typing import List, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def is_windows() -> bool:
    return platform.system() == "Windows"


def query_security_events(max_events: int = 30) -> List[Dict]:
    """
    Query recent Security log events related to logon / privilege use.
    Requires Windows and sufficient privileges.
    """
    if not is_windows():
        return []

    try:
        import win32evtlog  # type: ignore
        import win32con  # type: ignore
    except ImportError:
        console.print("[yellow]pywin32 is required for Windows Event Log support.[/yellow]")
        console.print("[dim]Install with: pip install pywin32[/dim]")
        return []

    events = []
    hand = None
    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while len(events) < max_events:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            for ev in records:
                if ev.EventID in (4624, 4625, 4672, 4688, 4648):
                    events.append({
                        "event_id": ev.EventID,
                        "time": str(ev.TimeGenerated),
                        "source": ev.SourceName,
                        "computer": ev.ComputerName,
                    })
                if len(events) >= max_events:
                    break
    except Exception as e:
        console.print(f"[red]Error reading Security log: {e}[/red]")
    finally:
        if hand:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass
    return events


def display_windows_events(max_events: int = 20) -> None:
    """Pretty-print recent interesting Windows Security events."""
    console.print(Panel.fit(
        "[bold cyan]Windows Event Log (Security)[/bold cyan]\n"
        "[dim]Defensive visibility only[/dim]",
        border_style="cyan"
    ))

    if not is_windows():
        console.print("[yellow]This host is not running Windows.[/yellow]")
        console.print("[dim]Windows Event Log features are only available on Windows.[/dim]")
        return

    events = query_security_events(max_events)
    if not events:
        console.print("[yellow]No events retrieved (permissions or pywin32 missing).[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Event ID")
    table.add_column("Time")
    table.add_column("Source")
    table.add_column("Computer")

    for e in events:
        table.add_row(
            str(e["event_id"]),
            e["time"][:19],
            e["source"][:25],
            e["computer"][:20]
        )
    console.print(table)
    console.print(f"\n[dim]Showing up to {len(events)} recent Security events.[/dim]")
    console.print("[green]\u2713 Windows Event Log check completed[/green]")
