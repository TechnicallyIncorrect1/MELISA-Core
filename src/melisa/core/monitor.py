"""Main local monitoring orchestrator."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .process import get_top_processes, get_process_count
from .network import get_active_connections, get_listening_ports
from ..utils.helpers import utc_now

console = Console()


def run_status_check() -> None:
    """Display a clean system status overview."""
    console.print(Panel.fit(
        f"[bold cyan]MELISA Core — System Status[/bold cyan]\n"
        f"[dim]Timestamp: {utc_now()}[/dim]",
        border_style="cyan"
    ))

    # Processes
    console.print("\n[bold]Top Processes (by CPU)[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("PID", style="dim")
    table.add_column("Name")
    table.add_column("CPU %", justify="right")
    table.add_column("Mem %", justify="right")
    table.add_column("User")
    table.add_column("Status")

    for p in get_top_processes(12):
        table.add_row(
            str(p["pid"]),
            p["name"][:30],
            f"{p['cpu_percent']:.1f}",
            f"{p['memory_percent']:.1f}",
            str(p["username"])[:15],
            p["status"]
        )
    console.print(table)
    console.print(f"[dim]Total processes: {get_process_count()}[/dim]")

    # Listening ports
    console.print("\n[bold]Listening Ports[/bold]")
    listen_table = Table(show_header=True, header_style="bold green")
    listen_table.add_column("IP")
    listen_table.add_column("Port", justify="right")
    listen_table.add_column("PID", justify="right")

    for item in get_listening_ports()[:15]:
        listen_table.add_row(item["ip"], str(item["port"]), str(item["pid"] or "N/A"))
    console.print(listen_table)

    console.print("\n[green]\u2713 Status check completed[/green]")


def run_monitor_loop(interval: int = 10) -> None:
    """Simple continuous monitoring loop (Ctrl+C to stop)."""
    import time
    console.print(f"[cyan]Starting local monitor (interval={interval}s). Press Ctrl+C to stop.[/cyan]")
    try:
        while True:
            run_status_check()
            console.print(f"\n[dim]Next check in {interval} seconds...[/dim]\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped by user.[/yellow]")
