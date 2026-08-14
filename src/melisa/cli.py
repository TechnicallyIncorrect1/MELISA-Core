"""
MELISA Core Command Line Interface
"""

import click
from rich.console import Console

from . import __version__
from .core.monitor import run_status_check, run_monitor_loop
from .intel.cisa_kev import display_kev
from .logs.analyzer import run_log_analysis
from .logs.windows_events import display_windows_events
from .anomaly.rules import display_anomaly_results
from .report.exporter import run_export

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="MELISA Core")
def main():
    """MELISA Core — Local Defensive Cybersecurity Agent"""
    pass


@main.command()
def status():
    """Show current system status (processes + network)."""
    run_status_check()


@main.command()
@click.option("--interval", default=10, help="Seconds between checks", show_default=True)
def monitor(interval: int):
    """Run continuous local monitoring."""
    run_monitor_loop(interval=interval)


@main.command()
@click.option("--limit", default=10, help="Number of vulnerabilities to show", show_default=True)
def kev(limit: int):
    """Fetch and display recent CISA Known Exploited Vulnerabilities."""
    display_kev(limit=limit)


@main.command()
@click.option("--lines", default=300, help="Max lines to scan per log", show_default=True)
def logs(lines: int):
    """Analyze common system logs for suspicious patterns."""
    run_log_analysis(max_lines=lines)


@main.command("winevt")
@click.option("--max", "max_events", default=20, help="Max events to show", show_default=True)
def winevt(max_events: int):
    """Show recent Windows Security Event Log entries (Windows only)."""
    display_windows_events(max_events=max_events)


@main.command()
def anomaly():
    """Run basic anomaly detection rules."""
    display_anomaly_results()


@main.command()
@click.option("--format", "fmt", type=click.Choice(["json", "text", "both"]), default="both", show_default=True)
def report(fmt: str):
    """Export a system + anomaly report."""
    run_export(fmt=fmt)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True, type=int)
def dashboard(host: str, port: int):
    """Start the local web dashboard."""
    from .web.app import run_dashboard
    run_dashboard(host=host, port=port)


@main.command()
def about():
    """Show information about MELISA Core."""
    console.print(f"""
[bold cyan]MELISA Core v{__version__}[/bold cyan]

Local Defensive Cybersecurity Agent
Author: Francisco Ruberki González Tejeda

Commands:
  status      System overview
  monitor     Continuous monitoring
  kev         CISA Known Exploited Vulnerabilities
  logs        Analyze system logs
  winevt      Windows Event Log (Windows only)
  anomaly     Basic anomaly rules
  report      Export JSON / text report
  dashboard   Local web UI (FastAPI)

This tool is designed for legitimate defensive monitoring
and public threat intelligence enrichment.
It does not perform offensive actions.
""")


if __name__ == "__main__":
    main()
