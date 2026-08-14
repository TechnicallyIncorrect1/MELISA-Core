"""
CISA Known Exploited Vulnerabilities (KEV) integration.

Uses the official public CISA KEV catalog:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from typing import List, Dict, Optional
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog(timeout: int = 30) -> Optional[Dict]:
    """Download the latest CISA KEV catalog."""
    try:
        response = requests.get(KEV_URL, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        console.print(f"[red]Failed to fetch CISA KEV catalog: {e}[/red]")
        return None


def get_recent_vulnerabilities(limit: int = 15) -> List[Dict]:
    """Return the most recently added vulnerabilities from the KEV catalog."""
    data = fetch_kev_catalog()
    if not data or "vulnerabilities" not in data:
        return []

    vulns = data["vulnerabilities"]
    sorted_vulns = sorted(
        vulns,
        key=lambda x: x.get("dateAdded", ""),
        reverse=True
    )
    return sorted_vulns[:limit]


def display_kev(limit: int = 10) -> None:
    """Pretty-print recent CISA KEV entries."""
    console.print(Panel.fit(
        "[bold cyan]CISA Known Exploited Vulnerabilities[/bold cyan]\n"
        "[dim]Public catalog — defensive use only[/dim]",
        border_style="cyan"
    ))

    vulns = get_recent_vulnerabilities(limit)
    if not vulns:
        console.print("[yellow]No data available.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Vendor / Product")
    table.add_column("Date Added", style="dim")
    table.add_column("Ransomware", justify="center")

    for v in vulns:
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        table.add_row(
            v.get("cveID", "N/A"),
            f"{v.get('vendorProject', '')} / {v.get('product', '')}"[:40],
            v.get("dateAdded", "N/A"),
            ransomware
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(vulns)} most recent entries from CISA KEV.[/dim]")
    console.print("[green]\u2713 Threat intel check completed[/green]")
