"""
Basic anomaly detection rules for local system state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import psutil
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class Finding:
    severity: str  # info / low / medium / high
    category: str
    message: str
    detail: str = ""


def check_high_cpu(threshold: float = 85.0) -> List[Finding]:
    findings = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
        try:
            cpu = proc.info["cpu_percent"] or 0.0
            if cpu >= threshold:
                findings.append(Finding(
                    severity="medium",
                    category="process",
                    message=f"High CPU process: {proc.info['name']} (PID {proc.info['pid']})",
                    detail=f"CPU {cpu:.1f}%"
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def check_high_memory(threshold: float = 80.0) -> List[Finding]:
    findings = []
    for proc in psutil.process_iter(["pid", "name", "memory_percent"]):
        try:
            mem = proc.info["memory_percent"] or 0.0
            if mem >= threshold:
                findings.append(Finding(
                    severity="medium",
                    category="process",
                    message=f"High memory process: {proc.info['name']} (PID {proc.info['pid']})",
                    detail=f"Memory {mem:.1f}%"
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def check_suspicious_names() -> List[Finding]:
    """Very basic name-based heuristics (defensive only)."""
    suspicious_keywords = [
        "mimikatz", "procdump", "psexec", "cobalt", "beacon",
        "meterpreter", "empire", "sharphound", "rubeus"
    ]
    findings = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info["name"] or "").lower()
            for kw in suspicious_keywords:
                if kw in name:
                    findings.append(Finding(
                        severity="high",
                        category="process",
                        message=f"Potentially suspicious process name: {proc.info['name']}",
                        detail=f"PID {proc.info['pid']}"
                    ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def check_listening_on_unusual_ports() -> List[Finding]:
    """Flag common high-risk or unusual listening ports (heuristic)."""
    unusual = {4444, 5555, 6666, 31337, 12345, 6667}
    findings = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN" and conn.laddr and conn.laddr.port in unusual:
            findings.append(Finding(
                severity="high",
                category="network",
                message=f"Listening on unusual port {conn.laddr.port}",
                detail=f"PID {conn.pid}"
            ))
    return findings


def run_anomaly_scan() -> List[Finding]:
    """Execute all basic rules and return findings."""
    findings: List[Finding] = []
    findings.extend(check_high_cpu())
    findings.extend(check_high_memory())
    findings.extend(check_suspicious_names())
    findings.extend(check_listening_on_unusual_ports())
    return findings


def display_anomaly_results() -> None:
    """Run and pretty-print anomaly findings."""
    console.print(Panel.fit(
        "[bold cyan]MELISA Anomaly Scan[/bold cyan]\n"
        "[dim]Basic heuristic rules — defensive only[/dim]",
        border_style="cyan"
    ))

    findings = run_anomaly_scan()
    if not findings:
        console.print("[green]No findings from current rule set.[/green]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Message")
    table.add_column("Detail")

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 9))

    for f in findings:
        color = {"high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.upper()}[/{color}]",
            f.category,
            f.message,
            f.detail
        )
    console.print(table)
    console.print(f"\n[dim]Total findings: {len(findings)}[/dim]")
    console.print("[green]\u2713 Anomaly scan completed[/green]")
