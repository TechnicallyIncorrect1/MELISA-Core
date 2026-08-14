"""
Simple report export (JSON + plain text).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from rich.console import Console

from ..anomaly.rules import run_anomaly_scan
from ..core.process import get_top_processes, get_process_count
from ..core.network import get_listening_ports
from ..utils.helpers import utc_now

console = Console()


def build_report() -> Dict[str, Any]:
    """Collect current system snapshot into a report dictionary."""
    findings = run_anomaly_scan()
    return {
        "generated_at": utc_now(),
        "host": {
            "process_count": get_process_count(),
            "top_processes": get_top_processes(10),
            "listening_ports": get_listening_ports()[:20],
        },
        "anomaly_findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "message": f.message,
                "detail": f.detail,
            }
            for f in findings
        ],
        "summary": {
            "total_findings": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
        },
    }


def export_json(path: str = "melisa_report.json") -> str:
    report = build_report()
    out = Path(path)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(out.resolve())


def export_text(path: str = "melisa_report.txt") -> str:
    report = build_report()
    lines = [
        "MELISA Core Report",
        f"Generated: {report['generated_at']}",
        "",
        f"Process count: {report['host']['process_count']}",
        f"Total anomaly findings: {report['summary']['total_findings']}",
        f"  High: {report['summary']['high']}",
        f"  Medium: {report['summary']['medium']}",
        "",
        "Findings:",
    ]
    for f in report["anomaly_findings"]:
        lines.append(f"  [{f['severity'].upper()}] {f['message']} ({f['detail']})")
    if not report["anomaly_findings"]:
        lines.append("  None")

    out = Path(path)
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out.resolve())


def run_export(fmt: str = "both") -> None:
    """Export report(s) and print locations."""
    if fmt in ("json", "both"):
        p = export_json()
        console.print(f"[green]JSON report saved:[/green] {p}")
    if fmt in ("text", "both"):
        p = export_text()
        console.print(f"[green]Text report saved:[/green] {p}")
