"""
Simple FastAPI dashboard for MELISA Core.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from ..core.process import get_top_processes, get_process_count
from ..core.network import get_listening_ports
from ..anomaly.rules import run_anomaly_scan
from ..utils.helpers import utc_now

app = FastAPI(
    title="MELISA Core",
    description="Local Defensive Cybersecurity Agent Dashboard",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/status")
def api_status() -> Dict[str, Any]:
    findings = run_anomaly_scan()
    return {
        "timestamp": utc_now(),
        "version": __version__,
        "process_count": get_process_count(),
        "top_processes": get_top_processes(10),
        "listening_ports": get_listening_ports()[:15],
        "anomaly_count": len(findings),
        "findings": [
            {"severity": f.severity, "category": f.category, "message": f.message, "detail": f.detail}
            for f in findings
        ],
    }


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    """Minimal single-page dashboard."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MELISA Core Dashboard</title>
  <style>
    :root {{
      --bg: #0b1220;
      --card: #121a2b;
      --text: #e6edf7;
      --muted: #8b9bb4;
      --accent: #3b82f6;
      --danger: #ef4444;
      --warn: #f59e0b;
      --ok: #22c55e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg); color: var(--text);
    }}
    header {{
      padding: 1.25rem 1.5rem; border-bottom: 1px solid #1e293b;
      display: flex; justify-content: space-between; align-items: center;
    }}
    h1 {{ margin: 0; font-size: 1.25rem; letter-spacing: 0.02em; }}
    .muted {{ color: var(--muted); font-size: 0.9rem; }}
    main {{ padding: 1.5rem; max-width: 1100px; margin: 0 auto; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }}
    .card {{
      background: var(--card); border: 1px solid #1e293b; border-radius: 12px; padding: 1rem 1.1rem;
    }}
    .card h2 {{ margin: 0 0 0.75rem; font-size: 0.95rem; color: var(--muted); font-weight: 600; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th, td {{ text-align: left; padding: 0.4rem 0.2rem; border-bottom: 1px solid #1e293b; }}
    th {{ color: var(--muted); font-weight: 500; }}
    .badge {{
      display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600;
    }}
    .high {{ background: rgba(239,68,68,0.15); color: var(--danger); }}
    .medium {{ background: rgba(245,158,11,0.15); color: var(--warn); }}
    .ok {{ color: var(--ok); }}
    button {{
      background: var(--accent); color: white; border: none; border-radius: 8px;
      padding: 0.45rem 0.9rem; cursor: pointer; font-weight: 600;
    }}
    button:hover {{ filter: brightness(1.08); }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>MELISA Core</h1>
      <div class="muted">Local Defensive Dashboard · v{__version__}</div>
    </div>
    <button onclick="load()">Refresh</button>
  </header>
  <main>
    <div class="grid" style="margin-bottom:1rem;">
      <div class="card"><h2>Processes</h2><div id="procCount" class="muted">—</div></div>
      <div class="card"><h2>Anomaly Findings</h2><div id="anomCount" class="muted">—</div></div>
      <div class="card"><h2>Last Update</h2><div id="ts" class="muted">—</div></div>
    </div>

    <div class="card" style="margin-bottom:1rem;">
      <h2>Top Processes</h2>
      <table>
        <thead><tr><th>PID</th><th>Name</th><th>CPU %</th><th>Mem %</th></tr></thead>
        <tbody id="procBody"></tbody>
      </table>
    </div>

    <div class="card">
      <h2>Findings</h2>
      <div id="findings" class="muted">Loading…</div>
    </div>
  </main>
  <script>
    async function load() {{
      try {{
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('procCount').textContent = data.process_count;
        document.getElementById('anomCount').textContent = data.anomaly_count;
        document.getElementById('ts').textContent = data.timestamp;

        const body = document.getElementById('procBody');
        body.innerHTML = '';
        (data.top_processes || []).forEach(p => {{
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${{p.pid}}</td><td>${{p.name}}</td><td>${{p.cpu_percent.toFixed(1)}}</td><td>${{p.memory_percent}}</td>`;
          body.appendChild(tr);
        }});

        const findings = document.getElementById('findings');
        if (!data.findings || data.findings.length === 0) {{
          findings.innerHTML = '<span class="ok">No findings from current rules.</span>';
        }} else {{
          findings.innerHTML = data.findings.map(f =>
            `<div style="margin:0.4rem 0;"><span class="badge ${{f.severity}}">${{f.severity.toUpperCase()}}</span> ${{f.message}} <span class="muted">${{f.detail || ''}}</span></div>`
          ).join('');
        }}
      }} catch (e) {{
        document.getElementById('findings').textContent = 'Failed to load status.';
      }}
    }}
    load();
    setInterval(load, 15000);
  </script>
</body>
</html>"""


def run_dashboard(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Launch the FastAPI dashboard with uvicorn."""
    import uvicorn
    print(f"Starting MELISA dashboard at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
