"""Process monitoring utilities."""

from typing import List, Dict
import time
import psutil


def get_top_processes(limit: int = 15) -> List[Dict]:
    """Return top processes sorted by CPU usage.

    Uses a short sampling interval so cpu_percent is meaningful
    on the first call (psutil returns 0.0 until it has a baseline).
    """
    # Prime CPU counters
    for proc in psutil.process_iter(["pid"]):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    time.sleep(0.15)

    processes = []
    for proc in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent", "username", "status"]
    ):
        try:
            info = proc.info
            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "unknown",
                "cpu_percent": float(info["cpu_percent"] or 0.0),
                "memory_percent": round(float(info["memory_percent"] or 0.0), 2),
                "username": info.get("username") or "N/A",
                "status": info.get("status") or "unknown",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return processes[:limit]


def get_process_count() -> int:
    """Return total number of running processes."""
    return len(list(psutil.process_iter()))
