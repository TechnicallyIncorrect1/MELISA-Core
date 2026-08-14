"""Process monitoring utilities."""

from typing import List, Dict
import psutil


def get_top_processes(limit: int = 15) -> List[Dict]:
    """Return top processes sorted by CPU usage."""
    processes = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "username", "status"]):
        try:
            info = proc.info
            processes.append({
                "pid": info["pid"],
                "name": info["name"],
                "cpu_percent": info["cpu_percent"] or 0.0,
                "memory_percent": round(info["memory_percent"] or 0.0, 2),
                "username": info["username"] or "N/A",
                "status": info["status"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return processes[:limit]


def get_process_count() -> int:
    """Return total number of running processes."""
    return len(list(psutil.process_iter()))
