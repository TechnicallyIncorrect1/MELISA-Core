"""Network connection monitoring utilities."""

from typing import List, Dict
import psutil


def get_active_connections(limit: int = 30) -> List[Dict]:
    """Return current network connections."""
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        try:
            connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
            })
        except Exception:
            continue
    return connections[:limit]


def get_listening_ports() -> List[Dict]:
    """Return ports currently in LISTEN state."""
    listening = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN" and conn.laddr:
            listening.append({
                "ip": conn.laddr.ip,
                "port": conn.laddr.port,
                "pid": conn.pid,
            })
    return listening
