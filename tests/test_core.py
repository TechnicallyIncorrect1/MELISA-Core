"""Basic unit tests for MELISA Core."""

import sys
from pathlib import Path

# Ensure src is on path when running tests directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from melisa.core.process import get_top_processes, get_process_count
from melisa.core.network import get_listening_ports
from melisa.anomaly.rules import run_anomaly_scan, Finding
from melisa.utils.helpers import utc_now, safe_get
from melisa import __version__


def test_version():
    assert isinstance(__version__, str)
    assert __version__.count(".") >= 1


def test_utc_now():
    ts = utc_now()
    assert "T" in ts
    assert ts.endswith("+00:00") or "Z" in ts or "+" in ts


def test_safe_get():
    data = {"a": {"b": 1}}
    assert safe_get(data, "a", "b") == 1
    assert safe_get(data, "a", "x", default=42) == 42
    assert safe_get(data, "missing") is None


def test_get_process_count():
    count = get_process_count()
    assert isinstance(count, int)
    assert count > 0


def test_get_top_processes():
    procs = get_top_processes(5)
    assert isinstance(procs, list)
    assert len(procs) <= 5
    if procs:
        assert "pid" in procs[0]
        assert "name" in procs[0]


def test_get_listening_ports():
    ports = get_listening_ports()
    assert isinstance(ports, list)


def test_run_anomaly_scan():
    findings = run_anomaly_scan()
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
        assert f.severity in {"info", "low", "medium", "high"}
