# MELISA Core

**Local Defensive Cybersecurity Agent**

MELISA Core is a clean, modular, open-source defensive monitoring tool designed for personal and organizational use.
It focuses on local system visibility, basic anomaly detection, log analysis, and enrichment with public threat intelligence sources.

This is **not** an offensive tool and does **not** claim any official government authorization.

---

## Features (v0.2)

- Local process and network connection monitoring
- Basic anomaly rules (high CPU/memory, suspicious names, unusual ports)
- System log analysis (Linux auth/syslog style patterns)
- Windows Event Log support (Security log – Windows only)
- Public threat intelligence (CISA Known Exploited Vulnerabilities)
- Report export (JSON + text)
- Simple local web dashboard (FastAPI)
- Clean modular Python architecture + unit tests

---

## Requirements

- Python 3.11+
- Windows 10/11 or Linux

```bash
pip install -r requirements.txt
```

Optional on Windows for Event Log support:

```bash
pip install pywin32
```

---

## Quick Start

```bash
# Install
pip install -r requirements.txt

# System status
python -m melisa status

# Anomaly scan
python -m melisa anomaly

# CISA KEV
python -m melisa kev --limit 10

# Log analysis
python -m melisa logs

# Export report
python -m melisa report

# Start dashboard (http://127.0.0.1:8080)
python -m melisa dashboard

# Continuous monitor
python -m melisa monitor
```

---

## Project Structure

```
melisa-project/
├── src/melisa/
│   ├── core/          # process, network, monitor
│   ├── intel/         # CISA KEV
│   ├── logs/          # log analyzer + Windows events
│   ├── anomaly/       # heuristic rules
│   ├── report/        # JSON/text export
│   ├── web/           # FastAPI dashboard
│   └── cli.py
├── tests/
├── config/
├── requirements.txt
└── README.md
```

---

## Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Philosophy

- Defensive only
- Transparent and auditable
- No exaggerated claims
- Built for real use and continuous improvement

---

## Author

Francisco Ruberki González Tejeda  
GitHub: [TechnicallyIncorrect1](https://github.com/TechnicallyIncorrect1)

---

## License

Apache 2.0
