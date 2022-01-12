#!/bin/bash
python -m pip install . --target torparse
find torparse -path '*/__pycache__*' -delete
python -m zipapp -m "tor_relay_scanner.scanner:main" -c torparse
