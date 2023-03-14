#!/bin/bash
python -m pip install . --target torparse
find torparse -path '*/__pycache__*' -delete
cp torparse/tor_relay_scanner/__main__.py torparse/
python -m zipapp -c -p '/usr/bin/env python3' torparse
