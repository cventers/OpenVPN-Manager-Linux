#!/bin/bash
# VPN Manager wrapper script
# This script is symlinked from ~/ovpn/vpn-manager.sh

# Get the real path of the script (resolve symlinks)
REAL_SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$REAL_SCRIPT")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to project directory
cd "$PROJECT_DIR"

# Activate poetry environment and run vpn_manager.py
poetry run python vpn_manager.py "$@"