#!/usr/bin/env bash
set -euo pipefail

python -m snowflake_data_security_monitor.main scan
