#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec python3 ./control_center.py stop
