#!/bin/sh
set -eu
cd "$(dirname "$0")"
printf "Installing Nutanix STIG Control Center...\n"
printf "This one-time setup registers the localhost supervisor at login.\n\n"
exec python3 ./control_center.py install
