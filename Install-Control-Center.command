#!/bin/sh
cd "$(dirname "$0")" || exit 1
printf "Installing Nutanix STIG Control Center...\n"
printf "This one-time setup registers the localhost supervisor at login.\n\n"
python3 ./control_center.py install
status=$?
if [ "$status" -ne 0 ]; then
  printf "\nInstallation failed. Press Return to close."
  read answer
fi
exit "$status"
