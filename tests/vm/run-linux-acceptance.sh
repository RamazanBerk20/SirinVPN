#!/bin/sh
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$project_root"
exec systemd-run --user --scope --quiet \
  -p MemoryHigh=3G -p MemoryMax=4G -p MemorySwapMax=0 \
  -p CPUQuota=150% -p TasksMax=256 \
  nice -n 10 python3 tests/vm/linux_acceptance.py "$@"
