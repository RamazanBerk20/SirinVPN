#!/bin/sh
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$project_root"
exec systemd-run --user --scope --quiet \
  -p MemoryMax=8G -p MemorySwapMax=0 \
  -p CPUQuota=400% -p TasksMax=512 \
  nice -n 10 python3 tests/vm/linux_acceptance.py "$@"
