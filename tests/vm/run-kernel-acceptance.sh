#!/bin/sh
# Compilation and image creation have no privileged networking. Real kernel
# operations run in fresh containers inside the disposable QEMU guest.
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$project_root"
exec systemd-run --user --scope --quiet \
  -p MemoryHigh=3G -p MemoryMax=4G -p MemorySwapMax=0 \
  -p CPUQuota=150% -p TasksMax=256 \
  nice -n 10 python3 tests/vm/kernel_acceptance.py "$@"
