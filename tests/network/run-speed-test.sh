#!/bin/sh
set -eu
# Same container and WireGuard link as the leak test; only the test differs.
exec sh "$(dirname -- "$0")/run-leak-test.sh" kernel_speed_test_measures_the_tunnel_to_the_vps
