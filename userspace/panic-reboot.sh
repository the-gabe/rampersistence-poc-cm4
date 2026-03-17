#!/bin/sh
# panic-reboot.sh — Trigger an immediate BCM2711 watchdog reset.
#
# This bypasses the kernel's shutdown/reboot path entirely.
# No PSCI, no reboot notifiers, no crypto key teardown.
# DRAM contents survive the reset.
#
# Requires: /dev/mem access (root), python3

set -e

echo "Triggering immediate watchdog reset..."
echo "DRAM will NOT be cleared."

python3 -c "
import mmap, struct, os
fd = os.open('/dev/mem', os.O_RDWR | os.O_SYNC)
m = mmap.mmap(fd, 0x1000, offset=0xfe100000)
m[0x24:0x28] = struct.pack('<I', 0x5a00000a)
m[0x1c:0x20] = struct.pack('<I', 0x5a000020)
"

# Should never reach here
sleep 1
echo "ERROR: Reset did not trigger!"
exit 1
