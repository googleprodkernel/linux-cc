#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

MNT_PATH="/tmp/mnt_hugetlb"
FILE_PATH="$MNT_PATH/test_file"

# Save original values
orig_nr=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
orig_overcommit=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_overcommit_hugepages)

cleanup() {
    echo "Cleaning up..."
    rm -f "$FILE_PATH"
    umount "$MNT_PATH" 2>/dev/null
    rmdir "$MNT_PATH" 2>/dev/null
    echo "$orig_nr" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
    echo "$orig_overcommit" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_overcommit_hugepages
    echo "Cleanup done."
}
trap cleanup EXIT

# 1. Mount hugetlbfs with size=2M (1 page)
mkdir -p "$MNT_PATH"
if ! mount -t hugetlbfs -o size=2M none "$MNT_PATH"; then
    echo "Failed to mount hugetlbfs"
    exit 1
fi

# 2. Set nr_hugepages to 0, overcommit to 0
echo 0 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
echo 0 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_overcommit_hugepages

# Check subpool usage before running
read total free < <(stat -f -c "%b %f" "$MNT_PATH")
used_before=$((total - free))
echo "Before test - Subpool total blocks: $total"
echo "Before test - Subpool free blocks:  $free"
echo "Before test - Subpool used blocks:  $used_before"
if [ "$used_before" -ne 0 ]; then
    echo "ERROR: Subpool is not clean before test starts!"
    exit 1
fi

# Run fallocate (expecting failure)
echo "Running fallocate (expecting failure)..."
if fallocate -l 2M "$FILE_PATH" 2>/dev/null; then
    echo "ERROR: fallocate succeeded but should have failed (nr_hugepages is 0)"
    exit 1
fi

# Check subpool usage via statfs
# %b: Total blocks
# %f: Free blocks
read total free < <(stat -f -c "%b %f" "$MNT_PATH")
used=$((total - free))

echo "Subpool total blocks: $total"
echo "Subpool free blocks:  $free"
echo "Subpool used blocks (leaked if > 0): $used"

if [ "$used" -gt 0 ]; then
    echo "RESULT: LEAK DETECTED (FAIL)"
    exit 1
else
    echo "RESULT: NO LEAK (PASS)"
    exit 0
fi
