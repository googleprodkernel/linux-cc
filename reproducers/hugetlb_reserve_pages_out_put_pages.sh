#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect default hugepage size to support both 2MB and 1GB pages robustly
hpz=$(grep -i hugepagesize /proc/meminfo | awk '{print $2}')
kb=$hpz
mb=$((kb / 1024))
hpage_size_bytes=$((kb * 1024))

hpage_dir="hugepages-${kb}kB"
SYSFS_PATH="/sys/kernel/mm/hugepages/$hpage_dir"

MNT_PATH="/tmp/mnt_hugetlb_repro"
FILE_PATH="$MNT_PATH/test_file"

# Save original values for safe restoration
orig_nr=$(cat "$SYSFS_PATH/nr_hugepages")
orig_overcommit=$(cat "$SYSFS_PATH/nr_overcommit_hugepages")

cleanup() {
    echo "Cleaning up..."
    rm -f "$FILE_PATH"
    umount "$MNT_PATH" 2>/dev/null
    rmdir "$MNT_PATH" 2>/dev/null
    echo "$orig_nr" > "$SYSFS_PATH/nr_hugepages"
    echo "$orig_overcommit" > "$SYSFS_PATH/nr_overcommit_hugepages"
    echo "Cleanup done."
}
trap cleanup EXIT

# Verify reproducer binary exists
if [ ! -x ./hugetlb_reserve_pages_out_put_pages ]; then
    echo "reproducer binary './hugetlb_reserve_pages_out_put_pages' not found or not executable."
    echo "Please compile it first: gcc -static -o hugetlb_reserve_pages_out_put_pages hugetlb_reserve_pages_out_put_pages.c"
    exit 1
fi

# 1. Set global pool such that only the mount-time reservation can succeed
echo 1 > "$SYSFS_PATH/nr_hugepages"
echo 0 > "$SYSFS_PATH/nr_overcommit_hugepages"

initial_resv=$(cat "$SYSFS_PATH/resv_hugepages")
echo "Initial resv_hugepages (before mount): $initial_resv"

# 2. Mount with min_size = 1 page, max size = 2 pages
min_size_str="${mb}M"
max_size_str="$((mb * 2))M"
mmap_size_bytes=$((hpage_size_bytes * 2))

mkdir -p "$MNT_PATH"
echo "Mounting hugetlbfs with pagesize=${mb}M, min_size=$min_size_str, size=$max_size_str..."
if ! mount -t hugetlbfs -o "pagesize=${mb}M,min_size=$min_size_str,size=$max_size_str" none "$MNT_PATH"; then
    echo "Failed to mount hugetlbfs"
    exit 1
fi

resv_after_mount=$(cat "$SYSFS_PATH/resv_hugepages")
echo "resv_hugepages after mount: $resv_after_mount"
expected_after_mount=$((initial_resv + 1))
if [ "$resv_after_mount" != "$expected_after_mount" ]; then
    echo "ERROR: resv_hugepages is not $expected_after_mount after mount (actual: $resv_after_mount)!"
    exit 1
fi

# Check mount stats after mount
expected_bsize=$hpage_size_bytes
bsize_S=$(stat -f -c "%S" "$MNT_PATH")
bsize_s=$(stat -f -c "%s" "$MNT_PATH")
echo "Mount block size after mount: $bsize_S / $bsize_s (expected: $expected_bsize)"
if [ "$bsize_S" != "$expected_bsize" ] && [ "$bsize_s" != "$expected_bsize" ]; then
    echo "ERROR: Unexpected mount block size after mount (actual S:$bsize_S s:$bsize_s, expected: $expected_bsize)"
    exit 1
fi

actual_stats_mount=$(stat -f -c "%b %f %a" "$MNT_PATH")
expected_stats_mount="2 2 2"
echo "Mount stats after mount (total free avail): $actual_stats_mount (expected: $expected_stats_mount)"
if [ "$actual_stats_mount" != "$expected_stats_mount" ]; then
    echo "ERROR: Unexpected mount stats after mount: $actual_stats_mount (expected: $expected_stats_mount)"
    exit 1
fi

# 3. Run the reproducer to trigger the out_put_pages failure path
echo "Running reproducer (expecting mmap failure with ENOMEM)..."
if ./hugetlb_reserve_pages_out_put_pages "$FILE_PATH" "$mmap_size_bytes"; then
    echo "Reproducer finished successfully."
    resv_after_mmap=$(cat "$SYSFS_PATH/resv_hugepages")
    echo "resv_hugepages after failed mmap: $resv_after_mmap"
    expected_after_mmap=$expected_after_mount
    if [ "$resv_after_mmap" = "$expected_after_mmap" ]; then
        echo "RESULT: out_put_pages EXERCISED (resv_hugepages preserved at $expected_after_mmap as expected)"

        # Check mount stats
        expected_bsize=$hpage_size_bytes
        bsize_S=$(stat -f -c "%S" "$MNT_PATH")
        bsize_s=$(stat -f -c "%s" "$MNT_PATH")
        echo "Mount block size: $bsize_S / $bsize_s (expected: $expected_bsize)"
        if [ "$bsize_S" != "$expected_bsize" ] && [ "$bsize_s" != "$expected_bsize" ]; then
            echo "ERROR: Unexpected mount block size (actual S:$bsize_S s:$bsize_s, expected: $expected_bsize)"
            exit 1
        fi

        actual_stats=$(stat -f -c "%b %f %a" "$MNT_PATH")
        expected_stats="2 2 2"
        echo "Mount stats (total free avail): $actual_stats (expected: $expected_stats)"
        if [ "$actual_stats" != "$expected_stats" ]; then
            echo "RESULT: Unexpected mount stats after failed mmap (FAIL)"
            exit 1
        else
            echo "RESULT: Mount stats restored to $expected_stats as expected (PASS)"
        fi
    else
        echo "RESULT: Unexpected resv_hugepages value: $resv_after_mmap (expected: $expected_after_mmap)"
        exit 1
    fi
else
    echo "FAIL: Reproducer returned non-zero (mmap didn't fail with ENOMEM)"
    exit 1
fi

# 4. Disable trap and do manual cleanup to check for final unmount underflow
trap - EXIT

echo "Unmounting..."
umount "$MNT_PATH"
rmdir "$MNT_PATH"

final_resv=$(cat "$SYSFS_PATH/resv_hugepages")
echo "Final resv_hugepages (after unmount): $final_resv"

# Restore original values
echo "Restoring original hugepage settings..."
echo "$orig_nr" > "$SYSFS_PATH/nr_hugepages"
echo "$orig_overcommit" > "$SYSFS_PATH/nr_overcommit_hugepages"

if [ "$final_resv" = "$initial_resv" ]; then
    echo "RESULT: State restored to $initial_resv (or cleaned up if fixed)"
    echo "ALL DONE."
    exit 0
else
    echo "RESULT: Underflow/Leak/Incorrect state detected! (final_resv = $final_resv, expected = $initial_resv)"
    echo "ALL DONE."
    exit 1
fi
