#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Script to run guest_memfd and related tests, stopping on the first failure.
#
# Copyright (C) 2026, Google LLC.

set -e

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
KSFT_SKIP=4

# Array of test paths relative to SCRIPT_DIR
TESTS=(
	"guest_memfd_test"
	"pre_fault_memory_test"
	"x86/private_mem_kvm_exits_test"
	"x86/guest_memfd_conversions_test"
	"x86/private_mem_conversions_test.sh"
)

for test_path in "${TESTS[@]}"; do
	full_path="${SCRIPT_DIR}/${test_path}"
	if [ ! -f "$full_path" ]; then
		echo "Error: Test executable not found: $full_path" >&2
		exit 1
	fi
	if [ ! -x "$full_path" ]; then
		echo "Error: Test is not executable: $full_path" >&2
		exit 1
	fi
done

has_success=0
has_skip=0

for test_path in "${TESTS[@]}"; do
	full_path="${SCRIPT_DIR}/${test_path}"
	echo "========================================================"
	echo "Running: $test_path"
	echo "========================================================"
	res=0
	"$full_path" || res=$?
	if [ $res -eq 0 ]; then
		echo "SUCCESS: $test_path"
		has_success=1
	elif [ $res -eq $KSFT_SKIP ]; then
		echo "SKIPPED: $test_path"
		has_skip=1
	else
		echo "FAILED: $test_path (exit code $res)" >&2
		exit $res
	fi
	echo ""
done

if [ $has_success -eq 1 ]; then
	echo "All executed tests passed successfully!"
	exit 0
elif [ $has_skip -eq 1 ]; then
	echo "All tests were skipped."
	exit $KSFT_SKIP
else
	echo "No tests were run."
	exit 0
fi
