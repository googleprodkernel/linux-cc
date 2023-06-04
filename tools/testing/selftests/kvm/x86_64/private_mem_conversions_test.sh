#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only */
#
# Wrapper script which runs different test setups of
# private_mem_conversions_test.
#
# tools/testing/selftests/kvm/private_mem_conversions_test.sh
# Copyright (C) 2023, Google LLC.

set -e

# The other hugetlb sizes are not supported on x86_64
[ "$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo 0)" -gt "0" ] && hugepage_2mb_enabled=1
[ "$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || echo 0)" -gt "0" ] && hugepage_1gb_enabled=1

backing_src_types=( anonymous )
backing_src_types+=( anonymous_thp )
[ -n "$hugepage_2mb_enabled" ] || [ -n "$hugepage_1gb_enabled" ] && \
    backing_src_types+=( anonymous_hugetlb ) || echo "skipping anonymous_hugetlb backing source type"
[ -n "$hugepage_2mb_enabled" ] && \
    backing_src_types+=( anonymous_hugetlb_2mb ) || echo "skipping anonymous_hugetlb_2mb backing source type"
[ -n "$hugepage_1gb_enabled" ] && \
    backing_src_types+=( anonymous_hugetlb_1gb ) || echo "skipping anonymous_hugetlb_1gb backing source type"
backing_src_types+=( shmem )
backing_src_types+=( shared_hugetlb )

set +e

TEST_EXECUTABLE="$(dirname $0)/private_mem_conversions_test"

(
	set -e

	for src_type in ${backing_src_types[@]}; do

		set -x

		$TEST_EXECUTABLE -s $src_type -n4
		$TEST_EXECUTABLE -s $src_type -n4 -m

		{ set +x; } 2>/dev/null

		echo
	done
)
RET=$?

exit $RET
