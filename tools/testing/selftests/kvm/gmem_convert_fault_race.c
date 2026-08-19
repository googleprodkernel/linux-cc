// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test for race between guest_memfd page faulting and memory attribute
 * conversion to private.
 *
 * Have the guest iterate over a 512-page range to fault pages in, while the
 * host concurrently attempts to convert the entire range to private. If the
 * conversion safety check runs while the vCPU is holding a folio refcount
 * during an in-flight page fault, kvm_gmem_is_safe_for_conversion() returns
 * -EAGAIN.
 *
 * Copyright (C) 2026, Google LLC.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/sizes.h>
#include <linux/kvm.h>

#include "kvm_util.h"
#include "test_util.h"
#include "processor.h"

#define TEST_NPAGES	512
#define TEST_GVA	0x90000000ULL
#define TEST_GPA	SZ_4G
#define TEST_SLOT		1
#define DEFAULT_ITERATIONS	10000
#define NR_VCPUS		4

static int gmem_fd;
static bool race_won;

static void usage(const char *cmd)
{
	printf("Usage: %s [-h] [-i iterations]\n", cmd);
	printf("  -i: Number of iterations (default: %d)\n",
	       DEFAULT_ITERATIONS);
	puts("");
	exit(0);
}

static void guest_code(uint64_t start_page)
{
	u64 *mem = (u64 *)TEST_GVA;
	int i = start_page;

	for (;;) {
		WRITE_ONCE(mem[i * (PAGE_SIZE / sizeof(u64))], i);
		i = (i + 1) % TEST_NPAGES;
		if (i == start_page)
			GUEST_SYNC(0);
	}
}

static void *vcpu_worker(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	struct ucall uc;

	while (!READ_ONCE(race_won)) {
		int r = __vcpu_run(vcpu);

		if (r == -1 && errno == EINTR)
			continue;

		if (r == -1 && errno == EFAULT &&
		    vcpu->run->exit_reason == KVM_EXIT_MEMORY_FAULT)
			continue;

		if (READ_ONCE(race_won))
			break;

		TEST_ASSERT(!r, "vcpu_run failed: %d (errno %d)", r, errno);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_FAIL("Unexpected ucall %lu", uc.cmd);
		}
	}

	return NULL;
}

static void test_gmem_convert_fault_race(int iterations)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_SW_PROTECTED_VM,
	};
	struct kvm_vcpu *vcpus[NR_VCPUS];
	pthread_t threads[NR_VCPUS];
	struct kvm_vm *vm;
	size_t size;
	int iter, i, r;

	size = TEST_NPAGES * getpagesize();

	vm = __vm_create_with_vcpus(shape, NR_VCPUS, TEST_NPAGES,
				    guest_code, vcpus);

	vm_mem_add(vm, VM_MEM_SRC_SHMEM, TEST_GPA, TEST_SLOT, TEST_NPAGES,
		   KVM_MEM_GUEST_MEMFD, -1, 0,
		   GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED);

	gmem_fd = kvm_slot_to_fd(vm, TEST_SLOT);
	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

	for (i = 0; i < NR_VCPUS; i++) {
		vcpu_args_set(vcpus[i], 1, i * (TEST_NPAGES / NR_VCPUS));
		r = pthread_create(&threads[i], NULL, vcpu_worker, vcpus[i]);
		TEST_ASSERT(!r, "pthread_create failed: %d", r);
	}

	for (iter = 0; iter < iterations; iter++) {
		u64 error_offset = 0;

		/*
		 * Convert range to shared. This zaps any existing private
		 * SPTEs so that subsequent guest accesses in the vCPU threads
		 * will trigger page faults again.
		 */
		gmem_set_shared(gmem_fd, 0, size);

		/*
		 * Give vCPUs a brief window to re-enter guest mode after the
		 * SPTE invalidation and begin in-flight page faults before
		 * attempting conversion to private.
		 */
		usleep(10);

		/*
		 * Convert range to private in parallel with the guest faulting
		 * in pages across the 512-page range. If this runs while a
		 * vCPU is holding a folio refcount during an in-flight page
		 * fault, kvm_gmem_is_safe_for_conversion() returns -EAGAIN.
		 */
		r = __gmem_set_private(gmem_fd, 0, size, &error_offset);
		if (r == -1 && errno == EAGAIN) {
			TEST_ASSERT(error_offset < size,
				    "Expected error_offset within range (0x%zx), got 0x%llx",
				    size, (unsigned long long)error_offset);
			TEST_ASSERT(error_offset % getpagesize() == 0,
				    "Expected page-aligned error_offset, got 0x%llx",
				    (unsigned long long)error_offset);
			WRITE_ONCE(race_won, true);
			pr_info("Reproduced -EAGAIN on attempt %d at error_offset 0x%llx\n",
				iter, (unsigned long long)error_offset);
			break;
		}

		TEST_ASSERT(r == 0,
			    "Unexpected error from __gmem_set_private: %d (errno %d)",
			    r, errno);
	}

	WRITE_ONCE(race_won, true);
	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(threads[i], NULL);

	TEST_ASSERT(iter < iterations,
		    "Failed to reproduce -EAGAIN within %d attempts",
		    iterations);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	int iterations = DEFAULT_ITERATIONS;
	int opt;

	while ((opt = getopt(argc, argv, "hi:")) != -1) {
		switch (opt) {
		case 'i':
			iterations = atoi_positive("Number of iterations", optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

#ifdef __x86_64__
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) &
		     BIT(KVM_X86_SW_PROTECTED_VM));
#endif
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) &
		     KVM_MEMORY_ATTRIBUTE_PRIVATE);

	test_gmem_convert_fault_race(iterations);

	return 0;
}
