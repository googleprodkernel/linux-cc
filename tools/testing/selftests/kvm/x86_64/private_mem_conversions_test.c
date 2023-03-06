// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022, Google LLC.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/memfd.h>
#include <linux/sizes.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

#define DATA_SLOT_BASE   10
#define DATA_GPA_BASE    ((uint64_t)(1ull << 32))
#define DATA_SIZE        ((uint64_t)(SZ_2M + PAGE_SIZE))
#define DATA_GPA_SPACING DATA_SIZE

/* Horrific macro so that the line info is captured accurately :-( */
#define memcmp_g(gpa, pattern,  size)				\
do {								\
	uint8_t *mem = (uint8_t *)gpa;				\
	size_t i;						\
								\
	for (i = 0; i < size; i++)				\
		GUEST_ASSERT_4(mem[i] == pattern,		\
			       gpa, i, mem[i], pattern);	\
} while (0)

static void memcmp_h(uint8_t *mem, uint8_t pattern, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		TEST_ASSERT(mem[i] == pattern,
			    "Expected 0x%x at offset %lu, got 0x%x",
			    pattern, i, mem[i]);
}

static void memcmp_ne_h(uint8_t *mem, uint8_t pattern, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		TEST_ASSERT(mem[i] != pattern,
			    "Expected not to find 0x%x at offset %lu but got 0x%x",
			    pattern, i, mem[i]);
}

/*
 * Run memory conversion tests with explicit conversion:
 * Execute KVM hypercall to map/unmap gpa range which will cause userspace exit
 * to back/unback private memory. Subsequent accesses by guest to the gpa range
 * will not cause exit to userspace.
 *
 * Test memory conversion scenarios with following steps:
 * 1) Access private memory using private access and verify that memory contents
 *   are not visible to userspace.
 * 2) Convert memory to shared using explicit conversions and ensure that
 *   userspace is able to access the shared regions.
 * 3) Convert memory back to private using explicit conversions and ensure that
 *   userspace is again not able to access converted private regions.
 */

#define GUEST_STAGE(o, s) { .offset = o, .size = s }

#define UCALL_RW_SHARED (0xca11 - 0)
#define UCALL_R_PRIVATE (0xca11 - 1)

#define REQUEST_HOST_RW_SHARED(gpa, size, current_pattern, new_pattern) \
	ucall(UCALL_RW_SHARED, 4, gpa, size, current_pattern, new_pattern)

#define REQUEST_HOST_R_PRIVATE(gpa, size, expected_pattern) \
	ucall(UCALL_R_PRIVATE, 3, gpa, size, expected_pattern)

const uint8_t init_p = 0xcc;

static void guest_test_conversions(uint64_t gpa_base)
{
	struct {
		uint64_t offset;
		uint64_t size;
		uint8_t pattern;
	} stages[] = {
		GUEST_STAGE(0, PAGE_SIZE),
		GUEST_STAGE(0, SZ_2M),
		GUEST_STAGE(PAGE_SIZE, PAGE_SIZE),
		GUEST_STAGE(PAGE_SIZE, SZ_2M),
		GUEST_STAGE(SZ_2M, PAGE_SIZE),
	};
	uint64_t j;
	int i;

	for (i = 0; i < ARRAY_SIZE(stages); i++) {
		uint64_t gpa = gpa_base + stages[i].offset;
		uint64_t size = stages[i].size;
		uint8_t p1 = 0x11;
		uint8_t p2 = 0x22;
		uint8_t p3 = 0x33;
		uint8_t p4 = 0x44;

		/*
		 * Set the test region to pattern one to differentiate it from
		 * the data range as a whole (contains the initial pattern).
		 */
		memset((void *)gpa, p1, size);

		/*
		 * Convert to private, set and verify the the private data, and
		 * then verify that the rest of the data (map shared) still
		 * holds the initial pattern.  Unlike shared memory, punching a
		 * hole in private memory is destructive, i.e. previous values
		 * aren't guaranteed to be preserved.
		 */
		kvm_hypercall_map_private(gpa, size);
		memset((void *)gpa, p2, size);

		/*
		 * Host should not be able to read the values written to private
		 * memory
		 */
		REQUEST_HOST_R_PRIVATE(gpa, size, p2);

		/*
		 * Verify that the private memory was set to pattern two, and
		 * that shared memory still holds the initial pattern.
		 */
		memcmp_g(gpa, p2, size);
		if (gpa > gpa_base)
			memcmp_g(gpa_base, init_p, gpa - gpa_base);
		if (gpa + size < gpa_base + DATA_SIZE)
			memcmp_g(gpa + size, init_p,
				 (gpa_base + DATA_SIZE) - (gpa + size));

		/*
		 * Convert odd-number page frames back to shared to verify KVM
		 * also correctly handles holes in private ranges.
		 */
		for (j = 0; j < size; j += PAGE_SIZE) {
			if (!((j >> PAGE_SHIFT) & 1))
				continue;

			kvm_hypercall_map_shared(gpa + j, PAGE_SIZE);
			REQUEST_HOST_RW_SHARED(gpa + j, PAGE_SIZE, p1, p3);

			memcmp_g(gpa + j, p3, PAGE_SIZE);
		}

		/*
		 * Even-number pages are still mapped as private, host should
		 * not be able to read those values.
		 */
		for (j = 0; j < size; j += PAGE_SIZE) {
			if (!((j >> PAGE_SHIFT) & 1))
				REQUEST_HOST_R_PRIVATE(gpa + j, PAGE_SIZE, p2);
		}

		/*
		 * Convert the entire region back to shared, explicitly write
		 * pattern three to fill in the even-number frames before
		 * asking the host to verify (and write pattern four).
		 */
		kvm_hypercall_map_shared(gpa, size);
		memset((void *)gpa, p3, size);
		REQUEST_HOST_RW_SHARED(gpa, size, p3, p4);
		memcmp_g(gpa, p4, size);

		/* Reset the shared memory back to the initial pattern. */
		memset((void *)gpa, init_p, size);
	}
}

static void guest_code(uint64_t gpa_base, uint32_t iterations)
{
	int i;

	/* Memory should be shared by default. */
	memset((void *)gpa_base, ~init_p, DATA_SIZE);
	REQUEST_HOST_RW_SHARED(gpa_base, DATA_SIZE, ~init_p, init_p);
	memcmp_g(gpa_base, init_p, DATA_SIZE);

	for (i = 0; i < iterations; i++)
		guest_test_conversions(gpa_base);

	GUEST_DONE();
}

static void handle_exit_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	uint64_t gpa = run->hypercall.args[0];
	uint64_t npages = run->hypercall.args[1];
	uint64_t attrs = run->hypercall.args[2];

	TEST_ASSERT(run->hypercall.nr == KVM_HC_MAP_GPA_RANGE,
		    "Wanted MAP_GPA_RANGE (%u), got '%llu'",
		    KVM_HC_MAP_GPA_RANGE, run->hypercall.nr);

	vm_mem_map_shared_or_private(vcpu->vm, gpa, npages * PAGE_SIZE,
				     !(attrs & KVM_MAP_GPA_RANGE_ENCRYPTED));

	run->hypercall.ret = 0;
}

static uint64_t data_gpa_base_for_vcpu_id(uint8_t n)
{
	return DATA_GPA_BASE + n * DATA_GPA_SPACING;
}

static void test_invalidation_code_unbound(struct kvm_vm *vm, uint8_t nr_memslots,
					   off_t data_size)
{
	struct {
		uint32_t fd;
		uint64_t offset;
	} params[KVM_MAX_VCPUS];
	int i;

	for (i = 0; i < nr_memslots; i++) {
		struct userspace_mem_region *region;

		region = memslot2region(vm, DATA_SLOT_BASE + i);
		params[i].fd = region->region.restrictedmem_fd;
		params[i].offset = region->region.restrictedmem_offset;
	}

	kvm_vm_free(vm);

	/*
	 * At this point the KVM invalidation code should have been unbound from
	 * the vm. We do allocation and truncation to exercise the restrictedmem
	 * code. There should be no issues after the unbinding happens.
	 */
	for (i = 0; i < nr_memslots; i++) {
		if (fallocate(params[i].fd, 0, params[i].offset, data_size))
			TEST_FAIL("Unexpected error in fallocate");
		if (fallocate(params[i].fd,
			      FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
			      params[i].offset, data_size))
			TEST_FAIL("Unexpected error in fallocate");
	}

}

static void test_mem_conversions_for_vcpu(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
					  uint32_t iterations)
{
	struct kvm_run *run;
	struct ucall uc;

	vcpu_args_set(vcpu, 2, data_gpa_base_for_vcpu_id(vcpu->id), iterations);

	run = vcpu->run;
	for ( ;; ) {
		vcpu_run(vcpu);

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_exit_hypercall(vcpu);
			continue;
		}

		TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
			    "Wanted KVM_EXIT_IO, got exit reason: %u (%s)",
			    run->exit_reason, exit_reason_str(run->exit_reason));

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT_4(uc, "%lx %lx %lx %lx");
		case UCALL_R_PRIVATE: {
			uint8_t *hva = addr_gpa2hva(vm, uc.args[0]);
			uint64_t size = uc.args[1];

			/*
			 * Try to read hva for private gpa from host, should not
			 * be able to read private data
			 */
			memcmp_ne_h(hva, uc.args[2], size);
			break;
		}
		case UCALL_RW_SHARED: {
			uint8_t *hva = addr_gpa2hva(vm, uc.args[0]);
			uint64_t size = uc.args[1];

			/* In all cases, the host should observe the shared data. */
			memcmp_h(hva, uc.args[2], size);

			/* Write the new pattern to shared memory. */
			memset(hva, uc.args[3], size);
			break;
		}
		case UCALL_DONE:
			return;
		default:
			TEST_FAIL("Unknown ucall 0x%lx.", uc.cmd);
		}
	}
}

struct thread_args {
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	uint32_t iterations;
};

void *thread_function(void *input)
{
	struct thread_args *args = (struct thread_args *)input;

	test_mem_conversions_for_vcpu(args->vm, args->vcpu, args->iterations);

	return NULL;
}

static void add_memslot_for_vcpu(
	struct kvm_vm *vm, enum vm_mem_backing_src_type src_type, uint8_t vcpu_id)
{
	uint64_t gpa = data_gpa_base_for_vcpu_id(vcpu_id);
	uint32_t slot = DATA_SLOT_BASE + vcpu_id;
	uint64_t npages = DATA_SIZE / vm->page_size;

	vm_userspace_mem_region_add(vm, src_type, gpa, slot, npages,
				    KVM_MEM_PRIVATE);
}

static void test_mem_conversions(enum vm_mem_backing_src_type src_type,
				 uint8_t nr_vcpus, uint32_t iterations)
{
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
	pthread_t threads[KVM_MAX_VCPUS];
	struct thread_args args[KVM_MAX_VCPUS];
	struct kvm_vm *vm;

	int i;
	int npages_for_all_vcpus;

	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_PROTECTED_VM,
	};

	vm = __vm_create_with_vcpus(shape, nr_vcpus, 0, guest_code, vcpus);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, (1 << KVM_HC_MAP_GPA_RANGE));

	npages_for_all_vcpus = DATA_SIZE / vm->page_size * nr_vcpus;
	virt_map(vm, DATA_GPA_BASE, DATA_GPA_BASE, npages_for_all_vcpus);

	for (i = 0; i < nr_vcpus; i++)
		add_memslot_for_vcpu(vm, src_type, i);

	for (i = 0; i < nr_vcpus; i++) {
		args[i].vm = vm;
		args[i].vcpu = vcpus[i];
		args[i].iterations = iterations;

		pthread_create(&threads[i], NULL, thread_function, &args[i]);
	}

	for (i = 0; i < nr_vcpus; i++)
		pthread_join(threads[i], NULL);

	test_invalidation_code_unbound(vm, nr_vcpus, DATA_SIZE);
}

static void usage(const char *command)
{
	puts("");
	printf("usage: %s [-h] [-s mem-type] [-n number-of-vcpus] [-i number-of-iterations]\n",
	       command);
	puts("");
	backing_src_help("-s");
	puts("");
	puts(" -n: specify the number of vcpus to run memory conversion");
	puts("     tests in parallel on. (default: 2)");
	puts("");
	puts(" -i: specify the number iterations of memory conversion");
	puts("     tests to run. (default: 10)");
	puts("");
}

int main(int argc, char *argv[])
{
	enum vm_mem_backing_src_type src_type = DEFAULT_VM_MEM_SRC;
	uint8_t nr_vcpus = 2;
	uint32_t iterations = 10;
	int opt;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_EXIT_HYPERCALL));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_PROTECTED_VM));

	while ((opt = getopt(argc, argv, "hs:n:i:")) != -1) {
		switch (opt) {
		case 'n':
			nr_vcpus = atoi_positive("nr_vcpus", optarg);
			break;
		case 'i':
			iterations = atoi_positive("iterations", optarg);
			break;
		case 's':
			src_type = parse_backing_src_type(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	test_mem_conversions(src_type, nr_vcpus, iterations);
	return 0;
}
