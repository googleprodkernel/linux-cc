// SPDX-License-Identifier: GPL-2.0-only
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "tdx/tdx_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"

#define GUEST_MEM_GPA SZ_4G
#define GUEST_MEM_GVA SZ_4G
#define GUEST_MEM_SLOT 10

static size_t guest_mem_size = (size_t)SZ_4G;
static unsigned int iterations = 10;

static void help(char *name)
{
	puts("");
	printf("usage: %s [-h] [-i iterations] [-s size] [--iterations iterations] [--size size]\n",
	       name);
	puts("");
	printf(" -i, --iterations       Number of iterations (default: 10)\n");
	printf(" -s, --size             Size of guest memory (e.g. 4k, 2m, 4g, default: 4g)\n");
	puts("");
	exit(0);
}

enum accept_page_level {
	PAGE_LEVEL_4K = 0,
	PAGE_LEVEL_2M,
};

static u64 tdx_accept_page(u64 gpa, enum accept_page_level level)
{
#define TDG_MEM_PAGE_ACCEPT 6
	register u64 rax_reg asm("rax") = TDG_MEM_PAGE_ACCEPT;
	register u64 rcx_reg asm("rcx") = gpa | level;

	asm volatile(
	 ".byte 0x66,0x0f,0x01,0xcc" /* tdcall */
	 : "+r" (rax_reg)
	 : "r" (rcx_reg)
	 : "cc", "memory"
	);

	return rax_reg;
}

static void guest_code(void)
{
	uint64_t i;

	while (true) {
		for (i = 0; i < guest_mem_size; i += PAGE_SIZE) {
			tdx_accept_page(GUEST_MEM_GPA + i, PAGE_LEVEL_4K);
			WRITE_ONCE(*((uint8_t *)(GUEST_MEM_GVA + i)), 0);
		}

		GUEST_SYNC(0);
	}
}

static void test_conversion(u64 gmem_flags)
{
	u64 nr_pages = guest_mem_size >> PAGE_SHIFT;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	int i;

	TEST_REQUIRE(is_tdx_supported());

	fprintf(stderr, "Creating VM...\n");
	vm = __vm_create(VM_SHAPE_TDX, 1, nr_pages);
	vcpu = vm_vcpu_add(vm, 0, guest_code);

	sync_global_to_guest(vm, guest_mem_size);

	fprintf(stderr, "Adding memslot...\n");
	vm_mem_add(vm, VM_MEM_SRC_SHMEM, GUEST_MEM_GPA, GUEST_MEM_SLOT,
		   nr_pages, KVM_MEM_GUEST_MEMFD, -1, 0, gmem_flags);

	/* Allocate physical pages as private in GUEST_MEM_SLOT */
	fprintf(stderr, "Allocating physical pages...\n");
	vm_phy_pages_alloc(vm, nr_pages, GUEST_MEM_GPA, GUEST_MEM_SLOT);

	fprintf(stderr, "Mapping it...\n");
	virt_map(vm, GUEST_MEM_GVA, GUEST_MEM_GPA, nr_pages);

	fprintf(stderr, "Finalizing...\n");
	kvm_arch_vm_finalize_vcpus(vm);

	/* Run guest to touch every page, faulting them into stage 2 */
	fprintf(stderr, "Guest touching to fault in pages...\n");
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);

	/* Benchmark: Conversion to shared */
	for (i = 0; i < iterations; i++) {
		fprintf(stderr, "Converting to shared (%d)...\n", i + 1);
		vm_mem_set_shared(vm, GUEST_MEM_GPA, guest_mem_size);

		fprintf(stderr, "Converting to private (%d)...\n", i + 1);
		vm_mem_set_private(vm, GUEST_MEM_GPA, guest_mem_size);

		fprintf(stderr, "Guest touching to fault in pages (%d)...\n",
			i + 1);
		vcpu_run(vcpu);
		TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	}

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	static const struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"iterations", required_argument, 0, 'i'},
		{"size", required_argument, 0, 's'},
		{0, 0, 0, 0}
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "hi:s:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			iterations = atoi_positive("Number of iterations", optarg);
			break;
		case 's':
			guest_mem_size = parse_size(optarg);
			break;
		case 'h':
		default:
			help(argv[0]);
			break;
		}
	}

	test_conversion(0);

	return 0;
}
