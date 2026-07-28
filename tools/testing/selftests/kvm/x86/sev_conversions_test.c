// SPDX-License-Identifier: GPL-2.0-only
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <math.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"

#define GHCB_MSR_REG_GPA_REQ		0x012
#define GHCB_MSR_REG_GPA_REQ_VAL(v)                \
	/* GHCBData[63:12] */                      \
	(((u64)((v) & GENMASK_ULL(51, 0)) << 12) | \
	 /* GHCBData[11:0] */			   \
	 GHCB_MSR_REG_GPA_REQ)

#define GHCB_MSR_REG_GPA_RESP		0x013
#define GHCB_MSR_REG_GPA_RESP_VAL(v)			\
	/* GHCBData[63:12] */				\
	(((u64)(v) & GENMASK_ULL(63, 12)) >> 12)

#define GHCB_DATA_LOW			12
#define GHCB_MSR_INFO_MASK		(BIT_ULL(GHCB_DATA_LOW) - 1)
#define GHCB_RESP_CODE(v) ((v) & GHCB_MSR_INFO_MASK)

/*
 * SNP Page State Change Operation
 *
 * GHCBData[55:52] - Page operation:
 *   0x0001	Page assignment, Private
 *   0x0002	Page assignment, Shared
 */
enum psc_op {
	SNP_PAGE_STATE_PRIVATE = 1,
	SNP_PAGE_STATE_SHARED,
};

#define GHCB_MSR_PSC_REQ		0x014
#define GHCB_MSR_PSC_REQ_GFN(gfn, op)			\
	/* GHCBData[55:52] */				\
	(((u64)((op) & 0xf) << 52) |			\
	/* GHCBData[51:12] */				\
	((u64)((gfn) & GENMASK_ULL(39, 0)) << 12) |	\
	/* GHCBData[11:0] */				\
	GHCB_MSR_PSC_REQ)

#define GHCB_MSR_PSC_RESP		0x015
#define GHCB_MSR_PSC_RESP_VAL(val)			\
	/* GHCBData[63:32] */				\
	(((u64)(val) & GENMASK_ULL(63, 32)) >> 32)

static u64 ghcb_gpa;

static void snp_register_ghcb(void)
{
	u64 ghcb_pfn = ghcb_gpa >> PAGE_SHIFT;
	u64 val;

	GUEST_ASSERT(ghcb_gpa);

	wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_REG_GPA_REQ_VAL(ghcb_gpa >> PAGE_SHIFT));
	vmgexit();

	val = rdmsr(MSR_AMD64_SEV_ES_GHCB);
	GUEST_ASSERT_EQ(GHCB_RESP_CODE(val), GHCB_MSR_REG_GPA_RESP);
	GUEST_ASSERT_EQ(GHCB_MSR_REG_GPA_RESP_VAL(val), ghcb_pfn);
}

static void snp_page_state_change(u64 gpa, enum psc_op op)
{
	u64 val;

	wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_PSC_REQ_GFN(gpa >> PAGE_SHIFT, op));
	vmgexit();

	val = rdmsr(MSR_AMD64_SEV_ES_GHCB);
	GUEST_ASSERT_EQ(GHCB_RESP_CODE(val), GHCB_MSR_PSC_RESP);
	GUEST_ASSERT_EQ(GHCB_MSR_PSC_RESP_VAL(val), 0);
}

#define RMP_PG_SIZE_4K			0

static inline void pvalidate(void *vaddr, bool validate)
{
	bool no_rmpupdate;
	int rc;

	/* "pvalidate" mnemonic support in binutils 2.36 and newer */
	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
		     : "=@ccc"(no_rmpupdate), "=a"(rc)
		     : "a"(vaddr), "c"(RMP_PG_SIZE_4K), "d"(validate)
		     : "memory", "cc");

	GUEST_ASSERT(!no_rmpupdate);
	GUEST_ASSERT_EQ(rc, 0);
}

#define CONVERSIONS_PRIVATE_VAL 0xab
#define CONVERSIONS_HOST_SHARED_VAL 0xcd
#define CONVERSIONS_GUEST_SHARED_VAL 0xef

static void handle_page_state_change(struct kvm_vcpu *vcpu,
				     bool expected_to_private,
				     gpa_t expected_gpa)
{
	struct kvm_run *run = vcpu->run;
	bool to_private;
	u64 attributes;
	size_t size;
	gpa_t gpa;

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_HYPERCALL);
	TEST_ASSERT_EQ(run->hypercall.nr, KVM_HC_MAP_GPA_RANGE);

	gpa = run->hypercall.args[0];
	TEST_ASSERT_EQ(gpa, expected_gpa);

	size = run->hypercall.args[1] * PAGE_SIZE;
	TEST_ASSERT_EQ(size, PAGE_SIZE);

	to_private = run->hypercall.args[2] & KVM_MAP_GPA_RANGE_ENCRYPTED;
	TEST_ASSERT_EQ(to_private, expected_to_private);

	attributes = to_private ? KVM_MEMORY_ATTRIBUTE_PRIVATE : 0;
	vm_mem_set_memory_attributes(vcpu->vm, gpa, size, attributes);
}

static void guest_code_conversion(u8 *conversions_shared_gva,
				  u8 *conversions_private_gva,
				  u64 conversions_gpa)
{
	snp_register_ghcb();

	WRITE_ONCE(*conversions_private_gva, CONVERSIONS_PRIVATE_VAL);
	GUEST_ASSERT_EQ(READ_ONCE(*conversions_private_gva), CONVERSIONS_PRIVATE_VAL);

	pvalidate(conversions_private_gva, false);
	snp_page_state_change(conversions_gpa, SNP_PAGE_STATE_SHARED);

	GUEST_ASSERT_EQ(READ_ONCE(*conversions_shared_gva), CONVERSIONS_HOST_SHARED_VAL);
	WRITE_ONCE(*conversions_shared_gva, CONVERSIONS_GUEST_SHARED_VAL);

	snp_page_state_change(conversions_gpa, SNP_PAGE_STATE_PRIVATE);
	pvalidate(conversions_private_gva, true);

	WRITE_ONCE(*conversions_private_gva, CONVERSIONS_PRIVATE_VAL);
	GUEST_ASSERT_EQ(READ_ONCE(*conversions_private_gva), CONVERSIONS_PRIVATE_VAL);

	wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_TERM_REQ);
	vmgexit();
}

static void test_conversion(u64 policy)
{
	struct userspace_mem_region *region;
	gva_t conversions_private_gva;
	gpa_t conversions_gpa;
	gva_t conversions_shared_gva;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	size_t conversions_size;
	gva_t ghcb_gva;
	void *ghcb_hva;
	u8 *test_hva;

	vm = vm_create_shape_with_one_vcpu(VM_SHAPE_SNP, &vcpu,
					   guest_code_conversion);

	ghcb_gva = vm_alloc_shared(vm, PAGE_SIZE, KVM_UTIL_MIN_VADDR,
				   MEM_REGION_TEST_DATA);
	ghcb_hva = addr_gva2hva(vm, ghcb_gva);
	ghcb_gpa = addr_gva2gpa(vm, ghcb_gva);
	sync_global_to_guest(vm, ghcb_gpa);

	conversions_size = getpagesize();
	conversions_shared_gva = vm_alloc_shared(vm, conversions_size,
						 KVM_UTIL_MIN_VADDR,
						 MEM_REGION_TEST_DATA);
	conversions_gpa = addr_gva2gpa(vm, conversions_shared_gva);

	conversions_private_gva = vm_unused_gva_gap(vm, conversions_size,
						    KVM_UTIL_MIN_VADDR);

	/* virt_pg_map() will map based on protected_phy_pages. */
	region = vm_get_mem_region(vm, MEM_REGION_TEST_DATA);
	sparsebit_set(region->protected_phy_pages, conversions_gpa >> vm->page_shift);
	virt_pg_map(vm, conversions_private_gva, conversions_gpa);

	vcpu_args_set(vcpu, 3, conversions_shared_gva, conversions_private_gva,
		      conversions_gpa);

	test_hva = addr_gva2hva(vm, conversions_shared_gva);

	vm_sev_launch(vm, policy, NULL);

	fprintf(stderr,
		"ghcb_hva=%p ghcb_gpa=%lx ghcb_gva=%lx\n",
		ghcb_hva, ghcb_gpa, ghcb_gva);
	fprintf(stderr,
		"test_hva=%p conversions_gpa=%lx conversions_private_gva=%lx conversions_shared_gva=%lx\n",
		test_hva, conversions_gpa, conversions_private_gva, conversions_shared_gva);

	vcpu_run(vcpu);
	handle_page_state_change(vcpu, false, conversions_gpa);

	WRITE_ONCE(*test_hva, CONVERSIONS_HOST_SHARED_VAL);
	TEST_ASSERT_EQ(READ_ONCE(*test_hva), CONVERSIONS_HOST_SHARED_VAL);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(READ_ONCE(*test_hva), CONVERSIONS_GUEST_SHARED_VAL);
	handle_page_state_change(vcpu, true, conversions_gpa);

	vcpu_run(vcpu);

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.type, KVM_SYSTEM_EVENT_SEV_TERM);
	TEST_ASSERT_EQ(vcpu->run->system_event.ndata, 1);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[0], GHCB_MSR_TERM_REQ);
}


int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_SEV));

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SNP_VM));

	test_conversion(snp_default_policy());

	return 0;
}
