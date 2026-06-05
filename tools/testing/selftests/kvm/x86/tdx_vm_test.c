// SPDX-License-Identifier: GPL-2.0-only

#include "processor.h"
#include "kvm_util.h"
#include "tdx/tdx_util.h"
#include "ucall_common.h"
#include "kselftest_harness.h"

static void guest_code_lifecycle(void)
{
	GUEST_DONE();
}

TEST(verify_td_lifecycle)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;

	vm = vm_create_shape_with_one_vcpu(VM_SHAPE_TDX, &vcpu,
					   guest_code_lifecycle);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

	kvm_vm_free(vm);
}

static gva_t conversions_private_gva;
static gpa_t conversions_private_gpa;
static gva_t conversions_shared_gva;
static gpa_t conversions_shared_gpa;
static size_t conversions_size;

u64 tdx_map_gpa(u64 gpa, u64 size)
{
#define TDG_VP_VMCALL 0
#define TDG_VP_VMCALL_MAP_GPA 0x10001
#define TDVMCALL_EXPOSE_REGS_MASK 0xFC00
	register u64 r10_reg asm("r10") = TDG_VP_VMCALL;
	register u64 r11_reg asm("r11") = TDG_VP_VMCALL_MAP_GPA;
	register u64 r12_reg asm("r12") = gpa;
	register u64 r13_reg asm("r13") = size;
	register u64 rax_reg asm("rax") = TDG_VP_VMCALL;
	register u64 rcx_reg asm("rcx") = TDVMCALL_EXPOSE_REGS_MASK;

	asm volatile(
	 ".byte 0x66,0x0f,0x01,0xcc" /* tdcall */
	 : "+r" (r10_reg), "+r" (r11_reg)
	 : "r" (r12_reg), "r" (r13_reg), "r" (rax_reg), "r" (rcx_reg)
	 : "cc", "memory"
	);

	return r10_reg;
}

enum accept_page_level {
	PAGE_LEVEL_4K = 0,
	PAGE_LEVEL_2M,
};

u64 tdx_accept_page(u64 gpa, enum accept_page_level level)
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

static void handle_hypercall_map_gpa(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u64 attributes;
	size_t size;
	gpa_t gpa;

	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_HYPERCALL);
	TEST_ASSERT_EQ(run->hypercall.nr, KVM_HC_MAP_GPA_RANGE);
	TEST_ASSERT_EQ(run->hypercall.flags, KVM_EXIT_HYPERCALL_LONG_MODE);

	gpa = run->hypercall.args[0];
	size = run->hypercall.args[1] * PAGE_SIZE;
	attributes = 0;
	if (run->hypercall.args[2] & KVM_MAP_GPA_RANGE_ENCRYPTED)
		attributes = KVM_MEMORY_ATTRIBUTE_PRIVATE;

	vm_mem_set_memory_attributes(vcpu->vm, gpa, size, attributes);
}

#define CONVERSIONS_PRIVATE_VAL 'A'
#define CONVERSIONS_GUEST_SHARED_VAL 'B'
#define CONVERSIONS_HOST_SHARED_VAL 'C'
#define CONVERSIONS_STAGE_WROTE_SHARED 0x99

static void guest_code_conversions(void)
{
	char *addr;

	addr = (void *)conversions_private_gva;
	WRITE_ONCE(*addr, CONVERSIONS_PRIVATE_VAL);
	GUEST_ASSERT_EQ(READ_ONCE(*addr), CONVERSIONS_PRIVATE_VAL);

	GUEST_ASSERT_EQ(tdx_map_gpa(conversions_shared_gpa, conversions_size), 0);

	addr = (void *)conversions_shared_gva;
	WRITE_ONCE(*addr, CONVERSIONS_GUEST_SHARED_VAL);
	GUEST_ASSERT_EQ(READ_ONCE(*addr), CONVERSIONS_GUEST_SHARED_VAL);

	GUEST_SYNC(CONVERSIONS_STAGE_WROTE_SHARED);

	GUEST_ASSERT_EQ(READ_ONCE(*addr), CONVERSIONS_HOST_SHARED_VAL);

	GUEST_ASSERT_EQ(tdx_map_gpa(conversions_private_gpa, conversions_size), 0);
	GUEST_ASSERT_EQ(tdx_accept_page(conversions_private_gpa, PAGE_LEVEL_4K), 0);

	addr = (void *)conversions_private_gva;
	WRITE_ONCE(*addr, CONVERSIONS_PRIVATE_VAL);
	GUEST_ASSERT_EQ(READ_ONCE(*addr), CONVERSIONS_PRIVATE_VAL);

	GUEST_DONE();
}

TEST(verify_conversions)
{
	struct userspace_mem_region *region;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	char *test_hva;

	vm = __vm_create(VM_SHAPE_TDX, 1, 0);
	vcpu = vm_vcpu_add(vm, 0, guest_code_conversions);

	conversions_size = getpagesize();

	conversions_shared_gva = vm_alloc_shared(vm, conversions_size,
						 KVM_UTIL_MIN_VADDR,
						 MEM_REGION_TEST_DATA);

	/* Store in _private_ gpa since addr_gva2gpa always untags the gpa. */
	conversions_private_gpa = addr_gva2gpa(vm, conversions_shared_gva);

	/* Add tag back for shared gpa. */
	conversions_shared_gpa = conversions_private_gpa | vm->arch.s_bit;

	conversions_private_gva = vm_unused_gva_gap(vm, conversions_size,
						    KVM_UTIL_MIN_VADDR);

	/* virt_pg_map() will map based on protected_phy_pages. */
	region = vm_get_mem_region(vm, MEM_REGION_TEST_DATA);
	sparsebit_set(region->protected_phy_pages, conversions_private_gpa >> vm->page_shift);
	virt_pg_map(vm, conversions_private_gva, conversions_private_gpa);

	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, (1 << KVM_HC_MAP_GPA_RANGE));

	sync_global_to_guest(vm, conversions_size);
	sync_global_to_guest(vm, conversions_private_gva);
	sync_global_to_guest(vm, conversions_private_gpa);
	sync_global_to_guest(vm, conversions_shared_gva);
	sync_global_to_guest(vm, conversions_shared_gpa);

	test_hva = addr_gva2hva(vm, conversions_shared_gva);

	kvm_arch_vm_finalize_vcpus(vm);

	vcpu_run(vcpu);
	handle_hypercall_map_gpa(vcpu);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], CONVERSIONS_STAGE_WROTE_SHARED);

	TEST_ASSERT_EQ(READ_ONCE(*test_hva), CONVERSIONS_GUEST_SHARED_VAL);

	WRITE_ONCE(*test_hva, CONVERSIONS_HOST_SHARED_VAL);
	TEST_ASSERT_EQ(READ_ONCE(*test_hva), CONVERSIONS_HOST_SHARED_VAL);

	vcpu_run(vcpu);
	handle_hypercall_map_gpa(vcpu);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

	kvm_vm_free(vm);
}

int main(int argc, char **argv)
{
	TEST_REQUIRE(is_tdx_supported());
	return test_harness_run(argc, argv);
}
