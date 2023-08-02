// SPDX-License-Identifier: GPL-2.0
#include "kvm_util_base.h"
#include "test_util.h"
#include "ucall_common.h"
#include <linux/kvm.h>
#include <linux/sizes.h>

#define MIGRATE_PRIVATE_MEM_TEST_SLOT 10
#define MIGRATE_PRIVATE_MEM_GPA ((uint64_t)(1ull << 32))
#define MIGRATE_PRIVATE_MEM_GVA MIGRATE_PRIVATE_MEM_GPA
#define MIGRATE_PRIVATE_MEM_VALUE 0xdeadbeef

static void migrate_private_mem_data_guest_code_src(void)
{
	uint64_t volatile *const ptr = (uint64_t *)MIGRATE_PRIVATE_MEM_GVA;

	*ptr = MIGRATE_PRIVATE_MEM_VALUE;

	GUEST_SYNC1(*ptr);
}

static void migrate_private_mem_guest_code_dst(void)
{
	uint64_t volatile *const ptr = (uint64_t *)MIGRATE_PRIVATE_MEM_GVA;

	GUEST_SYNC1(*ptr);
}

static void test_migrate_private_mem_data(bool migrate)
{
	struct kvm_vm *src_vm, *dst_vm;
	struct kvm_vcpu *src_vcpu, *dst_vcpu;
	int src_memfd, dst_memfd;
	struct ucall uc;

	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_SW_PROTECTED_VM,
	};

	/* Build the source VM, use it to write to private memory */
	src_vm = __vm_create_shape_with_one_vcpu(
		shape, &src_vcpu, 0, migrate_private_mem_data_guest_code_src);
	src_memfd = vm_create_guest_memfd(src_vm, SZ_4K, 0);

	vm_mem_add(src_vm, DEFAULT_VM_MEM_SRC, MIGRATE_PRIVATE_MEM_GPA,
		   MIGRATE_PRIVATE_MEM_TEST_SLOT, 1, KVM_MEM_PRIVATE,
		   src_memfd, 0);

	virt_map(src_vm, MIGRATE_PRIVATE_MEM_GVA, MIGRATE_PRIVATE_MEM_GPA, 1);
	vm_set_memory_attributes(src_vm, MIGRATE_PRIVATE_MEM_GPA, SZ_4K,
				 KVM_MEMORY_ATTRIBUTE_PRIVATE);

	vcpu_run(src_vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(src_vcpu, KVM_EXIT_IO);
	get_ucall(src_vcpu, &uc);
	TEST_ASSERT(uc.args[0] == MIGRATE_PRIVATE_MEM_VALUE,
		    "Source VM should be able to write to private memory");

	/* Build the destination VM with linked fd */
	dst_vm = __vm_create_shape_with_one_vcpu(
		shape, &dst_vcpu, 0, migrate_private_mem_guest_code_dst);
	dst_memfd = vm_link_guest_memfd(dst_vm, src_memfd, 0);

	vm_mem_add(dst_vm, DEFAULT_VM_MEM_SRC, MIGRATE_PRIVATE_MEM_GPA,
		   MIGRATE_PRIVATE_MEM_TEST_SLOT, 1, KVM_MEM_PRIVATE,
		   dst_memfd, 0);

	virt_map(dst_vm, MIGRATE_PRIVATE_MEM_GVA, MIGRATE_PRIVATE_MEM_GPA, 1);
	if (migrate)
		vm_migrate_from(dst_vm, src_vm);
	else
		vm_set_memory_attributes(dst_vm, MIGRATE_PRIVATE_MEM_GPA, SZ_4K,
					 KVM_MEMORY_ATTRIBUTE_PRIVATE);

	vcpu_run(dst_vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(dst_vcpu, KVM_EXIT_IO);
	get_ucall(dst_vcpu, &uc);
	TEST_ASSERT(uc.args[0] == MIGRATE_PRIVATE_MEM_VALUE,
		    "Destination VM should be able to read value transferred");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM));

	test_migrate_private_mem_data(false);

	if (kvm_check_cap(KVM_CAP_VM_MOVE_ENC_CONTEXT_FROM))
		test_migrate_private_mem_data(true);

	return 0;
}
