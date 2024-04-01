// SPDX-License-Identifier: GPL-2.0-only

#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include <processor.h>
#include <sys/wait.h>

#define NR_MIGRATE_TEST_VMS 10
#define TDX_IOEXIT_TEST_PORT 0x50

static int __tdx_migrate_from(int dst_fd, int src_fd)
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_VM_MOVE_ENC_CONTEXT_FROM,
		.args = { src_fd }
	};

	return ioctl(dst_fd, KVM_ENABLE_CAP, &cap);
}


static void tdx_migrate_from(struct kvm_vm *dst_vm, struct kvm_vm *src_vm)
{
	int ret;

	vm_migrate_mem_regions(dst_vm, src_vm);
	ret = __tdx_migrate_from(dst_vm->fd, src_vm->fd);
	TEST_ASSERT(!ret, "Migration failed, ret: %d, errno: %d\n", ret, errno);
	src_vm->enc_migrated = true;
}

void guest_code(void)
{
	int ret;
	uint64_t data;

	data = 1;
	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1,
					   PORT_WRITE,
					   &data);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	data++;
	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1,
					   PORT_WRITE,
					   &data);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	tdx_test_success();
}

static void test_tdx_migrate_vm_with_private_memory(void)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vm;
	struct kvm_vcpu *dst_vcpu;
	uint32_t data;

	printf("Verifying migration of VM with private memory:\n");

	src_vm = td_create();
	td_initialize(src_vm, VM_MEM_SRC_ANONYMOUS, 0);
	td_vcpu_add(src_vm, 0, guest_code);
	td_finalize(src_vm);

	dst_vm = td_create();
	tdx_enable_capabilities(dst_vm);
	dst_vcpu = vm_vcpu_recreate(dst_vm, 0);

	tdx_migrate_from(dst_vm, src_vm);

	kvm_vm_free(src_vm);

	tdx_run(dst_vcpu);
	tdx_test_assert_io(dst_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			   PORT_WRITE);
	data = *(uint8_t *)((void *)dst_vcpu->run +
			    dst_vcpu->run->io.data_offset);
	TEST_ASSERT_EQ(data, 1);

	tdx_run(dst_vcpu);
	tdx_test_assert_io(dst_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			   PORT_WRITE);
	data = *(uint8_t *)((void *)dst_vcpu->run +
			    dst_vcpu->run->io.data_offset);
	TEST_ASSERT_EQ(data, 2);

	tdx_run(dst_vcpu);
	tdx_test_assert_success(dst_vcpu);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

static void test_tdx_migrate_running_vm(void)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vm;
	struct kvm_vcpu *src_vcpu;
	struct kvm_vcpu *dst_vcpu;
	uint32_t data;

	printf("Verifying migration of a running VM:\n");

	src_vm = td_create();
	td_initialize(src_vm, VM_MEM_SRC_ANONYMOUS, 0);
	src_vcpu = td_vcpu_add(src_vm, 0, guest_code);
	td_finalize(src_vm);

	dst_vm = td_create();
	tdx_enable_capabilities(dst_vm);
	dst_vcpu = vm_vcpu_recreate(dst_vm, 0);

	tdx_run(src_vcpu);
	tdx_test_assert_io(src_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			   PORT_WRITE);
	data = *(uint8_t *)((void *)src_vcpu->run +
			    src_vcpu->run->io.data_offset);
	TEST_ASSERT_EQ(data, 1);

	tdx_migrate_from(dst_vm, src_vm);

	kvm_vm_free(src_vm);

	tdx_run(dst_vcpu);
	tdx_test_assert_io(dst_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			   PORT_WRITE);
	data = *(uint8_t *)((void *)dst_vcpu->run +
			    dst_vcpu->run->io.data_offset);
	TEST_ASSERT_EQ(data, 2);

	tdx_run(dst_vcpu);
	tdx_test_assert_success(dst_vcpu);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

#define TDX_SHARED_MEM_TEST_PRIVATE_GVA (0x80000000)
#define TDX_SHARED_MEM_TEST_VADDR_SHARED_MASK BIT_ULL(30)
#define TDX_SHARED_MEM_TEST_SHARED_GVA     \
	(TDX_SHARED_MEM_TEST_PRIVATE_GVA | \
	 TDX_SHARED_MEM_TEST_VADDR_SHARED_MASK)

#define TDX_SHARED_MEM_TEST_PRIVATE_VALUE (100)
#define TDX_SHARED_MEM_TEST_SHARED_VALUE (200)
#define TDX_SHARED_MEM_TEST_DIFF_VALUE (1)


static uint64_t test_mem_private_gpa;
static uint64_t test_mem_shared_gpa;

void guest_with_shared_mem(void)
{
	uint64_t *test_mem_shared_gva =
		(uint64_t *)TDX_SHARED_MEM_TEST_SHARED_GVA;

	uint64_t *private_data, *shared_data;
	uint64_t placeholder;
	uint64_t failed_gpa;
	uint64_t data;
	int ret;

	/* Map gpa as shared */
	tdg_vp_vmcall_map_gpa(test_mem_shared_gpa, PAGE_SIZE,
			      &failed_gpa);

	shared_data = test_mem_shared_gva;
	private_data = &data;

	*private_data = TDX_SHARED_MEM_TEST_PRIVATE_VALUE;
	*shared_data = TDX_SHARED_MEM_TEST_SHARED_VALUE;

	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   PORT_WRITE,
					   private_data);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	/* Exit so host can read shared value */
	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   PORT_WRITE,
					   &placeholder);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	*private_data += TDX_SHARED_MEM_TEST_DIFF_VALUE;
	*shared_data += TDX_SHARED_MEM_TEST_DIFF_VALUE;

	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   PORT_WRITE,
					   private_data);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	/* Exit so host can read shared value */
	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   PORT_WRITE,
					   &placeholder);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	tdx_test_success();
}

static void test_tdx_migrate_vm_with_shared_mem(void)
{
	uint32_t private_data;
	vm_vaddr_t test_mem_private_gva;
	uint32_t *test_mem_hva;
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vm;
	struct kvm_vcpu *src_vcpu;
	struct kvm_vcpu *dst_vcpu;

	printf("Verifying migration of a VM with shared memory:\n");

	src_vm = td_create();
	td_initialize(src_vm, VM_MEM_SRC_ANONYMOUS, 0);
	src_vcpu = td_vcpu_add(src_vm, 0, guest_with_shared_mem);

	/*
	 * Set up shared memory page for testing by first allocating as private
	 * and then mapping the same GPA again as shared. This way, the TD does
	 * not have to remap its page tables at runtime.
	 */
	test_mem_private_gva = vm_vaddr_alloc(src_vm, src_vm->page_size,
					      TDX_SHARED_MEM_TEST_PRIVATE_GVA);
	TEST_ASSERT_EQ(test_mem_private_gva, TDX_SHARED_MEM_TEST_PRIVATE_GVA);

	test_mem_hva = addr_gva2hva(src_vm, test_mem_private_gva);
	TEST_ASSERT(test_mem_hva != NULL,
		    "Guest address not found in guest memory regions\n");

	test_mem_private_gpa = addr_gva2gpa(src_vm, test_mem_private_gva);
	virt_map_shared(src_vm, TDX_SHARED_MEM_TEST_SHARED_GVA,
			test_mem_private_gpa, 1);

	test_mem_shared_gpa = test_mem_private_gpa | src_vm->arch.s_bit;
	sync_global_to_guest(src_vm, test_mem_shared_gpa);

	td_finalize(src_vm);

	dst_vm = td_create();
	tdx_enable_capabilities(dst_vm);
	dst_vcpu = vm_vcpu_recreate(dst_vm, 0);

	vm_enable_cap(src_vm, KVM_CAP_EXIT_HYPERCALL,
		      BIT_ULL(KVM_HC_MAP_GPA_RANGE));

	printf("Verifying shared memory accesses for TDX\n");

	/* Begin guest execution; guest writes to shared memory. */
	printf("\t ... Starting guest execution\n");

	/* Handle map gpa as shared */
	tdx_run(src_vcpu);

	tdx_run(src_vcpu);
	tdx_test_assert_io(src_vcpu, TDX_IOEXIT_TEST_PORT, 4, PORT_WRITE);
	TEST_ASSERT_EQ(*(uint32_t *)((void *)src_vcpu->run +
				     src_vcpu->run->io.data_offset),
		       TDX_SHARED_MEM_TEST_PRIVATE_VALUE);

	tdx_run(src_vcpu);
	tdx_test_assert_io(src_vcpu, TDX_IOEXIT_TEST_PORT, 4, PORT_WRITE);
	TEST_ASSERT_EQ(*test_mem_hva, TDX_SHARED_MEM_TEST_SHARED_VALUE);

	tdx_migrate_from(dst_vm, src_vm);

	kvm_vm_free(src_vm);

	tdx_run(dst_vcpu);
	tdx_test_assert_io(dst_vcpu, TDX_IOEXIT_TEST_PORT, 4,
			   PORT_WRITE);
	private_data = *(uint32_t *)((void *)dst_vcpu->run +
				     dst_vcpu->run->io.data_offset);
	TEST_ASSERT_EQ(private_data, TDX_SHARED_MEM_TEST_PRIVATE_VALUE +
		       TDX_SHARED_MEM_TEST_DIFF_VALUE);

	tdx_run(dst_vcpu);
	tdx_test_assert_io(dst_vcpu, TDX_IOEXIT_TEST_PORT, 4,
			   PORT_WRITE);
	TEST_ASSERT_EQ(*test_mem_hva, TDX_SHARED_MEM_TEST_SHARED_VALUE +
		       TDX_SHARED_MEM_TEST_DIFF_VALUE);

	tdx_run(dst_vcpu);
	tdx_test_assert_success(dst_vcpu);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

void guest_code_empty(void)
{
	tdx_test_success();
}

static void test_tdx_migrate_multiple_vms(void)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vms[NR_MIGRATE_TEST_VMS];
	int i, ret;

	printf("Verifying migration between multiple VMs:\n");

	src_vm = td_create();
	td_initialize(src_vm, VM_MEM_SRC_ANONYMOUS, 0);
	td_vcpu_add(src_vm, 0, guest_code_empty);
	td_finalize(src_vm);

	for (i = 0; i < NR_MIGRATE_TEST_VMS; ++i) {
		dst_vms[i] = td_create();
		tdx_enable_capabilities(dst_vms[i]);
		vm_vcpu_recreate(dst_vms[i], 0);
	}

	/* Initial migration from the src to the first dst. */
	tdx_migrate_from(dst_vms[0], src_vm);

	for (i = 1; i < NR_MIGRATE_TEST_VMS; i++)
		tdx_migrate_from(dst_vms[i], dst_vms[i - 1]);

	/* Migrate the guest back to the original VM. */
	ret = __tdx_migrate_from(src_vm->fd,
				 dst_vms[NR_MIGRATE_TEST_VMS - 1]->fd);
	TEST_ASSERT(ret == -1 && errno == EIO,
		    "VM that was migrated from should be dead. ret %d, errno: %d\n",
		    ret, errno);

	kvm_vm_free(src_vm);
	for (i = 0; i < NR_MIGRATE_TEST_VMS; ++i)
		kvm_vm_free(dst_vms[i]);

	printf("\t ... PASSED\n");
}

int main(int argc, char *argv[])
{
	if (!is_tdx_enabled()) {
		print_skip("TDX is not supported by the KVM");
		exit(KSFT_SKIP);
	}

	run_in_new_process(&test_tdx_migrate_vm_with_private_memory);
	run_in_new_process(&test_tdx_migrate_running_vm);
	run_in_new_process(&test_tdx_migrate_vm_with_shared_mem);
	run_in_new_process(&test_tdx_migrate_multiple_vms);

	return 0;
}
