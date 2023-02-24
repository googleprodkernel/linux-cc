// SPDX-License-Identifier: GPL-2.0-only

#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include <processor.h>
#include <sys/wait.h>

#define NR_MIGRATE_TEST_VMS 10
#define SHARED_GPA_BASE 0x80000000

static int __tdx_migrate_from(int dst_fd, int src_fd)
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_VM_COPY_ENC_CONTEXT_FROM,
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
}

#define TDX_IOEXIT_TEST_PORT 0x50

void guest_code(void)
{
	uint64_t data;

	data = 1;
	tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&data);

	data++;
	tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1,
					TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					&data);

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
	td_configure(dst_vm, VM_MEM_SRC_ANONYMOUS, 0);
	dst_vcpu = vm_vcpu_add_for_migration(dst_vm, 0);

	tdx_migrate_from(dst_vm, src_vm);

	kvm_vm_free(src_vm);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_IO(dst_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	data = *(uint8_t *)((void *)dst_vcpu->run + dst_vcpu->run->io.data_offset);
	ASSERT_EQ(data, 1);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_IO(dst_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	data = *(uint8_t *)((void *)dst_vcpu->run + dst_vcpu->run->io.data_offset);
	ASSERT_EQ(data, 2);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_SUCCESS(dst_vcpu);

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
	td_configure(dst_vm, VM_MEM_SRC_ANONYMOUS, 0);
	dst_vcpu = vm_vcpu_add_for_migration(dst_vm, 0);

	vcpu_run(src_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(src_vcpu);
	TDX_TEST_ASSERT_IO(src_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	data = *(uint8_t *)((void *)src_vcpu->run + src_vcpu->run->io.data_offset);
	ASSERT_EQ(data, 1);

	tdx_migrate_from(dst_vm, src_vm);

	kvm_vm_free(src_vm);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_IO(dst_vcpu, TDX_IOEXIT_TEST_PORT, 1,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	data = *(uint8_t *)((void *)dst_vcpu->run + dst_vcpu->run->io.data_offset);
	ASSERT_EQ(data, 2);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_SUCCESS(dst_vcpu);

	kvm_vm_free(dst_vm);

	printf("\t ... PASSED\n");
}

#define TDX_SHARED_MEM_TEST_PRIVATE_GVA (0x80000000)
#define TDX_SHARED_MEM_TEST_VADDR_SHARED_MASK BIT_ULL(30)
#define TDX_SHARED_MEM_TEST_SHARED_GVA     \
	(TDX_SHARED_MEM_TEST_PRIVATE_GVA | \
	 TDX_SHARED_MEM_TEST_VADDR_SHARED_MASK)

/*
 * Shared variables between guest and host
 */
static uint64_t test_mem_private_gpa;
static uint64_t test_mem_shared_gpa;

void guest_with_shared_mem(void)
{
	uint64_t *test_mem_shared_gva =
		(uint64_t *)TDX_SHARED_MEM_TEST_SHARED_GVA;

	uint64_t *private_data, *shared_data;
	uint64_t failed_gpa;
	uint64_t data;

	/* Map gpa as shared */
	tdg_vp_vmcall_map_gpa(test_mem_shared_gpa, PAGE_SIZE,
				    &failed_gpa);

	shared_data = test_mem_shared_gva;
	private_data = &data;

	*private_data = 1;
	*shared_data = 11;

	tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   private_data);

	tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   shared_data);

	(*private_data)++;
	(*shared_data)++;

	tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   private_data);

	tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 4,
					   TDG_VP_VMCALL_INSTRUCTION_IO_WRITE,
					   shared_data);

	tdx_test_success();
}

static void test_tdx_migrate_vm_with_shared_mem(void)
{
	uint32_t private_data, shared_data;
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
	ASSERT_EQ(test_mem_private_gva, TDX_SHARED_MEM_TEST_PRIVATE_GVA);

	test_mem_hva = addr_gva2hva(src_vm, test_mem_private_gva);
	TEST_ASSERT(test_mem_hva != NULL,
		    "Guest address not found in guest memory regions\n");

	test_mem_private_gpa = addr_gva2gpa(src_vm, test_mem_private_gva);
	virt_pg_map_shared(src_vm, TDX_SHARED_MEM_TEST_SHARED_GVA,
			   test_mem_private_gpa);

	test_mem_shared_gpa = test_mem_private_gpa | BIT_ULL(src_vm->pa_bits - 1);
	sync_global_to_guest(src_vm, test_mem_private_gpa);
	sync_global_to_guest(src_vm, test_mem_shared_gpa);

	td_finalize(src_vm);

	dst_vm = td_create();
	td_configure(dst_vm, VM_MEM_SRC_ANONYMOUS, 0);
	dst_vcpu = vm_vcpu_add_for_migration(dst_vm, 0);

	vcpu_run(src_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(src_vcpu);
	TDX_TEST_ASSERT_IO(src_vcpu, TDX_IOEXIT_TEST_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	private_data = *(uint32_t *)((void *)src_vcpu->run + src_vcpu->run->io.data_offset);
	ASSERT_EQ(private_data, 1);

	vcpu_run(src_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(src_vcpu);
	TDX_TEST_ASSERT_IO(src_vcpu, TDX_IOEXIT_TEST_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	shared_data = *(uint8_t *)((void *)src_vcpu->run + src_vcpu->run->io.data_offset);
	ASSERT_EQ(shared_data, 11);

	tdx_migrate_from(dst_vm, src_vm);

	kvm_vm_free(src_vm);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_IO(dst_vcpu, TDX_IOEXIT_TEST_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	private_data = *(uint32_t *)((void *)dst_vcpu->run + dst_vcpu->run->io.data_offset);
	ASSERT_EQ(private_data, 2);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_IO(dst_vcpu, TDX_IOEXIT_TEST_PORT, 4,
			TDG_VP_VMCALL_INSTRUCTION_IO_WRITE);
	shared_data = *(uint8_t *)((void *)dst_vcpu->run + dst_vcpu->run->io.data_offset);
	ASSERT_EQ(shared_data, 12);

	vcpu_run(dst_vcpu);
	TDX_TEST_CHECK_GUEST_FAILURE(dst_vcpu);
	TDX_TEST_ASSERT_SUCCESS(dst_vcpu);

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
		td_configure(dst_vms[i], VM_MEM_SRC_ANONYMOUS, 0);
		vm_vcpu_add_for_migration(dst_vms[i], 0);
	}

	/* Initial migration from the src to the first dst. */
	tdx_migrate_from(dst_vms[0], src_vm);

	for (i = 1; i < NR_MIGRATE_TEST_VMS; i++)
		tdx_migrate_from(dst_vms[i], dst_vms[i - 1]);

	/* Migrate the guest back to the original VM. */
	ret = __tdx_migrate_from(src_vm->fd, dst_vms[NR_MIGRATE_TEST_VMS - 1]->fd);
	TEST_ASSERT(ret == -1 && errno == EIO,
		    "VM that was migrated from should be dead. ret %d, errno: %d\n", ret,
		    errno);

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
