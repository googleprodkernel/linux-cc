// SPDX-License-Identifier: GPL-2.0-only
/*
 * Helpers used for SEV guests
 *
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <stdint.h>
#include <stdbool.h>

#include "kvm_util.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "processor.h"
#include "sev.h"

#define CPUID_MEM_ENC_LEAF 0x8000001f
#define CPUID_EBX_CBIT_MASK 0x3f

#define SEV_FW_REQ_VER_MAJOR 0
#define SEV_FW_REQ_VER_MINOR 17

enum sev_guest_state {
	SEV_GSTATE_UNINIT = 0,
	SEV_GSTATE_LUPDATE,
	SEV_GSTATE_LSECRET,
	SEV_GSTATE_RUNNING,
};

static void sev_ioctl(int cmd, void *data)
{
	int ret;
	struct sev_issue_cmd arg;

	arg.cmd = cmd;
	arg.data = (unsigned long)data;
	ret = ioctl(open_sev_dev_path_or_exit(), SEV_ISSUE_CMD, &arg);
	TEST_ASSERT(ret == 0, "SEV ioctl %d failed, error: %d, fw_error: %d",
		    cmd, ret, arg.error);
}

static void kvm_sev_ioctl(struct kvm_vm *vm, int cmd, void *data)
{
	struct kvm_sev_cmd arg = {0};
	int ret;

	arg.id = cmd;
	arg.sev_fd = open_sev_dev_path_or_exit();
	arg.data = (__u64)data;

	ret = ioctl(vm->fd, KVM_MEMORY_ENCRYPT_OP, &arg);
	TEST_ASSERT(
		ret == 0,
		"SEV KVM ioctl %d failed, rc: %i errno: %i (%s), fw_error: %d",
		cmd, ret, errno, strerror(errno), arg.error);
}

static void sev_register_user_region(struct kvm_vm *vm, struct userspace_mem_region *region)
{
	struct kvm_enc_region range = {0};
	int ret;

	range.addr = (__u64)region->region.userspace_addr;
	;
	range.size = region->region.memory_size;

	ret = ioctl(vm->fd, KVM_MEMORY_ENCRYPT_REG_REGION, &range);
	TEST_ASSERT(ret == 0, "failed to register user range, errno: %i\n",
		    errno);
}

static void sev_launch_update_data(struct kvm_vm *vm, vm_paddr_t gpa, uint64_t size)
{
	struct kvm_sev_launch_update_data ksev_update_data = {0};

	pr_debug("%s: addr: 0x%lx, size: %lu\n", __func__, gpa, size);

	ksev_update_data.uaddr = (__u64)addr_gpa2hva(vm, gpa);
	ksev_update_data.len = size;

	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_UPDATE_DATA, &ksev_update_data);
}

static void encrypt_region(struct kvm_vm *vm, struct userspace_mem_region *region)
{
	const struct sparsebit *protected_phy_pages =
		region->protected_phy_pages;
	const uint64_t memory_size = region->region.memory_size;
	const vm_paddr_t gpa_start = region->region.guest_phys_addr;
	sparsebit_idx_t pg = 0;

	sev_register_user_region(vm, region);

	while (pg < (memory_size / vm->page_size)) {
		sparsebit_idx_t nr_pages;

		if (sparsebit_is_clear(protected_phy_pages, pg)) {
			pg = sparsebit_next_set(protected_phy_pages, pg);
			if (!pg)
				break;
		}

		nr_pages = sparsebit_next_clear(protected_phy_pages, pg) - pg;
		if (nr_pages <= 0)
			nr_pages = 1;

		sev_launch_update_data(vm, gpa_start + pg * vm->page_size,
				       nr_pages * vm->page_size);
		pg += nr_pages;
	}
}

static void sev_encrypt(struct kvm_vm *vm)
{
	int ctr;
	struct userspace_mem_region *region;

	hash_for_each(vm->regions.slot_hash, ctr, region, slot_node) {
		encrypt_region(vm, region);
	}

	vm->arch.is_pt_protected = true;
}

bool is_kvm_sev_supported(void)
{
	struct sev_user_data_status sev_status;

	sev_ioctl(SEV_PLATFORM_STATUS, &sev_status);

	if (!(sev_status.api_major > SEV_FW_REQ_VER_MAJOR ||
	      (sev_status.api_major == SEV_FW_REQ_VER_MAJOR &&
	       sev_status.api_minor >= SEV_FW_REQ_VER_MINOR))) {
		pr_info("SEV FW version too old. Have API %d.%d (build: %d), need %d.%d, skipping test.\n",
			sev_status.api_major, sev_status.api_minor,
			sev_status.build, SEV_FW_REQ_VER_MAJOR,
			SEV_FW_REQ_VER_MINOR);
		return false;
	}

	return true;
}

static void sev_vm_launch(struct kvm_vm *vm, uint32_t policy)
{
	struct kvm_sev_launch_start ksev_launch_start = {0};
	struct kvm_sev_guest_status ksev_status;

	ksev_launch_start.policy = policy;
	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_START, &ksev_launch_start);
	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.policy == policy, "Incorrect guest policy.");
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_LUPDATE,
		    "Unexpected guest state: %d", ksev_status.state);

	ucall_init(vm, 0);

	sev_encrypt(vm);
}

static void sev_vm_launch_measure(struct kvm_vm *vm, uint8_t *measurement)
{
	struct kvm_sev_launch_measure ksev_launch_measure;
	struct kvm_sev_guest_status ksev_guest_status;

	ksev_launch_measure.len = 256;
	ksev_launch_measure.uaddr = (__u64)measurement;
	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_MEASURE, &ksev_launch_measure);

	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &ksev_guest_status);
	TEST_ASSERT(ksev_guest_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", ksev_guest_status.state);
}

static void sev_vm_launch_finish(struct kvm_vm *vm)
{
	struct kvm_sev_guest_status ksev_status;

	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_LUPDATE ||
			    ksev_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", ksev_status.state);

	kvm_sev_ioctl(vm, KVM_SEV_LAUNCH_FINISH, NULL);

	kvm_sev_ioctl(vm, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_RUNNING,
		    "Unexpected guest state: %d", ksev_status.state);
}

static void configure_sev_pte_masks(struct kvm_vm *vm)
{
	uint32_t eax, ebx, ecx, edx, enc_bit;

	cpuid(CPUID_MEM_ENC_LEAF, &eax, &ebx, &ecx, &edx);
	enc_bit = ebx & CPUID_EBX_CBIT_MASK;

	vm->arch.c_bit = 1 << enc_bit;
	vm->arch.pte_me_mask = vm->arch.c_bit | vm->arch.s_bit;
	vm->protected = true;
}

static void sev_vm_measure(struct kvm_vm *vm)
{
	uint8_t measurement[512];
	int i;

	sev_vm_launch_measure(vm, measurement);

	/* TODO: Validate the measurement is as expected. */
	pr_debug("guest measurement: ");
	for (i = 0; i < 32; ++i)
		pr_debug("%02x", measurement[i]);
	pr_debug("\n");
}

struct kvm_vm *vm_sev_create_with_one_vcpu(uint32_t policy, void *guest_code,
					   struct kvm_vcpu **cpu)
{
	enum vm_guest_mode mode = VM_MODE_PXXV48_4K;
	uint64_t nr_pages = vm_nr_pages_required(mode, 1, 0);
	struct kvm_vm *vm;

	vm = ____vm_create(mode, nr_pages, KVM_VM_TYPE_DEFAULT);

	kvm_sev_ioctl(vm, KVM_SEV_INIT, NULL);

	configure_sev_pte_masks(vm);

	*cpu = vm_vcpu_add(vm, 0, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name);

	sev_vm_launch(vm, policy);

	sev_vm_measure(vm);

	sev_vm_launch_finish(vm);

	pr_info("SEV guest created, policy: 0x%x, size: %lu KB\n", policy,
		nr_pages * vm->page_size / 1024);

	return vm;
}
