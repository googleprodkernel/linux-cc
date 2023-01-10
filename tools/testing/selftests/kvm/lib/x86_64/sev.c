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


/*
 * Iterate over set ranges within sparsebit @s. In each iteration,
 * @range_begin and @range_end will take the beginning and end of the set
 * range, which are of type sparsebit_idx_t.
 *
 * For example, if the range [3, 7] (inclusive) is set, within the
 * iteration,@range_begin will take the value 3 and @range_end will take
 * the value 7.
 *
 * Ensure that there is at least one bit set before using this macro with
 * sparsebit_any_set(), because sparsebit_first_set() will abort if none
 * are set.
 */
#define sparsebit_for_each_set_range(s, range_begin, range_end)         \
	for (range_begin = sparsebit_first_set(s),                      \
	     range_end =                                        \
	     sparsebit_next_clear(s, range_begin) - 1;          \
	     range_begin && range_end;                                  \
	     range_begin = sparsebit_next_set(s, range_end),            \
	     range_end =                                        \
	     sparsebit_next_clear(s, range_begin) - 1)

/*
 * sparsebit_next_clear() can return 0 if [x, 2**64-1] are all set, and the
 * -1 would then cause an underflow back to 2**64 - 1. This is expected and
 * correct.
 *
 * If the last range in the sparsebit is [x, y] and we try to iterate,
 * sparsebit_next_set() will return 0, and sparsebit_next_clear() will try
 * and find the first range, but that's correct because the condition
 * expression would cause us to quit the loop.
 */
static void encrypt_region(struct kvm_vm *vm, struct userspace_mem_region *region)
{
	const struct sparsebit *protected_phy_pages =
		region->protected_phy_pages;
	const vm_paddr_t gpa_base = region->region.guest_phys_addr;
	const sparsebit_idx_t lowest_page_in_region = gpa_base >> vm->page_shift;

	sparsebit_idx_t i;
	sparsebit_idx_t j;

	if (!sparsebit_any_set(protected_phy_pages))
		return;

	sev_register_user_region(vm, region);

	sparsebit_for_each_set_range(protected_phy_pages, i, j) {
		const uint64_t size_to_load = (j - i + 1) * vm->page_size;
		const uint64_t offset = (i - lowest_page_in_region) * vm->page_size;
		const uint64_t gpa = gpa_base + offset;

		sev_launch_update_data(vm, gpa, size_to_load);
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

void sev_vm_init(struct kvm_vm *vm)
{
	kvm_sev_ioctl(vm, KVM_SEV_INIT, NULL);
}

struct kvm_vm *vm_sev_create_with_one_vcpu(uint32_t policy, void *guest_code,
					   struct kvm_vcpu **cpu)
{
	enum vm_guest_mode mode = VM_MODE_PXXV48_4K_SEV;
	struct kvm_vm *vm;
	struct kvm_vcpu *cpus[1];

	vm = __vm_create_with_vcpus(VM_SHAPE(mode), 1, 0, guest_code, cpus);
	*cpu = cpus[0];

	sev_vm_launch(vm, policy);

	sev_vm_measure(vm);

	sev_vm_launch_finish(vm);

	pr_info("SEV guest created, policy: 0x%x\n", policy);

	return vm;
}
