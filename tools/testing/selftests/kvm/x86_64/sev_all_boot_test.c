// SPDX-License-Identifier: GPL-2.0-only
/*
 * Basic SEV boot tests.
 *
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"

#define NR_SYNCS 1

#define MSR_AMD64_SEV_BIT  1

static void guest_run_loop(struct kvm_vcpu *vcpu)
{
	struct ucall uc;
	int i;

	for (i = 0; i <= NR_SYNCS; ++i) {
		vcpu_run(vcpu);
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			continue;
		case UCALL_DONE:
			return;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_FAIL("Unexpected exit: %s",
				  exit_reason_str(vcpu->run->exit_reason));
		}
	}
}

static void is_sev_enabled(void)
{
	uint64_t sev_status;

	GUEST_ASSERT(this_cpu_has(X86_FEATURE_SEV));

	sev_status = rdmsr(MSR_AMD64_SEV);
	GUEST_ASSERT(sev_status & 0x1);
}

static void guest_sev_code(void)
{
	GUEST_SYNC(1);

	is_sev_enabled();

	GUEST_DONE();
}

static void test_sev(void *guest_code, uint64_t policy)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = vm_sev_create_with_one_vcpu(policy, guest_code, &vcpu);
	TEST_ASSERT(vm, "vm_sev_create_with_one_vcpu() failed to create VM\n");

	guest_run_loop(vcpu);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(is_kvm_sev_supported());

	test_sev(guest_sev_code, SEV_POLICY_NO_DBG);
	test_sev(guest_sev_code, 0);

	return 0;
}
