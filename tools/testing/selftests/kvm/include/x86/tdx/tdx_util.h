/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_TDX_TDX_UTIL_H
#define SELFTESTS_TDX_TDX_UTIL_H

#include <stdbool.h>

#include "kvm_util.h"

static inline bool is_tdx_vm(struct kvm_vm *vm)
{
	return vm->type == KVM_X86_TDX_VM;
}

/*
 * TDX ioctls
 * Use underscores to avoid collisions with struct member names.
 */
#define __tdx_vm_ioctl(vm, cmd, _flags, arg)				\
({									\
	int r;								\
									\
	union {								\
		struct kvm_tdx_cmd c;					\
		unsigned long raw;					\
	} tdx_cmd = { .c = {						\
		.id = (cmd),						\
		.flags = (u32)(_flags),				\
		.data = (u64)(arg),				\
	} };								\
									\
	r = __vm_ioctl(vm, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd.raw);	\
	r ?: tdx_cmd.c.hw_error;					\
})

#define tdx_vm_ioctl(vm, cmd, flags, arg)				\
({									\
	int ret = __tdx_vm_ioctl(vm, cmd, flags, arg);			\
									\
	__TEST_ASSERT_VM_VCPU_IOCTL(!ret, #cmd,	ret, vm);		\
})

#define __tdx_vcpu_ioctl(vcpu, cmd, _flags, arg)			\
({									\
	int r;								\
									\
	union {								\
		struct kvm_tdx_cmd c;					\
		unsigned long raw;					\
	} tdx_cmd = { .c = {						\
		.id = (cmd),						\
		.flags = (u32)(_flags),				\
		.data = (u64)(arg),				\
	} };								\
									\
	r = __vcpu_ioctl(vcpu, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd.raw);	\
	r ?: tdx_cmd.c.hw_error;					\
})

#define tdx_vcpu_ioctl(vcpu, cmd, flags, arg)				\
({									\
	int ret = __tdx_vcpu_ioctl(vcpu, cmd, flags, arg);		\
									\
	__TEST_ASSERT_VM_VCPU_IOCTL(!ret, #cmd,	ret, (vcpu)->vm);	\
})

void tdx_init_vm(struct kvm_vm *vm, u64 attributes);
void tdx_vm_setup_boot_code_region(struct kvm_vm *vm);
void tdx_vm_setup_boot_parameters_region(struct kvm_vm *vm, u32 nr_runnable_vcpus);
void tdx_vm_load_common_boot_parameters(struct kvm_vm *vm);

#endif /* SELFTESTS_TDX_TDX_UTIL_H */
