// SPDX-License-Identifier: GPL-2.0
/*
 * ucall support. A ucall is a "hypercall to userspace".
 *
 * Copyright (C) 2018, Red Hat, Inc.
 */
#include "kvm_util.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"

#define UCALL_PIO_PORT ((u16)0x1000)

/* HPET address is guaranteed to be unused for ucall MMIO */
#define UCALL_MMIO_GPA 0xfed00000

static u8 vm_type;
static gpa_t ucall_mmio_gpa;

void ucall_arch_init(struct kvm_vm *vm, gpa_t mmio_gpa)
{
	vm_type = vm->type;
	sync_global_to_guest(vm, vm_type);

	if (is_tdx_vm(vm)) {
		ucall_mmio_gpa = UCALL_MMIO_GPA | vm->arch.s_bit;
		sync_global_to_guest(vm, ucall_mmio_gpa);
	}
}

void ucall_arch_do_ucall(gva_t uc)
{
	if (vm_type == KVM_X86_TDX_VM) {
		tdx_mmio_write(ucall_mmio_gpa, sizeof(gva_t), uc);
		return;
	}

	asm volatile("in %[port], %%al"
		: : [port] "d" (UCALL_PIO_PORT), "D" (uc) : "rax", "memory");
}

void *ucall_arch_get_ucall(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	if (vm_type == KVM_X86_TDX_VM) {
		if (run->exit_reason == KVM_EXIT_MMIO &&
		    run->mmio.phys_addr == UCALL_MMIO_GPA &&
		    run->mmio.len == sizeof(gva_t) &&
		    run->mmio.is_write)
			return (void *)(*((gva_t *)run->mmio.data));
		return NULL;
	}

	if (run->exit_reason == KVM_EXIT_IO && run->io.port == UCALL_PIO_PORT) {
		struct kvm_regs regs;

		vcpu_regs_get(vcpu, &regs);
		return (void *)regs.rdi;
	}
	return NULL;
}
