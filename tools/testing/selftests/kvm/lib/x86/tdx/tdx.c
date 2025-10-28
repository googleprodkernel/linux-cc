// SPDX-License-Identifier: GPL-2.0-only

#include "tdx/tdx.h"

#define TDG_VP_VMCALL 0
#define TDG_VP_VMCALL_VE_REQUEST_MMIO    48
#define TDVMCALL_MMIO_WRITE		  1
#define TDVMCALL_EXPOSE_REGS_MASK    0xFC00

u64 tdx_mmio_write(u64 address, enum mmio_size size, u64 data_in)
{
	register u64 r10_reg asm("r10") = TDG_VP_VMCALL;
	register u64 r11_reg asm("r11") = TDG_VP_VMCALL_VE_REQUEST_MMIO;
	register u64 r12_reg asm("r12") = size;
	register u64 r13_reg asm("r13") = TDVMCALL_MMIO_WRITE;
	register u64 r14_reg asm("r14") = address;
	register u64 r15_reg asm("r15") = data_in;
	register u64 rax_reg asm("rax") = TDG_VP_VMCALL;
	register u64 rcx_reg asm("rcx") = TDVMCALL_EXPOSE_REGS_MASK;

	asm volatile(
	 ".byte 0x66,0x0f,0x01,0xcc" /* tdcall */
	 : "+r" (r10_reg), "+r" (r11_reg)
	 : "r" (r12_reg), "r" (r13_reg), "r" (r14_reg), "r" (r15_reg),
	   "r" (rax_reg), "r" (rcx_reg)
	 : "cc", "memory"
	);

	return r10_reg;
}
