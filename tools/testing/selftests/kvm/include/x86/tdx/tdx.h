/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTESTS_TDX_TDX_H
#define SELFTESTS_TDX_TDX_H

#include <linux/types.h>

enum mmio_size {
	MMIO_SIZE_1B = 1,
	MMIO_SIZE_2B = 2,
	MMIO_SIZE_4B = 4,
	MMIO_SIZE_8B = 8
};

u64 tdx_mmio_write(u64 address, enum mmio_size size, u64 data_in);

#endif // SELFTESTS_TDX_TDX_H
