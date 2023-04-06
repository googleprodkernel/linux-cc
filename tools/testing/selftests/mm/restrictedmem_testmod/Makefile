# SPDX-License-Identifier: GPL-2.0-only

RESTRICTEDMEM_TESTMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(RESTRICTEDMEM_TESTMOD_DIR)/../../../../..)

ifeq ($(V),1)
Q =
else
Q = @
endif

MODULES = restrictedmem_testmod.ko

obj-m += restrictedmem_testmod.o
CFLAGS_restrictedmem_testmod.o = -I$(src)

all:
	+$(Q)make -C $(KDIR) M=$(RESTRICTEDMEM_TESTMOD_DIR) modules

clean:
	+$(Q)make -C $(KDIR) M=$(RESTRICTEDMEM_TESTMOD_DIR) clean
