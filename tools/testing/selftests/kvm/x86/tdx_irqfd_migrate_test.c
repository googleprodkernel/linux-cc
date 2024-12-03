// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <stdio.h>
#include <linux/kvm.h>
#include <string.h>
#include <sys/eventfd.h>

#include "apic.h"
#include "kvm_util.h"
#include "processor.h"
#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include "test_util.h"
#include "ucall_common.h"

#define TEST_IRQ_PIN 24

#define NUM_INTERRUPTS 256
#define INTERRUPT_COUNT_GPA 0x100000000ULL
#define INTERRUPT_COUNT_MEMSLOT 5

#define MIGRATION_LOOPS 10

static uint32_t (*interrupt_count_per_vector)[NUM_INTERRUPTS];

static void interrupt_handler_increment_count(struct ex_regs *regs)
{
	(*interrupt_count_per_vector)[regs->vector]++;
	x2apic_write_reg(APIC_EOI, 0);
}

static void guest_code(void)
{
	uint32_t sync_count = 0;

	tdx_guest_x2apic_enable();

	/* Enable interrupts which are disabled by default. */
	asm volatile("sti");

	/* Keep guest runnable by continuously looping. */
	while (true)
		GUEST_SYNC(++sync_count);
}

/**
 * gsi_route_add - Used to add a GSI route.
 *
 * @msi_redir_hint: Look up "Message Address Register Format" in Intel SDM
 * @dest_mode: Look up "Message Address Register Format" in Intel SDM
 *             Use false for DM=0 and true for DM=1
 * @trig_mode: Look up "Message Data Register Format" in Intel SDM
 *             Use false for edge sensitive and true for level sensitive
 * @delivery_mode: A 3 bit code: look up "Message Data Register Format"
 *
 * Add a route by building up the routing information in address_hi, address_lo
 * and data according to how it is used in struct kvm_lapic_irq. For full
 * details, look up how fields in struct kvm_lapic_irq are used.
 *
 * Return: None
 */
static void gsi_route_add(struct kvm_irq_routing *table, uint32_t gsi,
			  bool use_x2apic_format, uint32_t dest_id,
			  uint8_t vector, bool msi_redir_hint, bool dest_mode,
			  bool trig_mode, uint8_t delivery_mode)
{
	union {
		struct {
			u32 vector : 8, delivery_mode : 3,
			dest_mode_logical : 1, reserved : 2,
			active_low : 1, is_level : 1;
		};
		uint32_t as_uint32;
	} data = { 0 };
	union {
		struct {
			u32 reserved_0 : 2, dest_mode_logical : 1,
			    redirect_hint : 1, reserved_1 : 1,
			    virt_destid_8_14 : 7, destid_0_7 : 8,
			    base_address : 12;
		};
		uint32_t as_uint32;
	} address_lo = { 0 };
	union {
		struct {
			u32 reserved : 8, destid_8_31 : 24;
		};
		uint32_t as_uint32;
	} address_hi = { 0 };

	/* Fixed 0xfee (see Intel SDM "Message Address Register Format") */
	address_lo.base_address = 0xfee;

	address_lo.destid_0_7 = dest_id & 0xff;
	if (use_x2apic_format)
		address_hi.destid_8_31 = (dest_id & 0xffffff00) >> 8;

	data.vector = vector;
	address_lo.dest_mode_logical = dest_mode;
	data.is_level = trig_mode;
	data.delivery_mode = delivery_mode & 0b111;
	address_lo.redirect_hint = msi_redir_hint;

	kvm_gsi_routing_msi_add(table, gsi, address_lo.as_uint32,
				address_hi.as_uint32, data.as_uint32);
}

/**
 * Sets up KVM irqfd in @vm
 *
 * @gsi: irqchip pin toggled by this event
 */
static void set_irqfd(struct kvm_vm *vm, int fd, uint32_t gsi, bool assign)
{
	struct kvm_irqfd ifd = {
		.fd = fd,
		.gsi = gsi,
		.flags = assign ? 0 : KVM_IRQFD_FLAG_DEASSIGN,
		.resamplefd = 0,
	};

	vm_ioctl(vm, KVM_IRQFD, &ifd);
}

static void setup_interrupt_count_per_vector(struct kvm_vm *vm)
{
	vm_vaddr_t gva;
	int npages;

	npages = round_up(sizeof(*interrupt_count_per_vector), PAGE_SIZE);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    INTERRUPT_COUNT_GPA,
				    INTERRUPT_COUNT_MEMSLOT, npages, 0);
	vm->memslots[MEM_REGION_TDX_SHARED_DATA] = INTERRUPT_COUNT_MEMSLOT;

	gva = vm_vaddr_alloc_shared(vm, sizeof(*interrupt_count_per_vector),
				    KVM_UTIL_MIN_VADDR,
				    MEM_REGION_TDX_SHARED_DATA);

	interrupt_count_per_vector = addr_gva2hva(vm, gva);
	memset(interrupt_count_per_vector, 0,
	       sizeof(*interrupt_count_per_vector));

	write_guest_global(vm, interrupt_count_per_vector,
			   (uint32_t(*)[NUM_INTERRUPTS])gva);
}

static void handle_vcpu_exit(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	default:
		TEST_FAIL("Unexpected exit: %s",
			  exit_reason_str(vcpu->run->exit_reason));
	}
}

void map_gsis_to_vectors(struct kvm_vm *vm, struct kvm_vcpu *vcpu, int *eventfds)
{
	struct kvm_irq_routing *table;
	uint32_t vector_and_gsi;
	int efd;

	/* Flush table first. */
	table = kvm_gsi_routing_create();
	kvm_gsi_routing_write(vm, table);

	/* Writing frees table, so we have to create another one. */
	table = kvm_gsi_routing_create();

	/* Map vectors to gsis 1 to 1 */
	for (vector_and_gsi = 32; vector_and_gsi < NUM_INTERRUPTS;
	     ++vector_and_gsi) {
		gsi_route_add(table, vector_and_gsi,
			      /*use_x2apic_format=*/true,
			      /*dest_id=*/vcpu->id,
			      /*vector=*/vector_and_gsi,
			      /*msi_redir_hint=*/false,
			      /*dest_mode=*/false,
			      /*trig_mode=*/false,
			      /*delivery_mode=*/0b000);

		efd = eventfd(0, EFD_NONBLOCK);
		set_irqfd(vm, efd, vector_and_gsi, true);

		eventfds[vector_and_gsi] = efd;
	}

	/* Configure KVM. Writing frees table. */
	kvm_gsi_routing_write(vm, table);

}

int main(int argc, char *argv[])
{
	int eventfds[NUM_INTERRUPTS] = { 0 };
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int vector, migration;

	TEST_REQUIRE(kvm_check_cap(KVM_CAP_SPLIT_IRQCHIP));

	setbuf(stdout, NULL);

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	vcpu = td_vcpu_add(vm, 0, guest_code);

	for (vector = 0; vector < NUM_INTERRUPTS; ++vector) {
		vm_install_exception_handler(vm, vector,
					     interrupt_handler_increment_count);
	}

	setup_interrupt_count_per_vector(vm);

	td_finalize(vm);

	map_gsis_to_vectors(vm, vcpu, eventfds);

	tdx_run(vcpu);
	handle_vcpu_exit(vcpu);

	for (migration = 0; migration < MIGRATION_LOOPS; ++migration) {
		struct kvm_vcpu *next_vcpu;
		struct kvm_vm *next_vm;

		next_vm = td_create();
		tdx_enable_capabilities(next_vm);
		next_vcpu = vm_vcpu_recreate(next_vm, 0);

		/* Inject on source VM. */
		for (vector = 32; vector < NUM_INTERRUPTS; ++vector)
			TEST_ASSERT_EQ(eventfd_write(eventfds[vector], 1), 0);

		map_gsis_to_vectors(next_vm, next_vcpu, eventfds);

		vcpu = next_vcpu;

		tdx_migrate_from(next_vm, vm);
		kvm_vm_free(vm);
		vm = next_vm;

		tdx_run(vcpu);
		handle_vcpu_exit(vcpu);

		for (vector = 32; vector < NUM_INTERRUPTS; ++vector)
			TEST_ASSERT_EQ((*interrupt_count_per_vector)[vector],
				       migration + 1);
	}

	kvm_vm_free(vm);
	for (vector = 32; vector < NUM_INTERRUPTS; ++vector)
		close(eventfds[vector]);
	return 0;
}
