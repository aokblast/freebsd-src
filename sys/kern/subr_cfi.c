#include <sys/cdefs.h>

#include <sys/systm.h>
#include <sys/proc.h>

#include <stdbool.h>

#include <machine/cpu.h>
#include <machine/cfi.h>


static void
report_cfi(struct trapframe *frame, unsigned long func, uint32_t type) {
	void *addr = TRAPF_PC(frame);

	vfprintf(stderr, "CFI chcek failed on ip %lu for callee %lu and type %u", addr, func, type);
}

static bool
cfi_handler(struct trapframe *frame) {
	unsigned long func;
	uint32_t type;
	if (decode_cfi(frame, &func, &type)) {
		report_cfi(frame, func, type);
		return (true);
	}

	return (false);
}
