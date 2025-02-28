/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 ShengYi Hung
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/priv.h>
#include <sys/sysctl.h>

#include <machine/cpu.h>

#define CFI_DEBUG_MSG "CFI check failed on PC %p for callee %p and type %x\n"

FEATURE(kcfi, "Kernel control flow integrity");

static SYSCTL_NODE(_debug, OID_AUTO, kcfi, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "KCFI options");

static bool cfi_panic __read_mostly = false;
SYSCTL_BOOL(_debug_kcfi, OID_AUTO, panic_on_violation,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &cfi_panic, 0, "Panic on KCFI violation");

static bool cfi_disabled __read_mostly = false;
SYSCTL_BOOL(_debug_kcfi, OID_AUTO, disabled, CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &cfi_disabled, 0, "Disable KCFI message");

static void
report_cfi(uintptr_t caller_addr, uintptr_t callee_addr, uint32_t type)
{
	if (cfi_panic)
		panic(CFI_DEBUG_MSG, (void *)caller_addr, (void *)callee_addr,
		    type);
	else
		printf(CFI_DEBUG_MSG, (void *)caller_addr, (void *)callee_addr,
		    type);
}

static int
kcfi_lookup_module(linker_file_t lf, void *arg)
{
	uintptr_t *module = (uintptr_t *)arg;

	if (lf->address <= (caddr_t)*module &&
	    (lf->address + lf->size) >= (caddr_t)*module) {
		*module = (uintptr_t)lf;
		return (1);
	}

	return (0);
}

static inline uintptr_t
cfi_trap_addr(int32_t *addr)
{
	return ((uintptr_t)((int32_t)(intptr_t)addr + *addr));
}

static bool
is_cfi_exception(uintptr_t address)
{
	linker_file_t module;
	int32_t *trap, *traps_end;

	module = (linker_file_t)address;
	linker_file_foreach(kcfi_lookup_module, &module);

	if ((uintptr_t)module == address)
		return (false);

	trap = (int32_t *)(module->kcfi_traps_addr);
	traps_end = (int32_t *)(module->kcfi_traps_addr +
	    module->kcfi_traps_size);

	if (trap == NULL)
		return (false);

	for (; trap != traps_end; trap++)
		if (cfi_trap_addr(trap) == address)
			return (true);

	return (false);
}

bool
cfi_handler(struct trapframe *frame)
{
	uintptr_t callee_addr, caller_addr;
	uint32_t type;

	caller_addr = TRAPF_PC(frame);

	if (decode_cfi_frame(frame, &callee_addr, &type) &&
	    is_cfi_exception((uintptr_t)caller_addr)) {
		report_cfi(caller_addr, callee_addr, type);
		/* needs to be platform dependent */
		post_cfi(frame);
		return (true);
	}

	return (false);
}

