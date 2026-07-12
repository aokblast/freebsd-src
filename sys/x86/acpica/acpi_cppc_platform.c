/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ShengYi Hung <aokblast@FreeBSD.org>
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/rman.h>

#include <machine/acpica_machdep.h>
#include <x86/x86_var.h>
#include <machine/bus.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>
#include <dev/acpica/acpi_cppc_lib.h>


uint64_t
acpi_ffh_read(device_t dev, struct acpi_cppc_ffh *ffh)
{
	uint64_t val = 0;

	/*
	 * The MSR index comes from firmware (_CPC/_PCT), so use the _SAFE
	 * variant: a bogus register must not panic the machine.  On a fault
	 * the value is left at 0.
	 */
	(void)x86_msr_op(ffh->address,
	    MSR_OP_RENDEZVOUS_ONE | MSR_OP_READ | MSR_OP_SAFE |
		MSR_OP_CPUID(cpu_get_pcpu(dev)->pc_cpuid),
	    0, &val);
	return (val);
}

void
acpi_ffh_write(device_t dev, struct acpi_cppc_ffh *ffh, uint64_t val)
{
	(void)x86_msr_op(ffh->address,
	    MSR_OP_RENDEZVOUS_ONE | MSR_OP_WRITE | MSR_OP_SAFE |
		MSR_OP_CPUID(cpu_get_pcpu(dev)->pc_cpuid),
	    val, NULL);
}
