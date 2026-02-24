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
#include <sys/bus.h>

#include <contrib/dev/acpica/include/acpi.h>

struct acpi_cppc_ctx;

enum acpi_cppc_regs {
	ACPI_CPPC_HIGHTEST_PERF,
	ACPI_CPPC_NOMINAL_PERF,
	ACPI_CPPC_NOLINEAR_PERF,
	ACPI_CPPC_LOWEST_PERF,
	ACPI_CPPC_MIN_REG,
	ACPI_CPPC_MAX_REG,
	ACPI_CPPC_DESIRED_REG,
	ACPI_CPPC_EPP_REG,
	ACPI_CPPC_ENABLE_REG,
	ACPI_CPPC_AUTONOMOUS_REG,
	ACPI_CPPC_LOWEST_FREQ,
	ACPI_CPPC_NOMINAL_FREQ,
};

enum acpi_cppc_feature {
	ACPI_CPPC_HAS_LOW_FREQ = (1 << 0),
	ACPI_CPPC_HAS_NOMINAL_FREQ = (1 << 1),
	ACPI_CPPC_HAS_MIN = (1 << 2),
	ACPI_CPPC_HAS_MAX = (1 << 3),
	ACPI_CPPC_HAS_EPP = (1 << 4),
	ACPI_CPPC_HAS_DESIRED = (1 << 5),
	ACPI_CPPC_HAS_ENABLE = (1 << 6),
	ACPI_CPPC_HAS_AUTONOMOUS = (1 << 7),
};

struct acpi_cppc_ffh {
	uint64_t address;
	uint8_t access_width;
};

struct acpi_cppc_ctx *acpi_cppc_ctx_init(device_t dev);
void acpi_cppc_ctx_free(device_t dev, struct acpi_cppc_ctx *ctx);
bool acpi_cppc_optional_object_valid(ACPI_OBJECT *pkg, int idx);
uint64_t acpi_cppc_read_reg(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg);
void acpi_cppc_write_reg(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg,
    uint64_t val);
uint32_t acpi_cppc_get_features(struct acpi_cppc_ctx *ctx);
