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
#include <sys/malloc.h>
#include <sys/rman.h>

#include <machine/acpica_machdep.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>

#include "acpi_cppc_lib.h"

#define	BITS_VALUE(bits, val)						\
	(((val) & (bits)) >> (ffsll((bits)) - 1))
#define	BITS_WITH_VALUE(bits, val)					\
	(((uintmax_t)(val) << (ffsll((bits)) - 1)) & (bits))
#define	SET_BITS_VALUE(var, bits, val)					\
	((var) = ((var) & ~(bits)) | BITS_WITH_VALUE((bits), (val)))

struct acpi_cppc_reg {
	uint64_t mask;
	union {
		struct acpi_cppc_ffh ffh;
		struct resource *res;
	};
	int type;
};

struct acpi_cppc_item {
	int type;
	bool rdonly;
	union {
		struct acpi_cppc_reg reg;
		uint64_t int_value;
	};
};

struct acpi_cppc_ctx {
	device_t dev;
	uint32_t features;
	struct acpi_cppc_item hightest_perf;
	struct acpi_cppc_item nominal_perf;
	struct acpi_cppc_item nolinear_perf;
	struct acpi_cppc_item lowest_perf;
	struct acpi_cppc_item min_reg;
	struct acpi_cppc_item max_reg;
	struct acpi_cppc_item desired_reg;
	struct acpi_cppc_item epp_reg;
	struct acpi_cppc_item enable_reg;
	struct acpi_cppc_item autonomous_reg;
	struct acpi_cppc_item lowest_freq;
	struct acpi_cppc_item nominal_freq;
};

static uint64_t
acpi_cppc_read_gas(device_t dev, struct acpi_cppc_item *item)
{
	uint64_t val;

	switch (item->reg.type) {
#ifdef ACPI_CPPC_FFH
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		val = acpi_ffh_read(dev, &item->reg.ffh);
		break;
#endif
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:
	case ACPI_ADR_SPACE_SYSTEM_IO:
		val = bus_read_8(item->reg.res, 0);
		break;
	default:
		val = 0;
		KASSERT(0, ("Impossible to read other type in CPPC"));
	}
	return (val);
}

static uint64_t
acpi_cppc_read_item(device_t dev, struct acpi_cppc_item *item)
{
	uint64_t val;

	if (item->type == ACPI_TYPE_INTEGER)
		return (item->int_value);
	else if (item->type == ACPI_TYPE_BUFFER) {
		val = acpi_cppc_read_gas(dev, item);
		val = BITS_VALUE(item->reg.mask, val);
		return (val);
	}
	KASSERT(0, ("Impossible to read other type in CPPC"));

	return (0);
}

static void
acpi_cppc_write_item(device_t dev, struct acpi_cppc_item *item, uint64_t val)
{
	uint64_t cur;

	if (!item->rdonly && item->type == ACPI_TYPE_BUFFER) {
		cur = acpi_cppc_read_gas(dev, item);
		SET_BITS_VALUE(cur, item->reg.mask, val);
		switch (item->reg.type) {
#ifdef ACPI_CPPC_FFH
		case ACPI_ADR_SPACE_FIXED_HARDWARE:
			return (acpi_ffh_write(dev, &item->reg.ffh, cur));
#endif
		case ACPI_ADR_SPACE_SYSTEM_MEMORY:
		case ACPI_ADR_SPACE_SYSTEM_IO:
			return (bus_write_8(item->reg.res, 0, cur));
		}
	}
	KASSERT(0, ("Impossible to write other type in CPPC"));
}

static void
acpi_cppc_free_item(device_t dev, struct acpi_cppc_item *item, int rid)
{
	if (item->type == ACPI_TYPE_BUFFER) {
		if (item->reg.type == ACPI_ADR_SPACE_SYSTEM_MEMORY) {
			bus_release_resource(dev, SYS_RES_MEMORY, rid,
			    item->reg.res);
			bus_delete_resource(dev, SYS_RES_MEMORY, rid);
		}
		if (item->reg.type == ACPI_ADR_SPACE_SYSTEM_IO) {
			bus_release_resource(dev, SYS_RES_IOPORT, rid,
			    item->reg.res);
			bus_delete_resource(dev, SYS_RES_IOPORT, rid);
		}
	}
}

static int
acpi_cppc_alloc_gas(device_t dev, ACPI_OBJECT *obj, int rid,
    struct acpi_cppc_reg *reg)
{
	ACPI_GENERIC_ADDRESS *gas;
	int error, type;

	if (obj->Buffer.Length < sizeof(ACPI_GENERIC_ADDRESS) + 3)
		return (EINVAL);
	gas = (ACPI_GENERIC_ADDRESS *)(obj->Buffer.Pointer + 3);
	reg->type = gas->SpaceId;
	/* A BitWidth of 64 would make the shift below undefined. */
	reg->mask = gas->BitWidth >= 64 ? ~0ULL : (1ULL << gas->BitWidth) - 1;
	reg->mask <<= gas->BitOffset;

	if (reg->type == ACPI_ADR_SPACE_FIXED_HARDWARE) {
		reg->ffh.address = gas->Address;
		reg->ffh.access_width = gas->AccessWidth;
	} else {
		error = acpi_bus_alloc_gas(dev, &type, rid, gas, &reg->res,
		    RF_SHAREABLE);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
acpi_cppc_parse_item(device_t dev, ACPI_OBJECT *obj,
    struct acpi_cppc_item *item, int rid, bool rdonly)
{
	item->type = obj->Type;
	item->rdonly = rdonly;
	if (obj->Type == ACPI_TYPE_INTEGER) {
		item->int_value = obj->Integer.Value;
		return (0);
	} else if (obj->Type == ACPI_TYPE_BUFFER) {
		return (acpi_cppc_alloc_gas(dev, obj, rid, &item->reg));
	}
	return (ENXIO);
}

bool
acpi_cppc_optional_object_valid(ACPI_OBJECT *pkg, int idx)
{
	ACPI_OBJECT *obj;
	int i;

	if (!ACPI_PKG_VALID(pkg, idx))
		return (false);
	obj = &pkg->Package.Elements[idx];
	if (!obj)
		return (false);
	if (obj->Type == ACPI_TYPE_INTEGER) {
		return (obj->Integer.Value != 0);
	} else if (obj->Type == ACPI_TYPE_BUFFER) {
		if (obj->Buffer.Length < sizeof(ACPI_GENERIC_ADDRESS) + 3)
			return (false);
		for (i = 0; i < sizeof(ACPI_GENERIC_ADDRESS); ++i)
			if (obj->Buffer.Pointer[3 + i] != 0)
				return (true);
	}

	return (false);
}

void
acpi_cppc_ctx_free(device_t dev, struct acpi_cppc_ctx *ctx)
{
	acpi_cppc_free_item(dev, &ctx->nominal_freq, 12);
	acpi_cppc_free_item(dev, &ctx->lowest_freq, 11);
	acpi_cppc_free_item(dev, &ctx->epp_reg, 10);
	acpi_cppc_free_item(dev, &ctx->autonomous_reg, 9);
	acpi_cppc_free_item(dev, &ctx->enable_reg, 8);
	acpi_cppc_free_item(dev, &ctx->max_reg, 7);
	acpi_cppc_free_item(dev, &ctx->min_reg, 6);
	acpi_cppc_free_item(dev, &ctx->desired_reg, 5);
	acpi_cppc_free_item(dev, &ctx->lowest_perf, 4);
	acpi_cppc_free_item(dev, &ctx->nolinear_perf, 3);
	acpi_cppc_free_item(dev, &ctx->nominal_perf, 2);
	acpi_cppc_free_item(dev, &ctx->hightest_perf, 1);
	free(ctx, M_DEVBUF);
}

struct acpi_cppc_ctx *
acpi_cppc_ctx_init(device_t dev)
{
	ACPI_HANDLE handle;
	ACPI_BUFFER buf;
	ACPI_OBJECT *pkg;
	struct acpi_cppc_ctx *ctx;
	int error = 0;

	handle = acpi_get_handle(dev);
	buf.Pointer = NULL;
	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle, "_CPC", NULL, &buf,
		ACPI_TYPE_PACKAGE)))
		return (NULL);
	pkg = buf.Pointer;
	ctx = malloc(sizeof(struct acpi_cppc_ctx), M_DEVBUF, M_WAITOK | M_ZERO);

	KASSERT(acpi_cppc_optional_object_valid(pkg, 2),
	    ("Highest Performance is mandatory in CPPC"));
	error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[2],
	    &ctx->hightest_perf, 1, true);
	if (error != 0)
		goto end;
	KASSERT(acpi_cppc_optional_object_valid(pkg, 3),
	    ("Nominal Performance is mandatory in CPPC"));
	error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[3],
	    &ctx->nominal_perf, 2, true);
	if (error != 0)
		goto end;
	KASSERT(acpi_cppc_optional_object_valid(pkg, 4),
	    ("Lowest Nonlinear Performance is mandatory in CPPC"));
	error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[4],
	    &ctx->nolinear_perf, 3, true);
	if (error != 0)
		goto end;
	KASSERT(acpi_cppc_optional_object_valid(pkg, 5),
	    ("Lowest Performance is mandatory in CPPC"));
	error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[5],
	    &ctx->lowest_perf, 4, true);
	if (error != 0)
		goto end;
	if (acpi_cppc_optional_object_valid(pkg, 7)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[7],
		    &ctx->desired_reg, 5, false);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_DESIRED;
	}
	if (acpi_cppc_optional_object_valid(pkg, 8)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[8],
		    &ctx->min_reg, 6, false);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_MIN;
	}
	if (acpi_cppc_optional_object_valid(pkg, 9)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[9],
		    &ctx->max_reg, 7, false);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_MAX;
	}
	if (acpi_cppc_optional_object_valid(pkg, 16)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[16],
		    &ctx->enable_reg, 8, false);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_ENABLE;
	}
	if (acpi_cppc_optional_object_valid(pkg, 17)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[17],
		    &ctx->autonomous_reg, 9, false);
		if (error != 0)
			goto end;
		/*
		 * Integer 1 means CPPC exclusively support autonomous mode
		 */
		if (ctx->autonomous_reg.type == ACPI_TYPE_INTEGER &&
		    acpi_cppc_read_item(dev, &ctx->autonomous_reg) == 1)
			ctx->features &= ~(ACPI_CPPC_HAS_DESIRED);
		ctx->features |= ACPI_CPPC_HAS_AUTONOMOUS;
	}
	if (acpi_cppc_optional_object_valid(pkg, 19)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[19],
		    &ctx->epp_reg, 10, false);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_EPP;
	}
	if (acpi_cppc_optional_object_valid(pkg, 21)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[21],
		    &ctx->lowest_freq, 11, true);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_LOW_FREQ;
	}
	if (acpi_cppc_optional_object_valid(pkg, 22)) {
		error = acpi_cppc_parse_item(dev, &pkg->Package.Elements[22],
		    &ctx->nominal_freq, 12, true);
		if (error != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_NOMINAL_FREQ;
	}
	ctx->dev = dev;
end:
	if (error != 0) {
		acpi_cppc_ctx_free(dev, ctx);
		ctx = NULL;
	}

	AcpiOsFree(buf.Pointer);
	return (ctx);
}

static struct acpi_cppc_item *
acpi_cppc_map_regs(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg)
{
	struct acpi_cppc_item *item;

	switch (reg) {
	case ACPI_CPPC_HIGHTEST_PERF:
		item = &ctx->hightest_perf;
		break;
	case ACPI_CPPC_NOMINAL_PERF:
		item = &ctx->nominal_perf;
		break;
	case ACPI_CPPC_NOLINEAR_PERF:
		item = &ctx->nolinear_perf;
		break;
	case ACPI_CPPC_LOWEST_PERF:
		item = &ctx->lowest_perf;
		break;
	case ACPI_CPPC_MIN_REG:
		item = &ctx->min_reg;
		break;
	case ACPI_CPPC_MAX_REG:
		item = &ctx->max_reg;
		break;
	case ACPI_CPPC_EPP_REG:
		item = &ctx->epp_reg;
		break;
	case ACPI_CPPC_ENABLE_REG:
		item = &ctx->enable_reg;
		break;
	case ACPI_CPPC_AUTONOMOUS_REG:
		item = &ctx->autonomous_reg;
		break;
	case ACPI_CPPC_LOWEST_FREQ:
		item = &ctx->lowest_freq;
		break;
	case ACPI_CPPC_NOMINAL_FREQ:
		item = &ctx->nominal_freq;
		break;
	case ACPI_CPPC_DESIRED_REG:
		item = &ctx->desired_reg;
		break;
	default:
		KASSERT(0, ("Unsupported register"));
	}
	return (item);
}

uint64_t
acpi_cppc_read_reg(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg)
{
	return (acpi_cppc_read_item(ctx->dev, acpi_cppc_map_regs(ctx, reg)));
}

void
acpi_cppc_write_reg(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg,
    uint64_t val)
{
	return (
	    acpi_cppc_write_item(ctx->dev, acpi_cppc_map_regs(ctx, reg), val));
}

uint32_t
acpi_cppc_get_features(struct acpi_cppc_ctx *ctx)
{
	return (ctx->features);
}
