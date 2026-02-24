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
	struct resource *res;
	int type;
};

struct acpi_cppc_item {
	int type;
	union {
		struct acpi_cppc_reg reg;
		uint64_t int_value;
	};
};

struct acpi_cppc_rdonly_item {
	int type;
	uint64_t value;
};

struct acpi_cppc_ctx {
	device_t dev;
	uint32_t features;
	struct acpi_cppc_rdonly_item hightest_perf;
	struct acpi_cppc_rdonly_item nominal_perf;
	struct acpi_cppc_rdonly_item nolinear_perf;
	struct acpi_cppc_rdonly_item lowest_perf;
	struct acpi_cppc_item min_reg;
	struct acpi_cppc_item max_reg;
	struct acpi_cppc_item desired_reg;
	struct acpi_cppc_item epp_reg;
	struct acpi_cppc_item enable_reg;
	struct acpi_cppc_item autonomous_reg;
	struct acpi_cppc_rdonly_item lowest_freq;
	struct acpi_cppc_rdonly_item nominal_freq;
};

static uint64_t
acpi_cppc_read_gas(device_t dev, struct acpi_cppc_item *item)
{
	uint64_t val;

	switch (item->reg.type) {
#ifdef SYS_RES_FFH
	case SYS_RES_FFH:
		val = acpi_ffh_read(dev, item->reg.res);
		break;
#endif
	case SYS_RES_IOPORT:
	case SYS_RES_MEMORY:
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
		val = BITS_VALUE(val, item->reg.mask);
		return (val);
	}
	KASSERT(0, ("Impossible to read other type in CPPC"));

	return (0);
}

static void
acpi_cppc_write_item(device_t dev, struct acpi_cppc_item *item, uint64_t val)
{
	uint64_t cur;

	if (item->type == ACPI_TYPE_BUFFER) {
		cur = acpi_cppc_read_gas(dev, item);
		SET_BITS_VALUE(cur, item->reg.mask, val);
		switch (item->reg.type) {
#ifdef SYS_RES_FFH
		case SYS_RES_FFH:
			return (acpi_ffh_write(dev, item->reg.res, cur));
#endif
		case SYS_RES_IOPORT:
		case SYS_RES_MEMORY:
			return (bus_write_8(item->reg.res, 0, cur));
		}
	}
	KASSERT(0, ("Impossible to write other type in CPPC"));
}

static void
acpi_cppc_free_item(device_t dev, struct acpi_cppc_item *item, int rid)
{
	if (item->type == ACPI_TYPE_BUFFER) {
		bus_release_resource(dev, item->reg.type, rid, item->reg.res);
		bus_delete_resource(dev, item->reg.type, rid);
	}
}

static int
acpi_cppc_alloc_gas(device_t dev, ACPI_OBJECT *obj, int rid,
    struct acpi_cppc_reg *reg)
{
	ACPI_GENERIC_ADDRESS *gas;

	if (obj->Buffer.Length < sizeof(ACPI_GENERIC_ADDRESS) + 3)
		return (EINVAL);
	gas = (ACPI_GENERIC_ADDRESS *)(obj->Buffer.Pointer + 3);
	reg->type = gas->SpaceId;
	reg->mask = (1ULL << gas->BitWidth) - 1;
	reg->mask <<= gas->BitOffset;
	return (acpi_bus_alloc_gas(dev, &reg->type, rid, gas, &reg->res,
	    RF_SHAREABLE));
}

static int
acpi_cppc_parse_item(device_t dev, ACPI_OBJECT *obj,
    struct acpi_cppc_item *item, int rid)
{
	item->type = obj->Type;
	if (obj->Type == ACPI_TYPE_INTEGER) {
		item->int_value = obj->Integer.Value;
		return (0);
	} else if (obj->Type == ACPI_TYPE_BUFFER) {
		return (acpi_cppc_alloc_gas(dev, obj, rid, &item->reg));
	}
	return (ENXIO);
}

static int
acpi_cppc_parse_rdonly_item(device_t dev, ACPI_OBJECT *obj,
    struct acpi_cppc_rdonly_item *item, int rid)
{
	struct acpi_cppc_item acpi_item;
	int err;

	item->type = ACPI_TYPE_INTEGER;
	if (obj->Type == ACPI_TYPE_INTEGER) {
		item->value = obj->Integer.Value;
		return (0);
	} else if (obj->Type == ACPI_TYPE_BUFFER) {
		err = acpi_cppc_parse_item(dev, obj, &acpi_item, rid);
		if (err)
			return (err);
		item->value = acpi_cppc_read_item(dev, &acpi_item);
		acpi_cppc_free_item(dev, &acpi_item, rid);
		return (0);
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
	acpi_cppc_free_item(dev, &ctx->epp_reg, 10);
	acpi_cppc_free_item(dev, &ctx->autonomous_reg, 9);
	acpi_cppc_free_item(dev, &ctx->enable_reg, 8);
	acpi_cppc_free_item(dev, &ctx->max_reg, 7);
	acpi_cppc_free_item(dev, &ctx->min_reg, 6);
	acpi_cppc_free_item(dev, &ctx->desired_reg, 5);
	free(ctx, M_DEVBUF);
}

struct acpi_cppc_ctx *
acpi_cppc_ctx_init(device_t dev)
{
	ACPI_HANDLE handle;
	ACPI_BUFFER buf;
	ACPI_OBJECT *pkg;
	struct acpi_cppc_ctx *ctx;
	int err;

	handle = acpi_get_handle(dev);
	buf.Pointer = NULL;
	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(handle, "_CPC", NULL, &buf,
		ACPI_TYPE_PACKAGE)))
		return (NULL);
	pkg = buf.Pointer;
	ctx = malloc(sizeof(struct acpi_cppc_ctx), M_DEVBUF, M_WAITOK);

	KASSERT(acpi_cppc_optional_object_valid(pkg, 2),
	    ("Highest Performance is mandatory in CPPC"));
	if ((err = acpi_cppc_parse_rdonly_item(dev, &pkg->Package.Elements[2],
		 &ctx->hightest_perf, 1)) != 0)
		goto end;
	KASSERT(acpi_cppc_optional_object_valid(pkg, 3),
	    ("Nominal Performance is mandatory in CPPC"));
	if ((err = acpi_cppc_parse_rdonly_item(dev, &pkg->Package.Elements[3],
		 &ctx->nominal_perf, 2)) != 0)
		goto end;
	KASSERT(acpi_cppc_optional_object_valid(pkg, 4),
	    ("Lowest Nonlinear Performance is mandatory in CPPC"));
	if ((err = acpi_cppc_parse_rdonly_item(dev, &pkg->Package.Elements[4],
		 &ctx->nolinear_perf, 3)) != 0)
		goto end;
	KASSERT(acpi_cppc_optional_object_valid(pkg, 5),
	    ("Lowest Performance is mandatory in CPPC"));
	if ((err = acpi_cppc_parse_rdonly_item(dev, &pkg->Package.Elements[5],
		 &ctx->lowest_perf, 4)) != 0)
		goto end;
	if (acpi_cppc_optional_object_valid(pkg, 7)) {
		if ((err = acpi_cppc_parse_item(dev, &pkg->Package.Elements[7],
			 &ctx->desired_reg, 5)) != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_DESIRED;
	}
	if (acpi_cppc_optional_object_valid(pkg, 8)) {
		if ((err = acpi_cppc_parse_item(dev, &pkg->Package.Elements[8],
			 &ctx->min_reg, 6)) != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_MIN;
	}
	if (acpi_cppc_optional_object_valid(pkg, 9)) {
		if ((err = acpi_cppc_parse_item(dev, &pkg->Package.Elements[9],
			 &ctx->max_reg, 7)) != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_MAX;
	}
	if (acpi_cppc_optional_object_valid(pkg, 16)) {
		if ((err = acpi_cppc_parse_item(dev, &pkg->Package.Elements[16],
			 &ctx->enable_reg, 8)) != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_ENABLE;
	}
	if (acpi_cppc_optional_object_valid(pkg, 17)) {
		if ((err = acpi_cppc_parse_item(dev, &pkg->Package.Elements[17],
			 &ctx->autonomous_reg, 9)) != 0)
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
		if ((err = acpi_cppc_parse_item(dev, &pkg->Package.Elements[19],
			 &ctx->epp_reg, 10)) != 0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_EPP;
	}
	if (acpi_cppc_optional_object_valid(pkg, 21)) {
		if ((err = acpi_cppc_parse_rdonly_item(dev,
			 &pkg->Package.Elements[21], &ctx->lowest_freq, 11)) !=
		    0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_LOW_FREQ;
	}
	if (acpi_cppc_optional_object_valid(pkg, 22)) {
		if ((err = acpi_cppc_parse_rdonly_item(dev,
			 &pkg->Package.Elements[22], &ctx->nominal_freq, 12)) !=
		    0)
			goto end;
		ctx->features |= ACPI_CPPC_HAS_NOMINAL_FREQ;
	}
	ctx->dev = dev;
end:
	if (err)
		acpi_cppc_ctx_free(dev, ctx);

	AcpiOsFree(buf.Pointer);
	return (ctx);
}

static struct acpi_cppc_item *
acpi_cppc_map_regs(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg)
{
	struct acpi_cppc_item *item;

	switch (reg) {
	case ACPI_CPPC_HIGHTEST_PERF:
		item = (struct acpi_cppc_item *)&ctx->hightest_perf;
		break;
	case ACPI_CPPC_NOMINAL_PERF:
		item = (struct acpi_cppc_item *)&ctx->nominal_perf;
		break;
	case ACPI_CPPC_NOLINEAR_PERF:
		item = (struct acpi_cppc_item *)&ctx->nolinear_perf;
		break;
	case ACPI_CPPC_LOWEST_PERF:
		item = (struct acpi_cppc_item *)&ctx->lowest_perf;
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
		item = (struct acpi_cppc_item *)&ctx->lowest_freq;
		break;
	case ACPI_CPPC_NOMINAL_FREQ:
		item = (struct acpi_cppc_item *)&ctx->nominal_freq;
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
