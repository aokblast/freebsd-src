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

struct acpi_cppc_ctx *acpi_cppc_ctx_init(device_t dev);
void acpi_cppc_ctx_free(device_t dev, struct acpi_cppc_ctx *ctx);
bool acpi_cppc_optional_object_valid(ACPI_OBJECT *pkg, int idx);
uint64_t acpi_cppc_read_reg(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg);
void acpi_cppc_write_reg(struct acpi_cppc_ctx *ctx, enum acpi_cppc_regs reg,
    uint64_t val);
uint32_t acpi_cppc_get_features(struct acpi_cppc_ctx *ctx);
