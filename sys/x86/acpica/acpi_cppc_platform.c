#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/rman.h>

#include <machine/acpica_machdep.h>
#include <machine/bus.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>

uint64_t
acpi_ffh_read(device_t dev, struct resource *res)
{
	uint64_t val;

	x86_msr_op(res->r_bushandle,
	    MSR_OP_RENDEZVOUS_ONE | MSR_OP_READ |
		MSR_OP_CPUID(cpu_get_pcpu(dev)->pc_cpuid),
	    0, &val);
	return (val);
}

void
acpi_ffh_write(device_t dev, struct resource *res, uint64_t val)
{
	x86_msr_op(res->r_bushandle,
	    MSR_OP_RENDEZVOUS_ONE | MSR_OP_WRITE |
		MSR_OP_CPUID(cpu_get_pcpu(dev)->pc_cpuid),
	    val, NULL);
}
