/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 The FreeBSD Foundation
 *
 * This software was developed under sponsorship from the FreeBSD Foundation.
 *
 * PCI enumeration path for the Intel INT3400 Dynamic Power Performance
 * Management (DPTF) device on Pantherlake (vendor 0x8086, device 0xB01D).
 *
 * Unlike the ACPI path (acpi_int3400.c), which drives the power slide through
 * the Pantherlake power slides _DSM, this device exposes the power slide as a
 * direct memory-mapped register in its PCI BAR.  The slide level is read and
 * written with bus_read_4()/bus_write_4() — no ACPI namespace access is used.
 */

#include "opt_pci.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/sysctl.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

/*
 * Power slider, a 64-bit memory-mapped register in BAR 0.  Layout (matching
 * Linux processor_thermal_soc_slider.c):
 *
 *   bits [2:0]  slider value (0 = highest performance .. 6 = highest
 *               efficiency; 3 = balanced; 7 reserved)
 *   bits [6:4]  offset field (forced to 0 for the minimum/maximum values,
 *               otherwise the configurable slider offset)
 *   bit  [7]    enable bit (must be set for the slider to take effect)
 */
#define PTL_PWR_SLIDE_BAR		PCIR_BAR(0)
#define SOC_POWER_SLIDER_OFFSET		0x5B38

#define SLIDER_MASK			0x07ull		/* bits [2:0] */
#define SLIDER_OFFSET_MASK		0x70ull		/* bits [6:4] */
#define SLIDER_OFFSET_SHIFT		4
#define SLIDER_ENABLE_BIT		(1ull << 7)

#define SOC_SLIDER_VALUE_MINIMUM	0x00		/* highest performance */
#define SOC_SLIDER_VALUE_BALANCE	0x03
#define SOC_SLIDER_VALUE_MAXIMUM	0x06		/* highest efficiency */

static const struct pci_device_table pci_int3400_devices[] = {
	{ PCI_DEV(0x8086, 0xb01d),
	  PCI_DESCR("Pantherlake Dynamic Power Performance Management") },
};

struct pci_int3400_softc {
	device_t	 dev;
	int		 bar_rid;
	struct resource	*bar;

	/* Offset field (bits [6:4]) applied to non-min/max slider values. */
	u_int		 slider_offset;
};

/*
 * Program the power slider register: set the slider value and enable bit,
 * and apply the offset field (zeroed for the minimum/maximum values, as
 * Linux does).  Read-modify-write to preserve unrelated bits.
 */
static void
set_soc_power_profile(struct pci_int3400_softc *sc, int slider)
{
	uint64_t val;
	u_int offset;

	if (slider == SOC_SLIDER_VALUE_MINIMUM ||
	    slider == SOC_SLIDER_VALUE_MAXIMUM)
		offset = 0;
	else
		offset = sc->slider_offset;

	val = bus_read_8(sc->bar, SOC_POWER_SLIDER_OFFSET);
	val &= ~SLIDER_MASK;
	val |= (slider & SLIDER_MASK) | SLIDER_ENABLE_BIT;
	val &= ~SLIDER_OFFSET_MASK;
	val |= ((uint64_t)offset << SLIDER_OFFSET_SHIFT) & SLIDER_OFFSET_MASK;
	bus_write_8(sc->bar, SOC_POWER_SLIDER_OFFSET, val);
}

static int
sysctl_pwr_slide(SYSCTL_HANDLER_ARGS)
{
	struct pci_int3400_softc *sc = arg1;
	int error, level;

	level = bus_read_8(sc->bar, SOC_POWER_SLIDER_OFFSET) & SLIDER_MASK;

	error = sysctl_handle_int(oidp, &level, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (level < SOC_SLIDER_VALUE_MINIMUM || level > SOC_SLIDER_VALUE_MAXIMUM)
		return (EINVAL);

	set_soc_power_profile(sc, level);
	return (0);
}

static int
sysctl_slider_offset(SYSCTL_HANDLER_ARGS)
{
	struct pci_int3400_softc *sc = arg1;
	int error;
	u_int offset;

	offset = sc->slider_offset;
	error = sysctl_handle_int(oidp, &offset, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (offset > (SLIDER_OFFSET_MASK >> SLIDER_OFFSET_SHIFT))
		return (EINVAL);

	sc->slider_offset = offset;
	/* Re-apply with the current slider value so the offset takes effect. */
	set_soc_power_profile(sc,
	    bus_read_8(sc->bar, SOC_POWER_SLIDER_OFFSET) & SLIDER_MASK);
	return (0);
}

static int
pci_int3400_probe(device_t dev)
{
	const struct pci_device_table *tbl;

	tbl = PCI_MATCH(dev, pci_int3400_devices);
	if (tbl == NULL)
		return (ENXIO);

	device_set_desc(dev, tbl->descr);
	return (BUS_PROBE_DEFAULT);
}

static int
pci_int3400_attach(device_t dev)
{
	struct pci_int3400_softc *sc = device_get_softc(dev);
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;

	sc->dev = dev;

	sc->bar_rid = PTL_PWR_SLIDE_BAR;
	sc->bar = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &sc->bar_rid,
	    RF_ACTIVE | RF_SHAREABLE);
	if (sc->bar == NULL) {
		device_printf(dev, "Could not allocate BAR\n");
		return (ENXIO);
	}

	/* Initialize the slider to the balanced profile, like Linux does. */
	set_soc_power_profile(sc, SOC_SLIDER_VALUE_BALANCE);

	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "power_slide",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    sysctl_pwr_slide, "I",
	    "Power slide level: 0=highest performance, 3=balanced, "
	    "6=highest efficiency (7 reserved)");
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "slider_offset",
	    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    sysctl_slider_offset, "IU",
	    "Slider offset (bits [6:4]) applied to non-min/max slide levels");

	return (0);
}

static int
pci_int3400_detach(device_t dev)
{
	struct pci_int3400_softc *sc = device_get_softc(dev);

	if (sc->bar != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->bar_rid, sc->bar);
	return (0);
}

static device_method_t pci_int3400_methods[] = {
	DEVMETHOD(device_probe,		pci_int3400_probe),
	DEVMETHOD(device_attach,	pci_int3400_attach),
	DEVMETHOD(device_detach,	pci_int3400_detach),
	DEVMETHOD_END
};

static driver_t pci_int3400_driver = {
	"pci_int3400",
	pci_int3400_methods,
	sizeof(struct pci_int3400_softc),
};

DRIVER_MODULE(pci_int3400, pci, pci_int3400_driver, NULL, NULL);
MODULE_DEPEND(pci_int3400, pci, 1, 1, 1);
MODULE_VERSION(pci_int3400, 1);
PCI_PNP_INFO(pci_int3400_devices);
