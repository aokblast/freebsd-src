/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 The FreeBSD Foundation
 *
 * This software was developed under sponsorship from the FreeBSD Foundation.
 *
 * PCI enumeration path for the Intel INT3400 Dynamic Power Performance
 * Management (DPTF) device.
 *
 * On Pantherlake (PTL) and later platforms the DPTF controller is also
 * visible as a PCI device (vendor 0x8086, device 0xB01D).  All functional
 * logic is shared with the ACPI path in acpi_int3400.c; this file only
 * contains the PCI probe and attach wrappers.
 *
 * Double-attachment prevention: if the PCI device has an ACPI companion
 * that is already attached (i.e. the ACPI path won the race), this driver
 * returns ENXIO so the same hardware is not managed twice.
 */

#include "opt_acpi.h"
#include "opt_pci.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/acpica/acpi_int3400.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

static const struct pci_device_table pci_int3400_devices[] = {
	{ PCI_DEV(0x8086, 0xb01d),
	  PCI_DESCR("Pantherlake Dynamic Power Performance Management") },
};

static int
pci_int3400_probe(device_t dev)
{
	const struct pci_device_table *tbl;
	ACPI_HANDLE handle;
	device_t acpi_dev;

	tbl = PCI_MATCH(dev, pci_int3400_devices);
	if (tbl == NULL)
		return (ENXIO);

	/*
	 * If an ACPI companion exists and is already attached, the ACPI path
	 * owns this hardware — yield to it.
	 */
	handle = acpi_get_handle(dev);
	if (handle != NULL) {
		acpi_dev = acpi_get_device(handle);
		if (acpi_dev != NULL && device_is_attached(acpi_dev))
			return (ENXIO);
	}

	device_set_desc(dev, tbl->descr);
	return (BUS_PROBE_DEFAULT);
}

static int
pci_int3400_attach(device_t dev)
{
	struct acpi_int3400_softc *sc = device_get_softc(dev);

	/*
	 * All DSM calls go through the ACPI companion handle.  On systems
	 * without an ACPI namespace entry for this device the handle is NULL
	 * and DSM probing will find nothing — the driver still attaches but
	 * with no power-slide support.
	 */
	sc->handle = acpi_get_handle(dev);
	return (int3400_attach(dev));
}

static device_method_t pci_int3400_methods[] = {
	DEVMETHOD(device_probe,		pci_int3400_probe),
	DEVMETHOD(device_attach,	pci_int3400_attach),
	DEVMETHOD(device_detach,	int3400_detach),
	DEVMETHOD_END
};

static driver_t pci_int3400_driver = {
	"acpi_int3400",
	pci_int3400_methods,
	sizeof(struct acpi_int3400_softc),
};

DRIVER_MODULE_ORDERED(pci_int3400, pci, pci_int3400_driver, NULL, NULL,
    SI_ORDER_ANY);
MODULE_DEPEND(pci_int3400, acpi, 1, 1, 1);
MODULE_DEPEND(pci_int3400, pci, 1, 1, 1);
PCI_PNP_INFO(pci_int3400_devices);
