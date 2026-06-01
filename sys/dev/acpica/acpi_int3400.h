/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 The FreeBSD Foundation
 *
 * This software was developed under sponsorship from the FreeBSD Foundation.
 *
 * Shared definitions for the Intel INT3400 Dynamic Power Performance
 * Management (DPTF) driver.  Consumed by acpi_int3400.c (ACPI path) and
 * pci_int3400.c (PCI path).
 */

#ifndef _DEV_ACPICA_ACPI_INT3400_H_
#define _DEV_ACPICA_ACPI_INT3400_H_

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

/*
 * Power slide levels, matching the Windows power slider:
 *   0 = Better Battery (power saving)
 *   1 = Balanced
 *   2 = Better Performance
 *   3 = Best Performance
 */
#define INT3400_PWR_SLIDE_MIN		0
#define INT3400_PWR_SLIDE_MAX		3
#define INT3400_PWR_SLIDE_DEFAULT	1	/* Balanced */

/* ACPI notification code sent when the platform changes the power slide. */
#define INT3400_NOTIF_PWRSLIDE		0x83

struct acpi_int3400_softc {
	device_t	dev;
	ACPI_HANDLE	handle;

	/* Whether the Pantherlake power slides DSM is present and usable. */
	bool		ptl_pwr_slide_supported;
	uint64_t	ptl_pwr_slide_functions;

	/* Cached number of slide levels (0 = unknown / not queried yet). */
	int		slide_count;

	/* Current power slide level. */
	int		slide_level;
};

/* Shared entry points called by both the ACPI and PCI probe paths. */
int	int3400_attach(device_t dev);
int	int3400_detach(device_t dev);

#endif /* _DEV_ACPICA_ACPI_INT3400_H_ */
