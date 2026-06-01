/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 The FreeBSD Foundation
 *
 * This software was developed under sponsorship from the FreeBSD Foundation.
 *
 * Shared definitions for the Intel INT3400 Dynamic Power Performance
 * Management (DPTF) driver family.
 *
 * The driver has two independent enumeration paths that do not share any
 * code, only the user-visible power-slide semantics defined here:
 *   - acpi_int3400.c: ACPI device (HID INT3400 / INTC10D4), power slide
 *     driven through the Pantherlake power slides _DSM.
 *   - pci_int3400.c:  PCI device (0x8086:0xB01D on Pantherlake), power slide
 *     driven through a direct memory-mapped register in the PCI BAR.
 */

#ifndef _DEV_ACPICA_ACPI_INT3400_H_
#define _DEV_ACPICA_ACPI_INT3400_H_

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

#endif /* _DEV_ACPICA_ACPI_INT3400_H_ */
