/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 The FreeBSD Foundation
 *
 * This software was developed under sponsorship from the FreeBSD Foundation.
 *
 * Driver for the Intel INT3400 Dynamic Power Performance Management (DPTF)
 * device, with support for Pantherlake (PTL) power slides.
 *
 * Reference: Intel DPTF ACPI Extensions Specification,
 * Linux drivers/thermal/intel/int340x_thermal/int3400_thermal.c
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/uuid.h>

#include <machine/_inttypes.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

#define _COMPONENT	ACPI_INT3400
ACPI_MODULE_NAME("INT3400")

/*
 * Power slide levels exposed via sysctl, matching the Windows power slider:
 *   0 = Better Battery (power saving)
 *   1 = Balanced
 *   2 = Better Performance
 *   3 = Best Performance
 */
#define INT3400_PWR_SLIDE_MIN		0
#define INT3400_PWR_SLIDE_MAX		3
#define INT3400_PWR_SLIDE_DEFAULT	1	/* Balanced */

/* ACPI notification code from the platform when the power slide changes. */
#define INT3400_NOTIF_PWRSLIDE		0x83

/* DSM function indices for the Pantherlake power slides DSM. */
#define PTL_PWR_SLIDE_DSM_ENUM		0	/* Enumerate supported funcs */
#define PTL_PWR_SLIDE_DSM_GET_COUNT	1	/* Get number of slide levels */
#define PTL_PWR_SLIDE_DSM_SET		2	/* Set current slide level */
#define PTL_PWR_SLIDE_DSM_GET		3	/* Get current slide level */

#define IDX_TO_BIT(idx)			(1ull << (idx))

static char *int3400_ids[] = {
	"INT3400",
	"INTC10D4",
	NULL
};

/*
 * Pantherlake power slides DSM UUID: fc3a49d3-3b49-416e-97d3-cb62d7df5a01
 * Introduced for Pantherlake (PTL) and later Intel platforms.
 */
static const struct uuid ptl_pwr_slide_uuid = {
	0xfc3a49d3, 0x3b49, 0x416e, 0x97, 0xd3,
	{ 0xcb, 0x62, 0xd7, 0xdf, 0x5a, 0x01 }
};
#define PTL_PWR_SLIDE_DSM_REVISION	1

struct acpi_int3400_softc {
	device_t	dev;
	ACPI_HANDLE	handle;

	/* Whether the Pantherlake power slides DSM is present and usable. */
	bool		ptl_pwr_slide_supported;
	uint64_t	ptl_pwr_slide_functions;

	/* Cached number of slide levels (0 means unknown / not queried yet). */
	int		slide_count;

	/* Current power slide level (authoritative when DSM unavailable). */
	int		slide_level;
};

static SYSCTL_NODE(_hw, OID_AUTO, int3400, CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, "Intel INT3400 DPTF");

static int
ptl_pwr_slide_call(struct acpi_int3400_softc *sc, int function,
    ACPI_OBJECT *arg, ACPI_BUFFER *result)
{
	return (acpi_EvaluateDSM(sc->handle,
	    (const uint8_t *)&ptl_pwr_slide_uuid,
	    PTL_PWR_SLIDE_DSM_REVISION, function, arg, result));
}

static int
ptl_pwr_slide_get_count(struct acpi_int3400_softc *sc)
{
	ACPI_BUFFER result = { ACPI_ALLOCATE_BUFFER, NULL };
	ACPI_OBJECT *obj;
	int count;

	if (ACPI_FAILURE(ptl_pwr_slide_call(sc, PTL_PWR_SLIDE_DSM_GET_COUNT,
	    NULL, &result)))
		return (-1);

	obj = (ACPI_OBJECT *)result.Pointer;
	if (obj == NULL)
		return (-1);

	if (obj->Type != ACPI_TYPE_INTEGER) {
		AcpiOsFree(obj);
		return (-1);
	}
	count = (int)obj->Integer.Value;
	AcpiOsFree(obj);
	return (count);
}

static int
ptl_pwr_slide_get(struct acpi_int3400_softc *sc)
{
	ACPI_BUFFER result = { ACPI_ALLOCATE_BUFFER, NULL };
	ACPI_OBJECT *obj;
	int level;

	if (ACPI_FAILURE(ptl_pwr_slide_call(sc, PTL_PWR_SLIDE_DSM_GET,
	    NULL, &result)))
		return (-1);

	obj = (ACPI_OBJECT *)result.Pointer;
	if (obj == NULL)
		return (-1);

	if (obj->Type != ACPI_TYPE_INTEGER) {
		AcpiOsFree(obj);
		return (-1);
	}
	level = (int)obj->Integer.Value;
	AcpiOsFree(obj);
	return (level);
}

static int
ptl_pwr_slide_set(struct acpi_int3400_softc *sc, int level)
{
	ACPI_BUFFER result = { ACPI_ALLOCATE_BUFFER, NULL };
	ACPI_OBJECT arg_obj;
	ACPI_STATUS status;

	arg_obj.Type = ACPI_TYPE_INTEGER;
	arg_obj.Integer.Value = level;

	status = ptl_pwr_slide_call(sc, PTL_PWR_SLIDE_DSM_SET,
	    &arg_obj, &result);
	if (result.Pointer != NULL)
		AcpiOsFree(result.Pointer);

	return (ACPI_SUCCESS(status) ? 0 : EIO);
}

static int
sysctl_pwr_slide(SYSCTL_HANDLER_ARGS)
{
	struct acpi_int3400_softc *sc = arg1;
	int error, level, max;

	level = sc->slide_level;
	error = sysctl_handle_int(oidp, &level, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	max = (sc->slide_count > 0) ? (sc->slide_count - 1) : INT3400_PWR_SLIDE_MAX;
	if (level < INT3400_PWR_SLIDE_MIN || level > max)
		return (EINVAL);

	if (sc->ptl_pwr_slide_supported) {
		error = ptl_pwr_slide_set(sc, level);
		if (error != 0)
			return (error);
	}
	sc->slide_level = level;
	return (0);
}

static void
acpi_int3400_notify(ACPI_HANDLE handle __unused, UINT32 notify, void *ctx)
{
	struct acpi_int3400_softc *sc = ctx;
	int level;

	if (notify != INT3400_NOTIF_PWRSLIDE)
		return;

	if (!sc->ptl_pwr_slide_supported)
		return;

	level = ptl_pwr_slide_get(sc);
	if (level >= 0) {
		if (bootverbose)
			device_printf(sc->dev,
			    "Power slide changed to %d\n", level);
		sc->slide_level = level;
	}
}

static void
acpi_int3400_probe_ptl_pwr_slide(struct acpi_int3400_softc *sc)
{
	uint64_t funcs;

	funcs = acpi_DSMQuery(sc->handle,
	    (const uint8_t *)&ptl_pwr_slide_uuid,
	    PTL_PWR_SLIDE_DSM_REVISION);

	/* Bit 0 (function 0) set means the DSM is present. */
	if ((funcs & IDX_TO_BIT(0)) == 0)
		return;

	/* We require at least set (2) and get (3) functions. */
	if ((funcs & IDX_TO_BIT(PTL_PWR_SLIDE_DSM_SET)) == 0 ||
	    (funcs & IDX_TO_BIT(PTL_PWR_SLIDE_DSM_GET)) == 0) {
		device_printf(sc->dev,
		    "PTL power slides DSM present but missing required "
		    "functions (funcs=%#" PRIx64 ")\n", funcs);
		return;
	}

	sc->ptl_pwr_slide_supported = true;
	sc->ptl_pwr_slide_functions = funcs;
}

static int
acpi_int3400_probe(device_t dev)
{
	char *name;

	if (acpi_get_type(dev) != ACPI_TYPE_DEVICE || acpi_disabled("int3400"))
		return (ENXIO);

	if (ACPI_ID_PROBE(device_get_parent(dev), dev, int3400_ids, &name) > 0)
		return (ENXIO);

	device_set_desc(dev, "Intel Dynamic Power Performance Management");
	return (BUS_PROBE_DEFAULT);
}

static int
acpi_int3400_attach(device_t dev)
{
	struct acpi_int3400_softc *sc = device_get_softc(dev);
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	ACPI_STATUS status;
	int level;

	sc->dev = dev;
	sc->handle = acpi_get_handle(dev);
	sc->slide_level = INT3400_PWR_SLIDE_DEFAULT;

	acpi_int3400_probe_ptl_pwr_slide(sc);

	if (sc->ptl_pwr_slide_supported) {
		device_printf(dev, "Pantherlake power slides supported "
		    "(funcs=%#" PRIx64 ")\n", sc->ptl_pwr_slide_functions);

		if ((sc->ptl_pwr_slide_functions &
		    IDX_TO_BIT(PTL_PWR_SLIDE_DSM_GET_COUNT)) != 0) {
			sc->slide_count = ptl_pwr_slide_get_count(sc);
			if (sc->slide_count > 0 && bootverbose)
				device_printf(dev, "Power slide levels: %d\n",
				    sc->slide_count);
		}

		level = ptl_pwr_slide_get(sc);
		if (level >= 0)
			sc->slide_level = level;
	} else {
		device_printf(dev, "No Pantherlake power slides DSM found\n");
	}

	status = AcpiInstallNotifyHandler(sc->handle, ACPI_DEVICE_NOTIFY,
	    acpi_int3400_notify, sc);
	if (ACPI_FAILURE(status))
		device_printf(dev,
		    "Could not install notify handler: %s\n",
		    AcpiFormatException(status));

	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "power_slide",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    sysctl_pwr_slide, "I",
	    "Power slide level: 0=Better Battery, 1=Balanced, "
	    "2=Better Performance, 3=Best Performance");
	SYSCTL_ADD_INT(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
	    "power_slide_count", CTLFLAG_RD, &sc->slide_count, 0,
	    "Number of available power slide levels (0 = unknown)");
	SYSCTL_ADD_BOOL(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
	    "ptl_power_slides", CTLFLAG_RD,
	    &sc->ptl_pwr_slide_supported, 0,
	    "Pantherlake power slides DSM is present and supported");

	return (0);
}

static int
acpi_int3400_detach(device_t dev)
{
	struct acpi_int3400_softc *sc = device_get_softc(dev);

	AcpiRemoveNotifyHandler(sc->handle, ACPI_DEVICE_NOTIFY,
	    acpi_int3400_notify);
	return (0);
}

static device_method_t acpi_int3400_methods[] = {
	DEVMETHOD(device_probe,		acpi_int3400_probe),
	DEVMETHOD(device_attach,	acpi_int3400_attach),
	DEVMETHOD(device_detach,	acpi_int3400_detach),
	DEVMETHOD_END
};

static driver_t acpi_int3400_driver = {
	"acpi_int3400",
	acpi_int3400_methods,
	sizeof(struct acpi_int3400_softc),
};

DRIVER_MODULE_ORDERED(acpi_int3400, acpi, acpi_int3400_driver, NULL, NULL,
    SI_ORDER_ANY);
MODULE_DEPEND(acpi_int3400, acpi, 1, 1, 1);
MODULE_VERSION(acpi_int3400, 1);
