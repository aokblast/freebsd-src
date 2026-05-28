/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Project
 * All rights reserved.
 *
 * ChromeOS EC gyroscope driver.
 *
 * Attaches as a child of the cros_ec bus when the EC reports a GYRO-type
 * motion sensor.  Exposes angular velocity data as an evdev input device
 * (/dev/input/eventN).
 *
 * Two delivery modes are supported, selected automatically at attach time:
 *
 *   Interrupt mode (preferred):
 *     The parent cros_ec driver has acquired an IRQ and handles MKBP events.
 *     This driver registers a callback; data arrives from the parent's ithread
 *     and is pushed to evdev with no polling overhead.
 *
 *   Poll mode (fallback):
 *     No IRQ is available (e.g., the EC ACPI node lacks an interrupt resource).
 *     A kernel thread issues EC_CMD_MOTION_SENSE_CMD/DATA at poll_rate Hz.
 *
 * evdev event layout:
 *   EV_ABS  ABS_RX   x-axis angular rate (millidegrees/second)
 *   EV_ABS  ABS_RY   y-axis angular rate
 *   EV_ABS  ABS_RZ   z-axis angular rate
 *   EV_SYN  SYN_REPORT
 *
 * Sysctl (dev.cros_ec_gyro.0):
 *   .poll_rate   samples per second [1, 200], default 50  (poll mode only)
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <dev/evdev/evdev.h>
#include <dev/evdev/input.h>

#include "cros_ec.h"

/* ---------- tunables ---------- */

#define CROS_EC_GYRO_POLL_DEFAULT	50	/* Hz */
#define CROS_EC_GYRO_POLL_MIN		1
#define CROS_EC_GYRO_POLL_MAX		200

/*
 * Default full-scale range assumed if the SENSOR_RANGE query fails.
 * 2000 dps is the widest common setting; converts to ±2,000,000 mdps.
 */
#define CROS_EC_GYRO_RANGE_DEFAULT_DPS	2000

/* ---------- softc ---------- */

struct cros_ec_gyro_softc {
	device_t		 gyro_dev;
	struct cros_ec_softc	*parent_sc;	/* parent cros_ec softc */
	int			 sensor_id;

	int			 poll_rate;	/* Hz, sysctl-writable */

	/*
	 * range_mdps: full-scale range in millidegrees/second.
	 * Used to convert int16 raw EC values to mdps:
	 *   mdps = raw * range_mdps / 32768
	 */
	int32_t			 range_mdps;

	struct evdev_dev	*evdev;

	struct mtx		 gyro_mtx;

	/*
	 * Delivery mode: interrupt or poll.
	 *
	 * use_intr = 1  — parent has an IRQ; callback registered, no poll
	 *                 thread.
	 * use_intr = 0  — no IRQ; poll thread active.
	 */
	int			 use_intr;

	/* Poll-thread fields (only used when use_intr == 0). */
	volatile int		 dying;		  /* set to 1 to stop poll thread */
	volatile int		 thread_running;  /* 1 while poll thread is alive */
};

static MALLOC_DEFINE(M_CROS_EC_GYRO, "cros_ec_gyro", "ChromeOS EC gyro driver");

/* ---------- raw-to-mdps conversion helper ---------- */

static inline void
cros_ec_gyro_push(struct cros_ec_gyro_softc *sc,
    int16_t rawx, int16_t rawy, int16_t rawz)
{
	int32_t x, y, z;

	x = (int32_t)rawx * sc->range_mdps / 32768;
	y = (int32_t)rawy * sc->range_mdps / 32768;
	z = (int32_t)rawz * sc->range_mdps / 32768;

	evdev_push_abs(sc->evdev, ABS_RX, x);
	evdev_push_abs(sc->evdev, ABS_RY, y);
	evdev_push_abs(sc->evdev, ABS_RZ, z);
	evdev_sync(sc->evdev);
}

/* ---------- evdev registration ---------- */

static int
cros_ec_gyro_evdev_init(struct cros_ec_gyro_softc *sc)
{
	int32_t range = sc->range_mdps;

	sc->evdev = evdev_alloc();
	if (sc->evdev == NULL)
		return (ENOMEM);

	evdev_set_name(sc->evdev, device_get_desc(sc->gyro_dev));
	evdev_set_phys(sc->evdev, device_get_nameunit(sc->gyro_dev));
	evdev_set_id(sc->evdev, BUS_VIRTUAL, 0x18d1 /* Google */, 0x0004, 1);

	evdev_support_event(sc->evdev, EV_SYN);
	evdev_support_event(sc->evdev, EV_ABS);

	/*
	 * ABS_RX/RY/RZ: angular rate axes.
	 * Range: ±range_mdps.  No fuzz or flat zone; resolution = 1 mdps/unit.
	 */
	evdev_support_abs(sc->evdev, ABS_RX, -range, range, 0, 0, 1);
	evdev_support_abs(sc->evdev, ABS_RY, -range, range, 0, 0, 1);
	evdev_support_abs(sc->evdev, ABS_RZ, -range, range, 0, 0, 1);

	if (evdev_register(sc->evdev) != 0) {
		evdev_free(sc->evdev);
		sc->evdev = NULL;
		return (EIO);
	}
	return (0);
}

/* ---------- interrupt-mode callback ---------- */

/*
 * Called from the parent cros_ec ithread each time the EC delivers a
 * SENSOR_FIFO MKBP event for this sensor.  Runs in kernel-thread context
 * (may sleep, may take non-spin mutexes).
 */
static void
cros_ec_gyro_cb(void *arg, uint8_t sensor_num __unused,
    int16_t rawx, int16_t rawy, int16_t rawz)
{
	struct cros_ec_gyro_softc *sc = arg;

	if (sc->evdev != NULL)
		cros_ec_gyro_push(sc, rawx, rawy, rawz);
}

/* ---------- poll thread (fallback when no IRQ) ---------- */

static void
cros_ec_gyro_poll(void *arg)
{
	struct cros_ec_gyro_softc *sc = arg;
	struct ec_params_ms_data req;
	struct ec_response_ms_data resp;
	int error;

	req.cmd        = MOTIONSENSE_CMD_DATA;
	req.sensor_num = (uint8_t)sc->sensor_id;

	sc->thread_running = 1;

	while (!sc->dying) {
		error = cros_ec_send_command(sc->parent_sc,
		    EC_CMD_MOTION_SENSE_CMD, 0,
		    &req, sizeof(req), &resp, sizeof(resp));

		if (error == 0 && sc->evdev != NULL) {
			cros_ec_gyro_push(sc,
			    (int16_t)le16toh((uint16_t)resp.data.data[0]),
			    (int16_t)le16toh((uint16_t)resp.data.data[1]),
			    (int16_t)le16toh((uint16_t)resp.data.data[2]));
		}

		/*
		 * Sleep until the next sample.  tsleep on &sc->dying allows
		 * cros_ec_gyro_detach to wake us immediately.
		 */
		tsleep(&sc->dying, PWAIT | PCATCH, "gyropoll",
		    hz / sc->poll_rate);
	}

	sc->thread_running = 0;
	wakeup(&sc->thread_running);
	kthread_exit();
}

/* ---------- sysctl ---------- */

static int
cros_ec_gyro_sysctl_poll_rate(SYSCTL_HANDLER_ARGS)
{
	struct cros_ec_gyro_softc *sc = arg1;
	int val, error;

	val = sc->poll_rate;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < CROS_EC_GYRO_POLL_MIN || val > CROS_EC_GYRO_POLL_MAX)
		return (EINVAL);
	sc->poll_rate = val;
	return (0);
}

/* ---------- probe / attach / detach ---------- */

static int
cros_ec_gyro_probe(device_t dev)
{
	int type;

	/*
	 * We only attach to children that the cros_ec parent created with
	 * the name "cros_ec_gyro" and sensor type == MOTIONSENSE_TYPE_GYRO.
	 */
	if (strcmp(device_get_name(dev), "cros_ec_gyro") != 0)
		return (ENXIO);

	type = cros_ec_get_sensor_type(dev);
	if (type != MOTIONSENSE_TYPE_GYRO)
		return (ENXIO);

	device_set_desc(dev, "ChromeOS EC Gyroscope");
	return (BUS_PROBE_DEFAULT);
}

static int
cros_ec_gyro_attach(device_t dev)
{
	struct cros_ec_gyro_softc *sc;
	struct ec_params_ms_range rreq;
	struct ec_response_ms_range rresp;
	device_t parent;
	int error;

	sc = device_get_softc(dev);
	sc->gyro_dev   = dev;
	sc->parent_sc  = device_get_softc(device_get_parent(dev));
	sc->sensor_id  = cros_ec_get_sensor_id(dev);
	sc->poll_rate  = CROS_EC_GYRO_POLL_DEFAULT;
	sc->range_mdps = (int32_t)CROS_EC_GYRO_RANGE_DEFAULT_DPS * 1000;

	mtx_init(&sc->gyro_mtx, "cros_ec_gyro", NULL, MTX_DEF);

	/* Query the current gyroscope full-scale range. */
	rreq.cmd        = MOTIONSENSE_CMD_SENSOR_RANGE;
	rreq.sensor_num = (uint8_t)sc->sensor_id;
	rreq.roundup    = 0;
	rreq.reserved   = 0;
	rreq.data       = -1;	/* -1 = read */
	error = cros_ec_send_command(sc->parent_sc, EC_CMD_MOTION_SENSE_CMD, 0,
	    &rreq, sizeof(rreq), &rresp, sizeof(rresp));
	if (error == 0 && rresp.range > 0)
		sc->range_mdps = (int32_t)le32toh(rresp.range) * 1000;

	/* Register the evdev device. */
	error = cros_ec_gyro_evdev_init(sc);
	if (error != 0) {
		device_printf(dev, "evdev registration failed (%d)\n", error);
		goto fail_mtx;
	}

	/* Sysctl (poll_rate is a no-op in interrupt mode but kept for ABI). */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "poll_rate",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, cros_ec_gyro_sysctl_poll_rate, "I",
	    "Polling rate in Hz (1-200); only effective in poll mode");

	/*
	 * Choose delivery mode.
	 *
	 * If the parent has a hardware interrupt, register the MKBP callback.
	 * The parent's ithread will call cros_ec_gyro_cb() for each sample,
	 * with no additional wakeup cost.
	 *
	 * Otherwise fall back to a dedicated poll thread.
	 */
	parent = device_get_parent(dev);
	if (cros_ec_has_intr(parent)) {
		error = cros_ec_sensor_intr_register(parent, sc->sensor_id,
		    cros_ec_gyro_cb, sc);
		if (error == 0) {
			sc->use_intr = 1;
			device_printf(dev,
			    "sensor %d, range \xc2\xb1%d dps, interrupt mode\n",
			    sc->sensor_id, sc->range_mdps / 1000);
			return (0);
		}
		device_printf(dev,
		    "interrupt registration failed (%d); falling back to poll\n",
		    error);
	}

	/* Poll-mode path. */
	error = kthread_add(cros_ec_gyro_poll, sc, NULL,
	    NULL, 0, 0, "cros_ec_gyro%d", device_get_unit(dev));
	if (error != 0) {
		device_printf(dev, "kthread_add failed (%d)\n", error);
		goto fail_evdev;
	}

	device_printf(dev, "sensor %d, range \xc2\xb1%d dps, polling at %d Hz\n",
	    sc->sensor_id, sc->range_mdps / 1000, sc->poll_rate);
	return (0);

fail_evdev:
	evdev_unregister(sc->evdev);
	evdev_free(sc->evdev);
fail_mtx:
	mtx_destroy(&sc->gyro_mtx);
	return (error != 0 ? error : ENXIO);
}

static int
cros_ec_gyro_detach(device_t dev)
{
	struct cros_ec_gyro_softc *sc = device_get_softc(dev);

	if (sc->use_intr) {
		/*
		 * Deregister the callback from the parent.  This call blocks
		 * until any in-progress cros_ec_gyro_cb() invocation has
		 * finished, guaranteeing that our softc is not touched
		 * after this function returns.
		 */
		cros_ec_sensor_intr_deregister(device_get_parent(dev),
		    sc->sensor_id);
	} else {
		/* Signal the poll thread to exit and wait for it. */
		sc->dying = 1;
		wakeup(&sc->dying);
		while (sc->thread_running)
			tsleep(&sc->thread_running, PWAIT, "gyrostop", hz / 10);
	}

	evdev_unregister(sc->evdev);
	evdev_free(sc->evdev);
	mtx_destroy(&sc->gyro_mtx);
	return (0);
}

/* ---------- module registration ---------- */

static device_method_t cros_ec_gyro_methods[] = {
	DEVMETHOD(device_probe,  cros_ec_gyro_probe),
	DEVMETHOD(device_attach, cros_ec_gyro_attach),
	DEVMETHOD(device_detach, cros_ec_gyro_detach),
	DEVMETHOD_END
};

static driver_t cros_ec_gyro_driver = {
	"cros_ec_gyro",
	cros_ec_gyro_methods,
	sizeof(struct cros_ec_gyro_softc),
};

DRIVER_MODULE(cros_ec_gyro, cros_ec, cros_ec_gyro_driver, 0, 0);
MODULE_DEPEND(cros_ec_gyro, cros_ec, 1, 1, 1);
MODULE_DEPEND(cros_ec_gyro, evdev,   1, 1, 1);
MODULE_VERSION(cros_ec_gyro, 1);
