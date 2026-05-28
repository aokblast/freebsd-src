/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Project
 * All rights reserved.
 *
 * ChromeOS Embedded Controller (GOOG0004) driver — LPC/eSPI transport.
 *
 * Attaches to the ACPI "GOOG0004" device and communicates with the EC
 * using host command protocol v3 over LPC I/O ports.
 *
 * Expected ACPI _CRS I/O layout (RID order matches _CRS declaration order):
 *
 *   Resource 0 — EC host command interface, one of:
 *     • 8 bytes at 0x200–0x207: data at offset 0, cmd/status at offset 4
 *     • 1 byte  at 0x66       : legacy ACPI-EC-style cmd/status port
 *   Resource 1 — Host packet region (≥ 128 bytes, typically 0x800–0x8FF).
 *                If the resource is ≥ 0x200 bytes, the EC memory map lives
 *                at offset 0x100 within the same range (absolute 0x900).
 *   Resource 2 — (Optional) separate EC memory map region at 0x900–0x9FF.
 *
 * Sysctl tree (dev.cros_ec.0):
 *   .battery.voltage_mv     actual battery voltage
 *   .battery.current_ma     charge/discharge current (negative = discharging)
 *   .battery.remaining_mah  remaining capacity
 *   .battery.full_mah       reported full capacity
 *   .battery.flags          EC_BATT_FLAG_* bitmask
 *   .thermal.sensorN        temperature in tenths of Kelvin
 */

#include <sys/cdefs.h>
#include "opt_acpi.h"

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <machine/bus.h>
#include <machine/cpufunc.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>

#include "cros_ec.h"

/* ---------- compile-time tunables ---------- */

#define CROS_EC_TIMEOUT_US	750000	/* 750 ms total wait for EC */
#define CROS_EC_POLL_US		50	/* polling interval */
#define CROS_EC_MAX_PKT		256	/* max bytes on the wire per transfer */

/*
 * Offset of the cmd/status byte within an 8-byte host-cmd I/O range.
 * (Range base 0x200, cmd/status port at 0x204.)
 */
#define CROS_EC_CMD_OFF_8BYTE	4

/*
 * Well-known ChromeOS EC LPC port addresses used as fallbacks when the
 * ACPI _CRS does not declare them (typical on PNP0C09-only systems such
 * as Framework laptops).
 */
#define CROS_EC_ADDR_HOST_CMD	0x200U	/* base of 8-byte host cmd range */
#define CROS_EC_ADDR_HOST_PKT	0x800U	/* base of packet + memmap region */
#define CROS_EC_SIZE_HOST_CMD	8U
#define CROS_EC_SIZE_HOST_PKT	0x200U	/* 512 bytes: packet(256) + memmap(256) */

/*
 * EC memory-mapped region and magic identifier used to confirm the device
 * is a ChromeOS EC before claiming a PNP0C09 device away from acpi_ec(4).
 *
 * The EC writes 'E', 'C' to memmap offsets 0x20 and 0x21 on boot.
 */
#define CROS_EC_MEMMAP_BASE	0x900U
#define CROS_EC_MEMMAP_MAGIC	0x20U	/* offsets of 'E' and 'C' within base */

/*
 * Microchip Embedded Controller (MEC) EMI (External Memory Interface).
 *
 * Framework laptops use a MEC1705 as the ChromeOS EC.  On MEC hardware the
 * packet buffer and memory map are NOT directly accessible via sequential
 * I/O reads; instead all host access goes through an indirect EMI window:
 *
 *   0x800  H2EC    Host→EC doorbell (1 byte write)
 *   0x801  EC2H    EC→Host doorbell (1 byte read)
 *   0x802  ADDR    16-bit EMI address register (write)
 *   0x804  DATA    32-bit EMI data register (read/write)
 *
 * The address register encodes a 4-byte-aligned EC address in bits [15:2]
 * and an access type in bits [1:0].  We always use LONG_AUTOINC (3), which
 * lets the 4 data bytes be addressed individually by offset from 0x804.
 *
 * EC address space layout seen through the EMI:
 *   [0x000, 0x0FF]  host command packet buffer
 *   [0x100, 0x1FF]  EC memory map  (≡ standard LPC 0x900–0x9FF)
 */
#define MEC_EMI_ADDR_PORT	0x802U	/* 16-bit address register */
#define MEC_EMI_DATA_PORT	0x804U	/* 32-bit data register */
#define MEC_ACCESS_LONG_AUTOINC	0x3U	/* access type: long, auto-increment */
#define MEC_EC_PACKET_OFF	0x000U	/* packet buffer base in EC address space */
#define MEC_EC_MEMMAP_OFF	0x100U	/* memmap base in EC address space */
/*
 * The EMI window is exactly 8 I/O ports:
 *   0x800 H2EC doorbell, 0x801 EC2H doorbell,
 *   0x802-0x803 ADDR register, 0x804-0x807 DATA register.
 * For MEC systems we reserve only these 8 bytes; the full packet buffer
 * and memory map are reached through the window, not via direct I/O.
 */
#define MEC_EMI_SIZE		8U

/* ---------- driver softc ---------- */

struct cros_ec_softc {
	device_t		 ec_dev;
	ACPI_HANDLE		 ec_handle;

	/*
	 * Host command / status port.
	 * ec_cmd_off: byte offset within the allocated resource to the cmd port.
	 *   0  — for a single-byte resource (e.g., port 0x66)
	 *   4  — for an 8-byte range (e.g., 0x200–0x207, cmd port at 0x204)
	 */
	int			 ec_cmd_rid;
	struct resource		*ec_cmd_res;
	bus_space_tag_t		 ec_cmd_tag;
	bus_space_handle_t	 ec_cmd_handle;
	bus_size_t		 ec_cmd_off;

	/* Host packet region: request/response packets are DMA'd through here. */
	int			 ec_pkt_rid;
	struct resource		*ec_pkt_res;
	bus_space_tag_t		 ec_pkt_tag;
	bus_space_handle_t	 ec_pkt_handle;

	/*
	 * EC memory map: temperature sensors and other live data.
	 * ec_mm_tag == 0 if the memmap is unavailable.
	 * ec_mm_off: byte offset from ec_mm_handle to the first memmap byte.
	 *   Non-zero when the memmap shares the packet resource (at +0x100).
	 */
	int			 ec_mm_rid;
	struct resource		*ec_mm_res;
	bus_space_tag_t		 ec_mm_tag;
	bus_space_handle_t	 ec_mm_handle;
	bus_size_t		 ec_mm_off;

	struct mtx		 ec_mtx;

	/*
	 * MKBP interrupt support.
	 *
	 * ec_irq_res is non-NULL when the parent ACPI device exported an IRQ
	 * resource and we successfully set up an interrupt handler for it.
	 *
	 * ec_sensor_cb[n] / ec_sensor_cb_arg[n]: callback registered by the
	 * child driver for sensor n.  Protected by ec_mtx.
	 *
	 * ec_cb_active: number of callback invocations currently executing.
	 * ec_cb_drain: CV broadcast when ec_cb_active drops to 0, used by
	 *   cros_ec_sensor_intr_deregister() to drain in-progress callbacks
	 *   before the child's softc may be freed.
	 */
	int			 ec_irq_rid;
	struct resource		*ec_irq_res;
	void			*ec_irq_cookie;

	cros_ec_sensor_cb_t	 ec_sensor_cb[EC_MOTION_SENSE_MAX_SENSORS];
	void			*ec_sensor_cb_arg[EC_MOTION_SENSE_MAX_SENSORS];
	int			 ec_cb_active;
	struct cv		 ec_cb_drain;

	/*
	 * ec_is_mec: 1 if this is a Microchip MEC variant that requires
	 * indirect EMI I/O for the packet buffer and memory map.
	 * Set in cros_ec_attach() after the EC signature check.
	 *
	 * ec_mec_mutex: ACPI AML named mutex "MCEM" in the EC device's scope.
	 * Non-NULL only when ec_is_mec == 1 and AcpiGetHandle() found "MCEM".
	 * Must be acquired BEFORE ec_mtx; released AFTER ec_mtx.  This prevents
	 * ACPI firmware _Q (query) handlers from interleaving their own EMI
	 * address/data register writes with ours, which would corrupt packets.
	 * AcpiAcquireMutex() can sleep, so it must never be called while
	 * ec_mtx (or any other non-sleepable lock) is held.
	 */
	int			 ec_is_mec;
	ACPI_HANDLE		 ec_mec_mutex;

	/* Motion sensor children enumerated from MOTIONSENSE_CMD_DUMP. */
	STAILQ_HEAD(, cros_ec_sensor_info) ec_sensors;
};

/* Per-child device state stored as device ivars. */
struct cros_ec_sensor_info {
	STAILQ_ENTRY(cros_ec_sensor_info) link;
	device_t		 child;
	uint8_t			 sensor_id;
	uint8_t			 sensor_type;
};

static MALLOC_DEFINE(M_CROS_EC, "cros_ec", "ChromeOS EC driver");

/* ---------- low-level I/O ---------- */

static inline uint8_t
cros_ec_read_status(struct cros_ec_softc *sc)
{
	return (bus_space_read_1(sc->ec_cmd_tag, sc->ec_cmd_handle,
	    sc->ec_cmd_off));
}

static inline void
cros_ec_write_cmd(struct cros_ec_softc *sc, uint8_t cmd)
{
	bus_space_write_1(sc->ec_cmd_tag, sc->ec_cmd_handle,
	    sc->ec_cmd_off, cmd);
}

/* ---------- MEC EMI indirect I/O ---------- */

/*
 * mec_emi_write — write len bytes from buf to MEC EC address ec_off.
 *
 * Algorithm (mirrors Linux cros_ec_lpc_io_bytes_mec):
 *   1. For bytes before the first 4-byte boundary: set address each time,
 *      write individual bytes to DATA_PORT + (offset & 3).
 *   2. For each aligned 4-byte chunk: set address once with LONG_AUTOINC,
 *      write 32 bits to DATA_PORT (auto-increments EC address by 4 after).
 *   3. For trailing bytes: same as step 1.
 *
 * Returns the byte checksum of all bytes written.
 */
static uint8_t
mec_emi_write(unsigned int ec_off, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	uint8_t sum = 0;
	uint32_t val;
	size_t i = 0;

	/* Unaligned leading bytes. */
	while (i < len && ((ec_off + i) & 3) != 0) {
		unsigned int off = ec_off + i;
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((off & ~3U) | MEC_ACCESS_LONG_AUTOINC));
		outb(MEC_EMI_DATA_PORT + (off & 3U), p[i]);
		sum += p[i++];
	}

	/* Aligned 4-byte words. */
	while (i + 4 <= len) {
		memcpy(&val, &p[i], 4);
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((ec_off + i) | MEC_ACCESS_LONG_AUTOINC));
		outl(MEC_EMI_DATA_PORT, val);
		sum += p[i] + p[i+1] + p[i+2] + p[i+3];
		i += 4;
	}

	/* Trailing bytes. */
	while (i < len) {
		unsigned int off = ec_off + i;
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((off & ~3U) | MEC_ACCESS_LONG_AUTOINC));
		outb(MEC_EMI_DATA_PORT + (off & 3U), p[i]);
		sum += p[i++];
	}

	return (sum);
}

/*
 * mec_emi_read — read len bytes from MEC EC address ec_off into buf.
 * Returns the byte checksum of all bytes read.
 */
static uint8_t
mec_emi_read(unsigned int ec_off, void *buf, size_t len)
{
	uint8_t *p = buf;
	uint8_t sum = 0;
	uint32_t val;
	size_t i = 0;

	/* Unaligned leading bytes. */
	while (i < len && ((ec_off + i) & 3) != 0) {
		unsigned int off = ec_off + i;
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((off & ~3U) | MEC_ACCESS_LONG_AUTOINC));
		p[i] = inb(MEC_EMI_DATA_PORT + (off & 3U));
		sum += p[i++];
	}

	/* Aligned 4-byte words. */
	while (i + 4 <= len) {
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((ec_off + i) | MEC_ACCESS_LONG_AUTOINC));
		val = inl(MEC_EMI_DATA_PORT);
		memcpy(&p[i], &val, 4);
		sum += p[i] + p[i+1] + p[i+2] + p[i+3];
		i += 4;
	}

	/* Trailing bytes. */
	while (i < len) {
		unsigned int off = ec_off + i;
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((off & ~3U) | MEC_ACCESS_LONG_AUTOINC));
		p[i] = inb(MEC_EMI_DATA_PORT + (off & 3U));
		sum += p[i++];
	}

	return (sum);
}

/* ---------- packet region I/O (dispatches on ec_is_mec) ---------- */

/*
 * Write len bytes from buf into the packet region at offset off.
 * Returns the running byte sum (for checksum calculation).
 */
static uint8_t
cros_ec_pkt_write(struct cros_ec_softc *sc, bus_size_t off,
    const void *buf, size_t len)
{
	if (sc->ec_is_mec)
		return (mec_emi_write(MEC_EC_PACKET_OFF + (unsigned int)off,
		    buf, len));

	const uint8_t *p = buf;
	uint8_t sum = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		bus_space_write_1(sc->ec_pkt_tag, sc->ec_pkt_handle,
		    off + i, p[i]);
		sum += p[i];
	}
	return (sum);
}

/*
 * Read len bytes from the packet region at offset off into buf.
 * Returns the running byte sum (for checksum verification).
 */
static uint8_t
cros_ec_pkt_read(struct cros_ec_softc *sc, bus_size_t off,
    void *buf, size_t len)
{
	if (sc->ec_is_mec)
		return (mec_emi_read(MEC_EC_PACKET_OFF + (unsigned int)off,
		    buf, len));

	uint8_t *p = buf;
	uint8_t sum = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		p[i] = bus_space_read_1(sc->ec_pkt_tag, sc->ec_pkt_handle,
		    off + i);
		sum += p[i];
	}
	return (sum);
}

/* ---------- EC memory map ---------- */

/*
 * Read a single byte from the EC memory-mapped region at the given offset
 * (relative to the memmap base).  Returns -1 if the memmap is unavailable.
 */
static int
cros_ec_memmap_read(struct cros_ec_softc *sc, bus_size_t offset)
{
	uint8_t val;

	if (sc->ec_is_mec) {
		mec_emi_read(MEC_EC_MEMMAP_OFF + (unsigned int)offset, &val, 1);
		return ((int)val);
	}
	if (sc->ec_mm_tag == 0)
		return (-1);
	return ((int)bus_space_read_1(sc->ec_mm_tag, sc->ec_mm_handle,
	    sc->ec_mm_off + offset));
}

/* ---------- protocol v3 ---------- */

/*
 * Spin until the EC's busy bit clears.  Must be called with ec_mtx held.
 */
static int
cros_ec_wait_ready(struct cros_ec_softc *sc)
{
	int i;

	for (i = 0; i < CROS_EC_TIMEOUT_US / CROS_EC_POLL_US; i++) {
		if (!(cros_ec_read_status(sc) & EC_LPC_STATUS_BUSY_MASK))
			return (0);
		DELAY(CROS_EC_POLL_US);
	}
	return (ETIMEDOUT);
}

/*
 * Issue an EC host command and retrieve its response.
 *
 * cmd / cmd_ver     : command code and version (version 0 for most commands).
 * req_data / req_size : request payload; NULL/0 if the command takes no data.
 * resp_data / resp_size: buffer for the response payload.  resp_data may be
 *                       NULL when no response data is expected (resp_size = 0).
 *
 * Returns 0 on success, errno on failure.
 */
int
cros_ec_send_command(struct cros_ec_softc *sc,
    uint16_t cmd, uint8_t cmd_ver,
    const void *req_data, uint16_t req_size,
    void *resp_data, uint16_t resp_size)
{
	struct ec_host_request hdr;
	struct ec_host_response rhdr;
	uint8_t sum;
	uint16_t data_len;
	size_t i;
	int error = 0;

	if ((size_t)req_size + sizeof(hdr) > CROS_EC_MAX_PKT ||
	    (size_t)resp_size + sizeof(rhdr) > CROS_EC_MAX_PKT)
		return (EINVAL);

	/*
	 * Acquire the AML mutex before ec_mtx.
	 *
	 * AcpiAcquireMutex() can sleep (it waits for ACPI firmware to release
	 * the mutex if firmware currently holds it), so it MUST be called
	 * before taking any non-sleepable lock.  The timeout 0xFFFF means
	 * "wait indefinitely" in ACPICA units.
	 *
	 * Locking order: AML mutex → ec_mtx (never the reverse).
	 */
	if (sc->ec_is_mec && sc->ec_mec_mutex != NULL)
		AcpiAcquireMutex(sc->ec_mec_mutex, NULL, 0xFFFF);

	mtx_lock(&sc->ec_mtx);

	/* Build request header. */
	hdr.struct_version  = EC_HOST_REQUEST_VERSION;
	hdr.checksum        = 0;		/* filled in below */
	hdr.command         = htole16(cmd);
	hdr.command_version = cmd_ver;
	hdr.reserved        = 0;
	hdr.data_len        = htole16(req_size);

	/*
	 * Checksum: sum of every byte in (header || payload) must equal 0
	 * mod 256.  Compute the sum with checksum=0, then negate.
	 */
	sum = 0;
	for (i = 0; i < sizeof(hdr); i++)
		sum += ((const uint8_t *)&hdr)[i];
	for (i = 0; i < req_size; i++)
		sum += ((const uint8_t *)req_data)[i];
	hdr.checksum = (uint8_t)(-sum);

	/* Write header and payload to the packet region. */
	cros_ec_pkt_write(sc, 0, &hdr, sizeof(hdr));
	if (req_size > 0)
		cros_ec_pkt_write(sc, sizeof(hdr), req_data, req_size);

	/* Trigger EC to process the protocol-v3 packet. */
	cros_ec_write_cmd(sc, EC_COMMAND_PROTOCOL_3);

	error = cros_ec_wait_ready(sc);
	if (error != 0) {
		device_printf(sc->ec_dev,
		    "command 0x%04x timed out\n", cmd);
		goto out;
	}

	/* Read response header. */
	sum = cros_ec_pkt_read(sc, 0, &rhdr, sizeof(rhdr));

	if (rhdr.struct_version != EC_HOST_REQUEST_VERSION) {
		device_printf(sc->ec_dev,
		    "bad response struct_version 0x%02x\n",
		    rhdr.struct_version);
		error = EIO;
		goto out;
	}
	if (le16toh(rhdr.result) != EC_RES_SUCCESS) {
		uint16_t ec_res = le16toh(rhdr.result);
		/*
		 * EC_RES_UNAVAILABLE means "queue empty" for GET_NEXT_EVENT
		 * and is the normal loop-termination signal — do not log it.
		 * Map it to ENOENT so callers can distinguish it from errors.
		 */
		if (ec_res != EC_RES_UNAVAILABLE)
			device_printf(sc->ec_dev,
			    "command 0x%04x: EC result %u\n", cmd, ec_res);
		error = (ec_res == EC_RES_UNAVAILABLE) ? ENOENT : EIO;
		goto out;
	}

	data_len = le16toh(rhdr.data_len);
	if (data_len > resp_size) {
		device_printf(sc->ec_dev,
		    "response too large: %u > %u\n", data_len, resp_size);
		error = ENOSPC;
		goto out;
	}

	/* Read response payload and accumulate into the running checksum. */
	if (data_len > 0 && resp_data != NULL)
		sum += cros_ec_pkt_read(sc, sizeof(rhdr), resp_data, data_len);

	/* Verify: header + payload bytes must sum to 0. */
	if (sum != 0) {
		device_printf(sc->ec_dev,
		    "response checksum error (residual 0x%02x)\n", sum);
		error = EIO;
	}

out:
	mtx_unlock(&sc->ec_mtx);
	/* Release AML mutex after ec_mtx, mirroring the acquire order. */
	if (sc->ec_is_mec && sc->ec_mec_mutex != NULL)
		AcpiReleaseMutex(sc->ec_mec_mutex, NULL);
	return (error);
}

/* ---------- MKBP interrupt machinery ---------- */

/*
 * Enable or disable the EC's sensor-FIFO interrupt.
 * Called with no locks held.
 */
static void
cros_ec_fifo_int_enable(struct cros_ec_softc *sc, int enable)
{
	struct ec_params_ms_fifo_int_enable req;
	struct ec_response_ms_fifo_int_enable resp;

	req.cmd    = MOTIONSENSE_CMD_FIFO_INT_ENABLE;
	req.enable = (int8_t)enable;
	(void)cros_ec_send_command(sc, EC_CMD_MOTION_SENSE_CMD, 0,
	    &req, sizeof(req), &resp, sizeof(resp));
}

/*
 * Interrupt thread handler — drain all queued MKBP events and dispatch
 * any SENSOR_FIFO events to registered child callbacks.
 *
 * Runs as a FreeBSD ithread (kernel thread, may sleep, may take mutexes).
 * cros_ec_send_command() acquires ec_mtx internally; we must not hold it
 * when calling through here.
 */
static void
cros_ec_intr(void *arg)
{
	struct cros_ec_softc *sc = arg;
	struct ec_response_get_next_event ev;
	cros_ec_sensor_cb_t cb;
	void *cb_arg;
	uint8_t snum;
	int error;

	/*
	 * Loop until GET_NEXT_EVENT returns non-zero (ENOENT = queue empty,
	 * EIO = actual error).  Either way we stop draining.
	 */
	while ((error = cros_ec_send_command(sc, EC_CMD_GET_NEXT_EVENT, 1,
	    NULL, 0, &ev, sizeof(ev))) == 0) {

		if (ev.event_type != EC_MKBP_EVENT_SENSOR_FIFO)
			continue;

		snum = ev.data.sensor_event.sensor_num;
		if (snum >= EC_MOTION_SENSE_MAX_SENSORS)
			continue;

		/*
		 * Snapshot the callback pointer under ec_mtx and increment
		 * ec_cb_active so that deregister() can drain in-flight calls.
		 */
		mtx_lock(&sc->ec_mtx);
		cb     = sc->ec_sensor_cb[snum];
		cb_arg = sc->ec_sensor_cb_arg[snum];
		if (cb != NULL)
			sc->ec_cb_active++;
		mtx_unlock(&sc->ec_mtx);

		if (cb != NULL) {
			cb(cb_arg, snum,
			    (int16_t)le16toh((uint16_t)ev.data.sensor_event.data[0]),
			    (int16_t)le16toh((uint16_t)ev.data.sensor_event.data[1]),
			    (int16_t)le16toh((uint16_t)ev.data.sensor_event.data[2]));

			mtx_lock(&sc->ec_mtx);
			if (--sc->ec_cb_active == 0)
				cv_broadcast(&sc->ec_cb_drain);
			mtx_unlock(&sc->ec_mtx);
		}
	}
}

/* ---------- public sensor interrupt API ---------- */

/*
 * Register a callback for MKBP sensor-FIFO events for sensor_num.
 * Returns 0 if interrupt mode is active, ENOTSUP otherwise.
 */
int
cros_ec_sensor_intr_register(device_t parent, int sensor_num,
    cros_ec_sensor_cb_t cb, void *arg)
{
	struct cros_ec_softc *sc = device_get_softc(parent);

	if (sc->ec_irq_res == NULL)
		return (ENOTSUP);
	if (sensor_num < 0 || sensor_num >= EC_MOTION_SENSE_MAX_SENSORS)
		return (EINVAL);

	mtx_lock(&sc->ec_mtx);
	sc->ec_sensor_cb[sensor_num]     = cb;
	sc->ec_sensor_cb_arg[sensor_num] = arg;
	mtx_unlock(&sc->ec_mtx);
	return (0);
}

/*
 * Deregister the callback for sensor_num and wait for any in-progress
 * invocation to finish.  Safe to free the child's softc afterward.
 */
void
cros_ec_sensor_intr_deregister(device_t parent, int sensor_num)
{
	struct cros_ec_softc *sc = device_get_softc(parent);

	if (sensor_num < 0 || sensor_num >= EC_MOTION_SENSE_MAX_SENSORS)
		return;

	mtx_lock(&sc->ec_mtx);
	sc->ec_sensor_cb[sensor_num]     = NULL;
	sc->ec_sensor_cb_arg[sensor_num] = NULL;
	/* Drain any callback that is currently executing. */
	while (sc->ec_cb_active > 0)
		cv_wait(&sc->ec_cb_drain, &sc->ec_mtx);
	mtx_unlock(&sc->ec_mtx);
}

/*
 * Returns non-zero if the parent EC device has a hardware interrupt and
 * interrupt-driven sensor delivery is available.
 */
int
cros_ec_has_intr(device_t parent)
{
	struct cros_ec_softc *sc = device_get_softc(parent);
	return (sc->ec_irq_res != NULL);
}

/* ---------- sysctl callbacks ---------- */

/* Selects which field of ec_response_battery_dynamic_info to return. */
#define BATT_FIELD_VOLTAGE	0
#define BATT_FIELD_CURRENT	1
#define BATT_FIELD_REMAINING	2
#define BATT_FIELD_FULL		3
#define BATT_FIELD_FLAGS	4

static int
cros_ec_sysctl_battery(SYSCTL_HANDLER_ARGS)
{
	struct cros_ec_softc *sc = arg1;
	struct ec_params_battery_dynamic_info params;
	struct ec_response_battery_dynamic_info resp;
	int error, val;

	params.index = 0;
	error = cros_ec_send_command(sc, EC_CMD_BATTERY_GET_DYNAMIC, 0,
	    &params, sizeof(params), &resp, sizeof(resp));
	if (error != 0)
		return (error);

	switch (arg2) {
	case BATT_FIELD_VOLTAGE:
		val = (int32_t)le32toh((uint32_t)resp.actual_voltage);
		break;
	case BATT_FIELD_CURRENT:
		val = (int32_t)le32toh((uint32_t)resp.actual_current);
		break;
	case BATT_FIELD_REMAINING:
		val = (int32_t)le32toh((uint32_t)resp.remaining_capacity);
		break;
	case BATT_FIELD_FULL:
		val = (int32_t)le32toh((uint32_t)resp.full_capacity);
		break;
	case BATT_FIELD_FLAGS:
		val = (int32_t)le32toh((uint32_t)resp.flags);
		break;
	default:
		return (EINVAL);
	}

	return (sysctl_handle_int(oidp, &val, 0, req));
}

/*
 * Report temperature for memmap sensor slot arg2.
 * Value is in tenths of Kelvin to avoid floating point.
 */
static int
cros_ec_sysctl_temp(SYSCTL_HANDLER_ARGS)
{
	struct cros_ec_softc *sc = arg1;
	int raw, temp_dk;

	raw = cros_ec_memmap_read(sc,
	    (bus_size_t)(EC_MEMMAP_TEMP_SENSOR + arg2));
	if (raw < 0)
		return (ENODEV);
	if ((uint8_t)raw == EC_TEMP_SENSOR_NOT_PRESENT)
		return (ENOENT);
	if ((uint8_t)raw == EC_TEMP_SENSOR_ERROR)
		return (EIO);

	temp_dk = (raw + EC_TEMP_SENSOR_OFFSET) * 10;
	return (sysctl_handle_int(oidp, &temp_dk, 0, req));
}

/* ---------- sysctl tree ---------- */

static void
cros_ec_sysctl_setup(device_t dev, struct cros_ec_softc *sc)
{
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid *tree  = device_get_sysctl_tree(dev);
	struct sysctl_oid *batt_tree, *therm_tree;
	char name[16];
	int i, raw;

	/* Battery subtree. */
	batt_tree = SYSCTL_ADD_NODE(ctx, SYSCTL_CHILDREN(tree),
	    OID_AUTO, "battery",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Battery status");

#define ADD_BATT(sname, field, desc)					\
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(batt_tree),		\
	    OID_AUTO, sname,						\
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,			\
	    sc, field, cros_ec_sysctl_battery, "I", desc)

	ADD_BATT("voltage_mv",    BATT_FIELD_VOLTAGE,    "Actual voltage (mV)");
	ADD_BATT("current_ma",    BATT_FIELD_CURRENT,
	    "Charge/discharge current (mA, negative = discharging)");
	ADD_BATT("remaining_mah", BATT_FIELD_REMAINING,  "Remaining capacity (mAh)");
	ADD_BATT("full_mah",      BATT_FIELD_FULL,       "Full charge capacity (mAh)");
	ADD_BATT("flags",         BATT_FIELD_FLAGS,      "Status flags (EC_BATT_FLAG_*)");
#undef ADD_BATT

	/* Thermal subtree: only add sensors present in the memmap at attach.
	 * On MEC, cros_ec_memmap_read() goes through EMI even though ec_mm_tag
	 * is 0, so treat ec_is_mec as an alternative "memmap available" signal. */
	if (sc->ec_mm_tag == 0 && !sc->ec_is_mec)
		return;

	therm_tree = SYSCTL_ADD_NODE(ctx, SYSCTL_CHILDREN(tree),
	    OID_AUTO, "thermal",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Temperature sensors");

	for (i = 0; i < EC_MEMMAP_TEMP_SENSOR_COUNT; i++) {
		raw = cros_ec_memmap_read(sc, EC_MEMMAP_TEMP_SENSOR + i);
		if (raw < 0 || (uint8_t)raw == EC_TEMP_SENSOR_NOT_PRESENT)
			continue;

		snprintf(name, sizeof(name), "sensor%d", i);
		SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(therm_tree),
		    OID_AUTO, name,
		    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, cros_ec_sysctl_temp, "IK",
		    "Temperature in tenths of Kelvin");
	}
}

/* ---------- resource allocation ---------- */

/*
 * Scan _CRS I/O resources (RIDs 0-7), classify each by base address, and
 * synthesise any that are missing at their canonical ChromeOS EC addresses.
 *
 * This handles two hardware layouts:
 *
 *   GOOG0004 / GOOG0003 (Chromebooks):
 *     _CRS declares all three regions; we find and adopt them in the scan.
 *
 *   PNP0C09 (Framework and other cros-EC-on-generic-ACPI-EC systems):
 *     _CRS declares only legacy ACPI EC ports (0x62, 0x66).  The ChromeOS
 *     LPC ranges (0x200-0x207, 0x800-0x9FF) are not listed, so we inject
 *     them with bus_set_resource() and allocate from the nexus rman.
 *
 * Synthetic RIDs start at 16, safely above the _CRS RIDs (0-7).
 *
 * Returns 0 on success, ENXIO on failure (partially-allocated resources
 * are released before returning).
 */
static int
cros_ec_attach_resources(device_t dev, struct cros_ec_softc *sc)
{
	struct resource *res;
	rman_res_t start, size;
	int rid, error;

	/*
	 * Phase 1 — walk _CRS entries, classify, adopt or release.
	 */
	for (rid = 0; rid < 8; rid++) {
		int tmp = rid;

		res = bus_alloc_resource_any(dev, SYS_RES_IOPORT, &tmp,
		    RF_ACTIVE);
		if (res == NULL)
			continue;

		start = rman_get_start(res);
		size  = rman_get_size(res);

		/* Legacy ACPI EC data/command ports — always skip. */
		if (start == 0x62 || start == 0x66) {
			bus_release_resource(dev, SYS_RES_IOPORT, tmp, res);
			continue;
		}

		/* cmd/status: starts in 0x200-0x20F, at least 4 bytes. */
		if (sc->ec_cmd_res == NULL &&
		    start >= CROS_EC_ADDR_HOST_CMD &&
		    start <  CROS_EC_ADDR_HOST_CMD + 0x10 &&
		    size  >= 4) {
			sc->ec_cmd_rid    = tmp;
			sc->ec_cmd_res    = res;
			sc->ec_cmd_tag    = rman_get_bustag(res);
			sc->ec_cmd_handle = rman_get_bushandle(res);
			sc->ec_cmd_off    = (size >= 8) ? CROS_EC_CMD_OFF_8BYTE : 0;
			continue;
		}

		/* Packet region: 0x800+, at least 128 bytes. */
		if (sc->ec_pkt_res == NULL &&
		    start >= CROS_EC_ADDR_HOST_PKT && size >= 128) {
			sc->ec_pkt_rid    = tmp;
			sc->ec_pkt_res    = res;
			sc->ec_pkt_tag    = rman_get_bustag(res);
			sc->ec_pkt_handle = rman_get_bushandle(res);
			/* Embedded memmap at +0x100 when range is ≥ 0x200 bytes. */
			if (size >= CROS_EC_SIZE_HOST_PKT) {
				sc->ec_mm_tag    = sc->ec_pkt_tag;
				sc->ec_mm_handle = sc->ec_pkt_handle;
				sc->ec_mm_off    = 0x100;
			}
			continue;
		}

		/* Explicit memmap region: 0x900+. */
		if (sc->ec_mm_res == NULL && start >= CROS_EC_MEMMAP_BASE) {
			sc->ec_mm_rid    = tmp;
			sc->ec_mm_res    = res;
			sc->ec_mm_tag    = rman_get_bustag(res);
			sc->ec_mm_handle = rman_get_bushandle(res);
			sc->ec_mm_off    = 0;
			continue;
		}

		/* Unrecognised — release immediately. */
		bus_release_resource(dev, SYS_RES_IOPORT, tmp, res);
	}

	/*
	 * Phase 2 — synthesise resources not found in _CRS.
	 */
	error = 0;

	if (sc->ec_cmd_res == NULL) {
		sc->ec_cmd_rid = 16;	/* synthetic RID, outside _CRS range */
		bus_set_resource(dev, SYS_RES_IOPORT, sc->ec_cmd_rid,
		    CROS_EC_ADDR_HOST_CMD, CROS_EC_SIZE_HOST_CMD);
		sc->ec_cmd_res = bus_alloc_resource_any(dev, SYS_RES_IOPORT,
		    &sc->ec_cmd_rid, RF_ACTIVE);
		if (sc->ec_cmd_res == NULL) {
			device_printf(dev,
			    "cannot map cmd/status port at 0x%03x\n",
			    CROS_EC_ADDR_HOST_CMD);
			error = ENXIO;
			goto fail;
		}
		sc->ec_cmd_tag    = rman_get_bustag(sc->ec_cmd_res);
		sc->ec_cmd_handle = rman_get_bushandle(sc->ec_cmd_res);
		sc->ec_cmd_off    = CROS_EC_CMD_OFF_8BYTE;
	}

	if (sc->ec_pkt_res == NULL) {
		sc->ec_pkt_rid = 17;	/* synthetic RID */
		if (sc->ec_is_mec) {
			/*
			 * MEC: the entire packet buffer and memory map are
			 * reached through the 8-byte EMI window (0x800-0x807).
			 * Reserve only those ports.  mec_emi_write/read issue
			 * raw outw/outl/inb/inl instructions directly, so
			 * bus_space setup is not needed.  The memory map is
			 * likewise accessed through EMI, so ec_mm_tag stays 0.
			 */
			bus_set_resource(dev, SYS_RES_IOPORT, sc->ec_pkt_rid,
			    CROS_EC_ADDR_HOST_PKT, MEC_EMI_SIZE);
			sc->ec_pkt_res = bus_alloc_resource_any(dev,
			    SYS_RES_IOPORT, &sc->ec_pkt_rid, RF_ACTIVE);
			if (sc->ec_pkt_res == NULL) {
				device_printf(dev,
				    "cannot reserve MEC EMI ports at 0x%03x\n",
				    CROS_EC_ADDR_HOST_PKT);
				error = ENXIO;
				goto fail;
			}
			/* ec_pkt_tag/handle intentionally not set for MEC. */
		} else {
			/*
			 * Standard LPC: synthesise the full 0x200-byte range
			 * 0x800-0x9FF.  The packet buffer occupies 0x800-0x8FF
			 * and the memory map is embedded at offset +0x100.
			 */
			bus_set_resource(dev, SYS_RES_IOPORT, sc->ec_pkt_rid,
			    CROS_EC_ADDR_HOST_PKT, CROS_EC_SIZE_HOST_PKT);
			sc->ec_pkt_res = bus_alloc_resource_any(dev,
			    SYS_RES_IOPORT, &sc->ec_pkt_rid, RF_ACTIVE);
			if (sc->ec_pkt_res == NULL) {
				device_printf(dev,
				    "cannot map packet region at 0x%03x\n",
				    CROS_EC_ADDR_HOST_PKT);
				error = ENXIO;
				goto fail;
			}
			sc->ec_pkt_tag    = rman_get_bustag(sc->ec_pkt_res);
			sc->ec_pkt_handle = rman_get_bushandle(sc->ec_pkt_res);
			/* 0x200-byte range; memmap embedded at +0x100. */
			sc->ec_mm_tag    = sc->ec_pkt_tag;
			sc->ec_mm_handle = sc->ec_pkt_handle;
			sc->ec_mm_off    = 0x100;
		}
	}

	return (0);

fail:
	/* Release everything we allocated so the caller can abort cleanly. */
	if (sc->ec_mm_res != NULL) {
		bus_release_resource(dev, SYS_RES_IOPORT,
		    sc->ec_mm_rid, sc->ec_mm_res);
		sc->ec_mm_res = NULL;
	}
	sc->ec_mm_tag = 0;
	if (sc->ec_pkt_res != NULL) {
		bus_release_resource(dev, SYS_RES_IOPORT,
		    sc->ec_pkt_rid, sc->ec_pkt_res);
		sc->ec_pkt_res = NULL;
	}
	if (sc->ec_cmd_res != NULL) {
		bus_release_resource(dev, SYS_RES_IOPORT,
		    sc->ec_cmd_rid, sc->ec_cmd_res);
		sc->ec_cmd_res = NULL;
	}
	return (error);
}

/* ---------- bus methods for sensor child devices ---------- */

static device_t
cros_ec_add_child(device_t dev, u_int order, const char *name, int unit)
{
	struct cros_ec_sensor_info *info;
	device_t child;

	child = device_add_child_ordered(dev, order, name, unit);
	if (child == NULL)
		return (NULL);
	info = malloc(sizeof(*info), M_CROS_EC, M_NOWAIT | M_ZERO);
	if (info == NULL) {
		device_delete_child(dev, child);
		return (NULL);
	}
	info->child = child;
	device_set_ivars(child, info);
	return (child);
}

static void
cros_ec_child_deleted(device_t dev, device_t child)
{
	struct cros_ec_sensor_info *info = device_get_ivars(child);

	if (info != NULL)
		free(info, M_CROS_EC);
}

static int
cros_ec_read_ivar(device_t dev, device_t child, int which, uintptr_t *result)
{
	struct cros_ec_sensor_info *info = device_get_ivars(child);

	if (info == NULL)
		return (EINVAL);
	switch (which) {
	case CROS_EC_IVAR_SENSOR_ID:
		*result = info->sensor_id;
		return (0);
	case CROS_EC_IVAR_SENSOR_TYPE:
		*result = info->sensor_type;
		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * Query the EC for available motion sensors and create a child device for
 * each gyroscope found.  Called from cros_ec_attach() after I/O resources
 * are set up.
 */
static void
cros_ec_enumerate_sensors(device_t dev)
{
	struct cros_ec_softc *sc = device_get_softc(dev);
	struct ec_params_ms_dump req;
	struct ec_response_ms_dump resp;
	struct ec_params_ms_info ireq;
	struct ec_response_ms_info iresp;
	struct cros_ec_sensor_info *info;
	device_t child;
	int error, i;

	req.cmd = MOTIONSENSE_CMD_DUMP;
	error = cros_ec_send_command(sc, EC_CMD_MOTION_SENSE_CMD, 0,
	    &req, sizeof(req), &resp, sizeof(resp));
	if (error != 0) {
		device_printf(dev,
		    "motion sense DUMP failed (%d); no sensor children\n",
		    error);
		return;
	}

	for (i = 0; i < resp.sensor_count && i < EC_MOTION_SENSE_MAX_SENSORS;
	    i++) {
		/* Query the sensor type. */
		ireq.cmd        = MOTIONSENSE_CMD_INFO;
		ireq.sensor_num = (uint8_t)i;
		error = cros_ec_send_command(sc, EC_CMD_MOTION_SENSE_CMD, 0,
		    &ireq, sizeof(ireq), &iresp, sizeof(iresp));
		if (error != 0) {
			device_printf(dev,
			    "sensor %d INFO failed (%d), skipping\n", i, error);
			continue;
		}

		/* Only expose gyroscopes; extend here for accel/mag etc. */
		if (iresp.type != MOTIONSENSE_TYPE_GYRO)
			continue;

		child = BUS_ADD_CHILD(dev, 0, "cros_ec_gyro", DEVICE_UNIT_ANY);
		if (child == NULL) {
			device_printf(dev,
			    "failed to add gyro child for sensor %d\n", i);
			continue;
		}

		info = device_get_ivars(child);
		info->sensor_id   = (uint8_t)i;
		info->sensor_type = iresp.type;
		STAILQ_INSERT_TAIL(&sc->ec_sensors, info, link);

		device_printf(dev, "sensor %d: gyroscope at %s\n",
		    i, iresp.location == MOTIONSENSE_LOC_LID ? "lid" : "base");
	}
}

/* ---------- ACPI probe / attach / detach ---------- */

/*
 * PNP0C09 is the generic ACPI Embedded Controller HID, also used by
 * acpi_ec(4).  Include it so Framework laptops (which expose the ChromeOS EC
 * under PNP0C09 instead of GOOG0004) are handled, but only after we verify
 * the ChromeOS EC memory-map signature.
 */
static char *cros_ec_ids[] = { "GOOG0004", "GOOG0003", "PNP0C09", NULL };

static int
cros_ec_probe(device_t dev)
{
	char *match = NULL;
	int rc;

	rc = ACPI_ID_PROBE(device_get_parent(dev), dev, cros_ec_ids, &match);
	if (rc > 0)
		return (rc);

	/*
	 * PNP0C09 is shared with acpi_ec(4), which returns BUS_PROBE_DEFAULT
	 * (0).  Only claim it when the ChromeOS EC memory-map magic bytes
	 * 'E', 'C' are present at 0x920/0x921; otherwise let acpi_ec(4) win.
	 *
	 * The magic check uses inb() directly — the I/O port is accessible
	 * before resource allocation and does not require locking.
	 */
	if (match != NULL && strcmp(match, "PNP0C09") == 0) {
		/*
		 * First try the standard direct I/O signature check at 0x920.
		 */
		if (inb(CROS_EC_MEMMAP_BASE + CROS_EC_MEMMAP_MAGIC)     == 'E' &&
		    inb(CROS_EC_MEMMAP_BASE + CROS_EC_MEMMAP_MAGIC + 1) == 'C') {
			device_set_desc(dev, "ChromeOS Embedded Controller (LPC)");
			return (-1);
		}

		/*
		 * Standard check failed.  Try the MEC EMI indirect path:
		 * write the EC address 0x120 (= memmap base 0x100 + magic
		 * offset 0x20) to the MEC address register, then read the
		 * 'E','C' bytes via individual byte offsets of the data port.
		 *
		 * MEC_EC_MEMMAP_OFF + CROS_EC_MEMMAP_MAGIC = 0x100 + 0x20 = 0x120.
		 * 0x120 is 4-byte aligned, so byte 0 is at DATA_PORT + 0,
		 * byte 1 is at DATA_PORT + 1.
		 */
		outw(MEC_EMI_ADDR_PORT,
		    (uint16_t)((MEC_EC_MEMMAP_OFF + CROS_EC_MEMMAP_MAGIC) |
		    MEC_ACCESS_LONG_AUTOINC));
		if (inb(MEC_EMI_DATA_PORT)     == 'E' &&
		    inb(MEC_EMI_DATA_PORT + 1) == 'C') {
			device_set_desc(dev,
			    "ChromeOS Embedded Controller (MEC LPC)");
			return (-1);
		}

		return (ENXIO);
	}

	device_set_desc(dev, "ChromeOS Embedded Controller (LPC)");
	return (rc);
}

static int
cros_ec_attach(device_t dev)
{
	struct cros_ec_softc *sc;
	int error, irq_err;

	sc = device_get_softc(dev);
	sc->ec_dev    = dev;
	sc->ec_handle = acpi_get_handle(dev);

	mtx_init(&sc->ec_mtx, "cros_ec", NULL, MTX_DEF);
	cv_init(&sc->ec_cb_drain, "cros_ec_cbdr");
	STAILQ_INIT(&sc->ec_sensors);

	/*
	 * Detect MEC vs standard LPC BEFORE allocating resources.
	 *
	 * cros_ec_attach_resources() synthesises the packet-buffer resource
	 * at the correct size — 8 bytes for MEC (EMI window only) vs 512
	 * bytes for standard LPC (packet buffer + embedded memmap) — so it
	 * needs ec_is_mec to be set first.
	 *
	 * Standard: direct inb() at 0x920/0x921 returns 'E','C'.
	 * MEC (Framework): those ports don't contain the signature; probe()
	 *   confirmed the MEC EMI path works instead.
	 */
	sc->ec_is_mec = (
	    inb(CROS_EC_MEMMAP_BASE + CROS_EC_MEMMAP_MAGIC)     != 'E' ||
	    inb(CROS_EC_MEMMAP_BASE + CROS_EC_MEMMAP_MAGIC + 1) != 'C');

	/*
	 * On MEC hardware, look up the AML mutex "MCEM" in the EC device's
	 * ACPI scope.  ACPI firmware EC query handlers (_Qxx methods) acquire
	 * this mutex before touching the EMI; we must do the same or our EMI
	 * address register write and data register read/write can be interleaved
	 * with the firmware's, corrupting both transactions.
	 *
	 * Failure to find the mutex is non-fatal: we warn and proceed without
	 * synchronisation (works on systems whose firmware doesn't use MCEM,
	 * but unsafe on Framework boards).
	 */
	if (sc->ec_is_mec) {
		ACPI_STATUS aml_status;

		aml_status = AcpiGetHandle(sc->ec_handle, "MCEM",
		    &sc->ec_mec_mutex);
		if (ACPI_FAILURE(aml_status)) {
			device_printf(dev,
			    "MCEM AML mutex not found (status 0x%x); "
			    "MEC EMI access unsynchronized with ACPI firmware\n",
			    aml_status);
			sc->ec_mec_mutex = NULL;
		} else {
			device_printf(dev, "MCEM AML mutex found\n");
		}
	}

	/*
	 * Map I/O resources.  cros_ec_attach_resources() handles both the
	 * GOOG0004 layout (all regions in _CRS) and the PNP0C09 layout used
	 * by Framework laptops (only 0x62/0x66 in _CRS; canonical ChromeOS
	 * LPC addresses synthesised via bus_set_resource).
	 */
	error = cros_ec_attach_resources(dev, sc);
	if (error != 0)
		goto fail_mtx;

	cros_ec_sysctl_setup(dev, sc);

	device_printf(dev,
	    "cmd port 0x%jx+%ju, packet region %ju bytes, %s%s\n",
	    (uintmax_t)rman_get_start(sc->ec_cmd_res),
	    (uintmax_t)sc->ec_cmd_off,
	    (uintmax_t)rman_get_size(sc->ec_pkt_res),
	    sc->ec_is_mec ? "MEC EMI, " : "",
	    (sc->ec_mm_tag != 0 || sc->ec_is_mec) ? "memmap present" : "no memmap");

	/* Enumerate motion sensors and create child devices. */
	cros_ec_enumerate_sensors(dev);

	/*
	 * Attempt to acquire the EC's hardware interrupt resource.
	 * Failure is non-fatal: child drivers fall back to polling.
	 */
	sc->ec_irq_rid = 0;
	sc->ec_irq_res = bus_alloc_resource_any(dev, SYS_RES_IRQ,
	    &sc->ec_irq_rid, RF_ACTIVE | RF_SHAREABLE);
	if (sc->ec_irq_res != NULL) {
		irq_err = bus_setup_intr(dev, sc->ec_irq_res,
		    INTR_TYPE_MISC | INTR_MPSAFE,
		    NULL, cros_ec_intr, sc, &sc->ec_irq_cookie);
		if (irq_err != 0) {
			device_printf(dev,
			    "failed to set up EC interrupt (%d); "
			    "falling back to child polling\n", irq_err);
			bus_release_resource(dev, SYS_RES_IRQ,
			    sc->ec_irq_rid, sc->ec_irq_res);
			sc->ec_irq_res = NULL;
		} else {
			cros_ec_fifo_int_enable(sc, 1);
			device_printf(dev, "MKBP interrupt mode enabled\n");
		}
	}

	bus_identify_children(dev);
	bus_attach_children(dev);

	return (0);

fail_mtx:
	cv_destroy(&sc->ec_cb_drain);
	mtx_destroy(&sc->ec_mtx);
	return (error);
}

static int
cros_ec_detach(device_t dev)
{
	struct cros_ec_softc *sc = device_get_softc(dev);

	/* Tear down the interrupt before releasing I/O resources. */
	if (sc->ec_irq_res != NULL) {
		cros_ec_fifo_int_enable(sc, 0);
		bus_teardown_intr(dev, sc->ec_irq_res, sc->ec_irq_cookie);
		bus_release_resource(dev, SYS_RES_IRQ,
		    sc->ec_irq_rid, sc->ec_irq_res);
	}

	if (sc->ec_mm_res != NULL)
		bus_release_resource(dev, SYS_RES_IOPORT,
		    sc->ec_mm_rid, sc->ec_mm_res);
	bus_release_resource(dev, SYS_RES_IOPORT,
	    sc->ec_pkt_rid, sc->ec_pkt_res);
	bus_release_resource(dev, SYS_RES_IOPORT,
	    sc->ec_cmd_rid, sc->ec_cmd_res);

	cv_destroy(&sc->ec_cb_drain);
	mtx_destroy(&sc->ec_mtx);
	return (0);
}

/* ---------- module registration ---------- */

static device_method_t cros_ec_methods[] = {
	/* Device interface. */
	DEVMETHOD(device_probe,		cros_ec_probe),
	DEVMETHOD(device_attach,	cros_ec_attach),
	DEVMETHOD(device_detach,	cros_ec_detach),

	/* Bus interface — minimal set for static child devices. */
	DEVMETHOD(bus_add_child,	cros_ec_add_child),
	DEVMETHOD(bus_child_deleted,	cros_ec_child_deleted),
	DEVMETHOD(bus_read_ivar,	cros_ec_read_ivar),
	DEVMETHOD(bus_print_child,	bus_generic_print_child),

	DEVMETHOD_END
};

static driver_t cros_ec_driver = {
	"cros_ec",
	cros_ec_methods,
	sizeof(struct cros_ec_softc),
};

DRIVER_MODULE(cros_ec, acpi, cros_ec_driver, 0, 0);
MODULE_DEPEND(cros_ec, acpi, 1, 1, 1);
MODULE_VERSION(cros_ec, 1);
