/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Project
 * All rights reserved.
 *
 * ChromeOS Embedded Controller host command protocol v3 definitions.
 * Based on include/ec_commands.h from the ChromeOS EC firmware project.
 */

#ifndef _DEV_CROS_EC_H_
#define _DEV_CROS_EC_H_

#include <sys/types.h>

/*
 * Protocol v3 host command trigger byte, written to the EC command port
 * (EC_LPC_ADDR_HOST_CMD, typically 0x204) to initiate a v3 transaction.
 */
#define EC_COMMAND_PROTOCOL_3		0xDAU

/* EC command/status port busy bit — poll until clear after issuing a command. */
#define EC_LPC_STATUS_BUSY_MASK		0x04U

/* EC return codes (ec_status). */
#define EC_RES_SUCCESS			0
#define EC_RES_INVALID_COMMAND		1
#define EC_RES_ERROR			2
#define EC_RES_INVALID_PARAM		3
#define EC_RES_ACCESS_DENIED		4
#define EC_RES_INVALID_RESPONSE		5
#define EC_RES_INVALID_VERSION		6
#define EC_RES_INVALID_CHECKSUM		7
#define EC_RES_IN_PROGRESS		8
#define EC_RES_UNAVAILABLE		9
#define EC_RES_TIMEOUT			10
#define EC_RES_OVERFLOW			11
#define EC_RES_INVALID_HEADER		12
#define EC_RES_REQUEST_TRUNCATED	13
#define EC_RES_RESPONSE_TOO_BIG		14
#define EC_RES_BUS_ERROR		15
#define EC_RES_BUSY			16

/* Host command codes. */
#define EC_CMD_GET_VERSION		0x0001U
#define EC_CMD_GET_PROTOCOL_INFO	0x000BU
#define EC_CMD_BATTERY_GET_STATIC	0x0024U
#define EC_CMD_BATTERY_GET_DYNAMIC	0x0025U
#define EC_CMD_TEMP_SENSOR_GET_INFO	0x0070U
#define EC_CMD_GPIO_SET			0x0092U
#define EC_CMD_GPIO_GET			0x0093U

/* Battery status flags (ec_response_battery_dynamic_info.flags). */
#define EC_BATT_FLAG_AC_PRESENT		0x01U
#define EC_BATT_FLAG_BATT_PRESENT	0x02U
#define EC_BATT_FLAG_DISCHARGING	0x04U
#define EC_BATT_FLAG_CHARGING		0x08U
#define EC_BATT_FLAG_LEVEL_CRITICAL	0x10U
#define EC_BATT_FLAG_INVALID_DATA	0x20U

/*
 * EC memory-map temperature encoding.
 * Raw byte from memmap: value = T_kelvin - EC_TEMP_SENSOR_OFFSET
 * 0xFF = sensor not present, 0xFE = sensor error.
 */
#define EC_TEMP_SENSOR_OFFSET		200
#define EC_TEMP_SENSOR_NOT_PRESENT	0xFFU
#define EC_TEMP_SENSOR_ERROR		0xFEU

/* Offsets within the EC memory-mapped region (base = EC_LPC_ADDR_MEMMAP = 0x900). */
#define EC_MEMMAP_TEMP_SENSOR		0x00U	/* up to 16 sensors, 1 byte each */
#define EC_MEMMAP_TEMP_SENSOR_COUNT	16

/*
 * Protocol v3 packet header — prepended to every host command request.
 * The checksum field is set so that the sum of every byte in the packet
 * (header + request data) equals zero (mod 256).
 */
struct ec_host_request {
	uint8_t		struct_version;	/* Must be EC_HOST_REQUEST_VERSION (3). */
	uint8_t		checksum;
	uint16_t	command;	/* Little-endian. */
	uint8_t		command_version;
	uint8_t		reserved;	/* Must be 0. */
	uint16_t	data_len;	/* Bytes of request data following header. */
} __packed;
#define EC_HOST_REQUEST_VERSION		3

struct ec_host_response {
	uint8_t		struct_version;	/* 3 */
	uint8_t		checksum;
	uint16_t	result;		/* EC_RES_* */
	uint16_t	data_len;	/* Bytes of response data following header. */
	uint16_t	reserved;	/* Must be 0. */
} __packed;

/* ----- Command-specific parameter/response structures ----- */

struct ec_params_battery_static_info {
	uint8_t		index;		/* Battery index, usually 0. */
} __packed;

struct ec_response_battery_static_info {
	uint32_t	design_capacity;		/* mAh */
	uint32_t	last_full_charge_capacity;	/* mAh */
	uint32_t	cycle_count;
	int32_t		design_voltage;			/* mV */
	uint8_t		manufacturer[32];
	uint8_t		model[32];
	uint8_t		serial[32];
	uint8_t		type[32];
} __packed;

struct ec_params_battery_dynamic_info {
	uint8_t		index;
} __packed;

struct ec_response_battery_dynamic_info {
	int32_t		actual_voltage;		/* mV */
	int32_t		actual_current;		/* mA, negative = discharging */
	int32_t		remaining_capacity;	/* mAh */
	int32_t		full_capacity;		/* mAh */
	int32_t		flags;			/* EC_BATT_FLAG_* */
	int32_t		desired_voltage;	/* mV */
	int32_t		desired_current;	/* mA */
} __packed;

struct ec_params_temp_sensor_get_info {
	uint8_t		id;
} __packed;

struct ec_response_temp_sensor_get_info {
	char		sensor_name[32];
	uint8_t		sensor_type;
} __packed;

struct ec_params_gpio_get {
	char		name[32];
} __packed;

struct ec_response_gpio_get {
	uint8_t		val;
} __packed;

struct ec_params_gpio_set {
	char		name[32];
	uint8_t		val;
} __packed;

/* ===== EC motion sense (EC_CMD_MOTION_SENSE_CMD = 0x002B) ===== */

#define EC_CMD_MOTION_SENSE_CMD		0x002BU

/* Subcommands passed in params.cmd. */
#define MOTIONSENSE_CMD_DUMP		0
#define MOTIONSENSE_CMD_INFO		1
#define MOTIONSENSE_CMD_SENSOR_RANGE	4
#define MOTIONSENSE_CMD_DATA		6

/* Sensor type (returned in info response). */
#define MOTIONSENSE_TYPE_ACCEL		0
#define MOTIONSENSE_TYPE_GYRO		1
#define MOTIONSENSE_TYPE_MAG		2
#define MOTIONSENSE_TYPE_PROX		3
#define MOTIONSENSE_TYPE_LIGHT		4
#define MOTIONSENSE_TYPE_ACTIVITY	5
#define MOTIONSENSE_TYPE_BARO		6

/* Sensor location. */
#define MOTIONSENSE_LOC_BASE		0
#define MOTIONSENSE_LOC_LID		1
#define MOTIONSENSE_LOC_CAMERA		2

/* Maximum number of sensors in a DUMP response. */
#define EC_MOTION_SENSE_MAX_SENSORS	16

/*
 * Per-sample data included in DUMP and DATA responses.
 * raw data[i] = angular_rate * 32768 / range_dps  (gyro)
 *             = linear_accel * 32768 / range_g     (accel)
 */
struct ec_ms_sensor_data {
	uint8_t		flags;
	uint8_t		sensor_num;
	int16_t		data[3];	/* x, y, z */
} __packed;

/* DUMP request: just the command byte. */
struct ec_params_ms_dump {
	uint8_t		cmd;		/* MOTIONSENSE_CMD_DUMP */
} __packed;

struct ec_response_ms_dump {
	uint8_t		module_flags;
	uint8_t		sensor_count;
	struct ec_ms_sensor_data sensor[EC_MOTION_SENSE_MAX_SENSORS];
} __packed;

/* INFO request / response (v0 — 4-byte response is sufficient for type). */
struct ec_params_ms_info {
	uint8_t		cmd;		/* MOTIONSENSE_CMD_INFO */
	uint8_t		sensor_num;
} __packed;

struct ec_response_ms_info {
	uint8_t		type;		/* MOTIONSENSE_TYPE_* */
	uint8_t		location;	/* MOTIONSENSE_LOC_* */
	uint8_t		sensor_num;
	uint8_t		chip;
} __packed;

/* DATA request / response. */
struct ec_params_ms_data {
	uint8_t		cmd;		/* MOTIONSENSE_CMD_DATA */
	uint8_t		sensor_num;
} __packed;

struct ec_response_ms_data {
	struct ec_ms_sensor_data data;
} __packed;

/*
 * SENSOR_RANGE request / response.
 * Set data = -1 to read the current range; data >= 0 to set a new range.
 */
struct ec_params_ms_range {
	uint8_t		cmd;		/* MOTIONSENSE_CMD_SENSOR_RANGE */
	uint8_t		sensor_num;
	uint8_t		roundup;	/* 1 = round up to nearest supported value */
	uint8_t		reserved;
	int32_t		data;		/* -1 = read; dps for gyro, g for accel */
} __packed;

struct ec_response_ms_range {
	uint32_t	range;		/* current range (dps or g) */
} __packed;

/* ===== MKBP (Matrix Keyboard/Button Protocol) event interface ===== */

/*
 * EC_CMD_GET_NEXT_EVENT version 1: dequeue one MKBP event from the EC.
 * EC returns EC_RES_UNAVAILABLE when the queue is empty.
 */
#define EC_CMD_GET_NEXT_EVENT		0x0067U

/* MKBP event type codes (event_type field of ec_response_get_next_event). */
#define EC_MKBP_EVENT_KEY_MATRIX	0
#define EC_MKBP_EVENT_HOST_EVENT	1
#define EC_MKBP_EVENT_SENSOR_FIFO	6

/*
 * GET_NEXT_EVENT response (version 1 — adds sensor_event to the data union).
 * For EC_MKBP_EVENT_SENSOR_FIFO, data.sensor_event carries one sensor sample.
 * The union must accommodate key_matrix[13], so sensor_event is padded.
 */
struct ec_response_get_next_event {
	uint8_t		event_type;
	union {
		uint8_t			 key_matrix[13];
		uint32_t		 host_event;
		uint64_t		 ec_future_event;
		struct ec_ms_sensor_data sensor_event;
	} data;
} __packed;

/*
 * Additional MOTIONSENSE subcommands for FIFO interrupt-driven delivery.
 *
 * FIFO_INT_ENABLE: arms (enable=1) or disarms (enable=0) the EC interrupt
 * that fires when new sensor data enters the FIFO.  enable=-1 queries state.
 */
#define MOTIONSENSE_CMD_FIFO_INFO	7
#define MOTIONSENSE_CMD_FIFO_READ	8
#define MOTIONSENSE_CMD_FIFO_INT_ENABLE	14

struct ec_params_ms_fifo_int_enable {
	uint8_t		cmd;		/* MOTIONSENSE_CMD_FIFO_INT_ENABLE */
	int8_t		enable;		/* 1=enable, 0=disable, -1=query */
} __packed;

struct ec_response_ms_fifo_int_enable {
	int8_t		enabled;	/* current armed state */
} __packed;

/* ===== cros_ec bus ivar interface ===== */

/*
 * Child devices of the cros_ec bus are created for each motion sensor found
 * via MOTIONSENSE_CMD_DUMP.  The ivar interface lets child drivers read the
 * sensor index and type without access to the parent's private softc.
 */
enum cros_ec_ivars {
	CROS_EC_IVAR_SENSOR_ID,		/* EC sensor index (uint8_t) */
	CROS_EC_IVAR_SENSOR_TYPE,	/* MOTIONSENSE_TYPE_* (uint8_t) */
};

#define CROS_EC_IVAR_ACCESSOR(var, ivar, type)				\
static __inline type							\
cros_ec_get_##var(device_t dev)						\
{									\
	uintptr_t v;							\
	BUS_READ_IVAR(device_get_parent(dev), dev,			\
	    CROS_EC_IVAR_##ivar, &v);					\
	return ((type)v);						\
}

CROS_EC_IVAR_ACCESSOR(sensor_id,   SENSOR_ID,   int)
CROS_EC_IVAR_ACCESSOR(sensor_type, SENSOR_TYPE, int)

/*
 * Forward declaration for cros_ec_send_command(), which child drivers call
 * via device_get_softc(device_get_parent(dev)).
 */
struct cros_ec_softc;
int cros_ec_send_command(struct cros_ec_softc *, uint16_t, uint8_t,
    const void *, uint16_t, void *, uint16_t);

/*
 * Sensor MKBP interrupt callback interface for child sensor drivers.
 *
 * cros_ec_sensor_intr_register():
 *   Register a callback for sensor_num.  Called from the parent's MKBP
 *   interrupt thread each time a SENSOR_FIFO event arrives for that sensor.
 *   Returns 0 on success, ENOTSUP if the parent has no interrupt resource.
 *
 * cros_ec_sensor_intr_deregister():
 *   Remove the callback.  Blocks until any in-progress callback invocation
 *   has finished, so the caller's softc may be freed immediately afterward.
 *
 * cros_ec_has_intr():
 *   Returns non-zero if the parent has a hardware interrupt; child drivers
 *   should use this to choose between interrupt and poll modes at attach time.
 */
typedef void (*cros_ec_sensor_cb_t)(void *arg, uint8_t sensor_num,
    int16_t x, int16_t y, int16_t z);

int  cros_ec_sensor_intr_register(device_t parent, int sensor_num,
    cros_ec_sensor_cb_t cb, void *arg);
void cros_ec_sensor_intr_deregister(device_t parent, int sensor_num);
int  cros_ec_has_intr(device_t parent);

#endif /* _DEV_CROS_EC_H_ */
