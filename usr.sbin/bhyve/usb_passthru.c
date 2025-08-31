#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <assert.h>
#include <libusb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "pci_xhci.h"
#include "usb_emul.h"

static int usb_passthru_debug = 1;
static bool libusb_is_init = false;
#define	DPRINTF(params) if (usb_passthru_debug) PRINTLN params
#define WPRINTF(params) PRINTLN params

#define OUT		0
#define IN		1

struct usb_passthru_libusb_xfer;

struct usb_passthru_ep_types {
	bool inout;
	int type;
};

struct usb_passthru_softc {
	struct usb_hci *hci; /* hci structure for issue xhci interrupt */
	pthread_mutex_t mtx; /* mutex for locking */
	unsigned long vid;   /* product vid */
	unsigned long pid;   /* product pid */
	struct libusb_device_handle *handle; /* libusb handler */
	libusb_hotplug_callback_handle cb;   /* callback handler */
	struct usb_passthru_ep_types endpoint_types[32];
	LIST_ENTRY(usb_passthru_softc) next;
};

struct usb_passthru_libusb_xfer {
	struct libusb_transfer *lusb_xfer;
	struct usb_data_xfer *usb_xfer;
	struct usb_passthru_softc *sc;
	uint8_t *buffer;
	bool in;
	int epid;
	int size;
};

static LIST_HEAD(, usb_passthru_softc) devices = LIST_HEAD_INITIALIZER(
    &devices);

static int usb_passthru_remove(void *scarg);
static pthread_t libusb_thread = NULL;
static int event_thread_exit = false;

static int
libusb_error_to_usb_error(enum libusb_error error)
{
	switch (error) {
	case LIBUSB_SUCCESS:
		return (USB_ERR_NORMAL_COMPLETION);
	case LIBUSB_ERROR_IO:
		return (USB_ERR_IOERROR);
	case LIBUSB_ERROR_INVALID_PARAM:
		return (USB_ERR_INVAL);
	case LIBUSB_ERROR_ACCESS:
		return (USB_ERR_INVAL);
	case LIBUSB_ERROR_NO_DEVICE:
		return (USB_ERR_NOT_CONFIGURED);
	case LIBUSB_ERROR_NOT_FOUND:
		return (USB_ERR_STALLED);
	case LIBUSB_ERROR_BUSY:
		return (USB_ERR_IN_USE);
	case LIBUSB_ERROR_TIMEOUT:
		return (USB_ERR_TIMEOUT);
	case LIBUSB_ERROR_OVERFLOW:
		return (USB_ERR_BAD_BUFSIZE);
	case LIBUSB_ERROR_PIPE:
		return (USB_ERR_NO_PIPE);
	case LIBUSB_ERROR_INTERRUPTED:
		return (USB_ERR_INTERRUPTED);
	case LIBUSB_ERROR_NO_MEM:
		return (USB_ERR_NOMEM);
	case LIBUSB_ERROR_NOT_SUPPORTED:
		return (USB_ERR_INVAL);
	case LIBUSB_ERROR_OTHER:
		return (USB_ERR_INVAL);
	}
}

static void *
libusb_pull_thread(void *arg __unused)
{
	struct timeval tv;
	int err;

	DPRINTF(("start libusb pullthread"));
	while (!event_thread_exit) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		err = libusb_handle_events_timeout(NULL, &tv);
		if (err && err != LIBUSB_ERROR_TIMEOUT)
			break;
	}

	DPRINTF(("stop libusb pullthread"));
	return (NULL);
}

static void
usb_passthru_calculate_xfer_ptr(struct usb_data_xfer *xfer, int *head,
    int *tail, int *size)
{
	int cur, i;
	int first = -1, length = 0;
	struct usb_data_xfer_block *blk;

	for (i = 0, cur = xfer->head; i < xfer->ndata;
	    ++i, cur = (cur + 1) % USB_MAX_XFER_BLOCKS) {
		blk = &xfer->data[cur];
		if (blk->processed)
			continue;
		switch (blk->status) {
		case USB_NEXT_DATA:
		case USB_LAST_DATA:
			first = first == -1 ? cur : first;
			length += blk->blen;
			break;
		case USB_NO_DATA:
			blk->processed = 1;
			continue;
		}

		if (blk->status == USB_LAST_DATA)
			break;
	}
	*head = first;
	*tail = i;
	*size = length;
}

static void
usb_passthru_data_calculate_num_isos(struct usb_data_xfer *xfer, int *head,
    int *nframe, int *len)
{
	int i, cur, first = -1, nf = 0, length = 0;

	for (i = 0, cur = xfer->head; i < xfer->ndata;
	    i = (i + 1) % USB_MAX_XFER_BLOCKS) {
		if (xfer->data[i].processed)
			continue;
		switch (xfer->data[i].status) {
		case USB_LAST_DATA:
			++nf;
			if (first == -1)
				first = i;
		/* Fallthrough */
		case USB_NEXT_DATA:
			length += xfer->data[i].blen;
			break;
		default:
			break;
		}
	}

	*nframe = nf;
	*head = first;
	*len = length;
}

static struct usb_passthru_libusb_xfer *
usb_passthru_xfer_alloc(struct usb_passthru_softc *sc, int in,
    struct usb_data_xfer *usb_xfer, int size, int ep, int iso)
{
	struct usb_passthru_libusb_xfer *xfer = calloc(1,
	    sizeof(struct usb_passthru_libusb_xfer));
	xfer->lusb_xfer = libusb_alloc_transfer(iso);
	xfer->usb_xfer = usb_xfer;
	xfer->buffer = calloc(1, size);
	xfer->size = size;
	xfer->in = in;
	xfer->sc = sc;
	xfer->epid = ep;
	return (xfer);
}

static void
usb_passthru_xfer_free(struct usb_passthru_libusb_xfer *xfer)
{
	free(xfer);
}

static int
usb_passthru_guest_attach_device(struct usb_passthru_softc *sc)
{
	struct libusb_config_descriptor *desc;
	struct libusb_device *dev;
	struct libusb_device_handle *handle;
	int intf, res;

	handle = sc->handle;
	dev = libusb_get_device(handle);
	res = libusb_get_active_config_descriptor(dev, &desc);
	if (res != LIBUSB_SUCCESS)
		goto done;

	for (intf = 0; intf < desc->bNumInterfaces; ++intf) {
		res = libusb_detach_kernel_driver(handle, intf);
		if (res != LIBUSB_SUCCESS)
			break;
		res = libusb_claim_interface(handle, intf);
		if (res != LIBUSB_SUCCESS)
			break;
	}

	libusb_free_config_descriptor(desc);
done:
	return (libusb_error_to_usb_error(res));
}

static int
usb_passthru_guest_detach_device_on_host(struct usb_passthru_softc *sc)
{
	struct libusb_config_descriptor *desc;
	struct libusb_device *dev;
	struct libusb_device_handle *handle;
	int intf, res;

	handle = sc->handle;
	if (handle == NULL)
		return (libusb_error_to_usb_error(LIBUSB_SUCCESS));
	dev = libusb_get_device(handle);

	res = libusb_get_active_config_descriptor(dev, &desc);
	if (res != LIBUSB_SUCCESS)
		return (libusb_error_to_usb_error(res));

	for (intf = 0; intf < desc->bNumInterfaces; ++intf) {
		res = libusb_release_interface(handle, intf);
		if (res != LIBUSB_SUCCESS)
			break;
		res = libusb_attach_kernel_driver(handle, intf);
		if (res != LIBUSB_SUCCESS)
			break;
	}

	libusb_free_config_descriptor(desc);

	return (libusb_error_to_usb_error(res));
}

static int
usb_passthru_guest_detach_device(struct usb_passthru_softc *sc __unused)
{
	return (USB_ERR_NORMAL_COMPLETION);
}

static int
usb_passthru_hotplug_callback(struct libusb_context *ctx __unused,
    struct libusb_device *dev, libusb_hotplug_event event, void *user_data)
{
	struct usb_passthru_softc *sc = user_data;
	int err = 0;

	DPRINTF(("%s: enter hotplug handler event: %d", __func__, event));

	pthread_mutex_lock(&sc->mtx);

	if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
		assert(sc->hci->hci_event(sc->hci, USBDEV_REMOVE, sc) == 0);
		libusb_close(sc->handle);
		sc->handle = NULL;
	} else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
		if (sc->handle != NULL)
			goto done;
		err = libusb_open(dev, &sc->handle);
		if (err)
			goto done;
		if ((err = usb_passthru_guest_attach_device(sc)) !=
		    LIBUSB_SUCCESS)
			goto done;
		assert(sc->hci->hci_event(sc->hci, USBDEV_ATTACH, sc) == 0);
	}

done:
	pthread_mutex_unlock(&sc->mtx);

	return (err);
}

static void
usb_passthru_data_callback(struct libusb_transfer *lusb_xfer)
{
	struct usb_passthru_libusb_xfer *up_xfer = lusb_xfer->user_data;
	struct usb_data_xfer *uxfer = up_xfer->usb_xfer;
	struct usb_passthru_softc *sc = up_xfer->sc;
	struct usb_hci *hci = sc->hci;
	int act_len = lusb_xfer->actual_length;
	int head, tail, size, cur_len, cur, offset, nframe;
	char *buffer;
	int cur_iso = 0, i;

	/*
	 * uxfer == NULL means the guest is cancelled by guest
	 * like machine shutdown.
	 */
	if (lusb_xfer->status == LIBUSB_TRANSFER_CANCELLED && uxfer == NULL) {
		usb_passthru_xfer_free(up_xfer);
		return;
	}

	USB_DATA_XFER_LOCK(uxfer);

	if (lusb_xfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
		usb_passthru_data_calculate_num_isos(uxfer, &head, &nframe,
		    &size);
	else
		usb_passthru_calculate_xfer_ptr(uxfer, &head, &tail, &size);

	if (lusb_xfer->status == LIBUSB_TRANSFER_STALL ||
	    lusb_xfer->status == LIBUSB_TRANSFER_NO_DEVICE ||
	    lusb_xfer->status == LIBUSB_TRANSFER_CANCELLED) {
		USB_DATA_SET_ERRCODE(&uxfer->data[head], USB_STALL);
		goto done;
	}

	DPRINTF(("%s: act_len: %d blen:%d in:%d epid:%d status: %d", __func__,
	    act_len, size, up_xfer->in, up_xfer->epid, lusb_xfer->status));

	if (up_xfer->in) {
		if (lusb_xfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
			act_len = lusb_xfer->iso_packet_desc[0].actual_length;

		if (act_len > size)
			act_len = size;

		for (cur = head, offset = 0, i = 0; i < uxfer->ndata;
		    cur = (cur + 1) % USB_MAX_XFER_BLOCKS, ++i) {
			cur_len = uxfer->data[cur].blen;
			if (cur_len > act_len) {
				cur_len = act_len;
				USB_DATA_SET_ERRCODE(&uxfer->data[cur],
				    USB_SHORT);
			}
			if (lusb_xfer->type != LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
				buffer = &lusb_xfer->buffer[offset];
			else
				buffer = libusb_get_iso_packet_buffer_simple(
					     lusb_xfer, cur_iso) +
				    offset;
			printf("%s %d %d\n", __func__, act_len, size);
			if (cur_len)
				memcpy(uxfer->data[cur].buf, buffer, cur_len);
			act_len -= cur_len;
			offset += cur_len;
			if (act_len <= 0 &&
			    lusb_xfer->type ==
				LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
				++cur_iso;
				act_len = lusb_xfer->iso_packet_desc[cur_iso]
					      .actual_length;
				offset = 0;
			}
			uxfer->data[cur].blen -= cur_len;
			uxfer->data[cur].bdone = cur_len;
			uxfer->data[cur].processed = 1;
		}
	} else {
		for (cur = head; uxfer->data[cur].buf;
		    cur = (cur + 1) % USB_MAX_XFER_BLOCKS)
			uxfer->data[cur].processed = 1;

		USB_DATA_SET_ERRCODE(&uxfer->data[head],
		    lusb_xfer->status == LIBUSB_TRANSFER_COMPLETED ?
			USB_ERR_NORMAL_COMPLETION :
			USB_ERR_IOERROR);
	}

done:
	uxfer->tr_softc = NULL;
	USB_DATA_XFER_UNLOCK(up_xfer->usb_xfer);
	hci->hci_intr(hci, up_xfer->epid);
	usb_passthru_xfer_free(up_xfer);
}

static void
usb_passthru_exit(void)
{
	struct usb_passthru_softc *sc, *tmp;

	LIST_FOREACH_SAFE(sc, &devices, next, tmp) {
		usb_passthru_remove(sc);
		free(sc);
	}

	event_thread_exit = true;
}

static void *
usb_passthru_probe(struct usb_hci *hci, const nvlist_t *nvl)
{
	struct usb_passthru_softc *sc;
	struct libusb_device_descriptor dev_desc;
	struct libusb_device *dev;
	struct libusb_init_option opts[] = {
		{ .option = LIBUSB_OPTION_CAPSICUMIZE }
	};
	const char *param;
	int error;

	if (!libusb_is_init) {
		libusb_is_init = true;
		error = libusb_init_context(NULL, opts,
		    sizeof(opts) / sizeof(struct libusb_init_option));
		if (error) {
			EPRINTLN("failed to capsicumize libusb");
			return (NULL);
		}
	}
	sc = calloc(1, sizeof(struct usb_passthru_softc));

	param = get_config_value_node(nvl, "param1");
	if (param == NULL) {
		free(sc);
		return (NULL);
	}
	sc->vid = strtoul(param, NULL, 16);
	param = get_config_value_node(nvl, "param2");
	if (param == NULL) {
		free(sc);
		return (NULL);
	}
	sc->pid = strtoul(param, NULL, 16);

	sc->hci = hci;
	sc->handle = libusb_open_device_with_vid_pid(NULL, sc->vid, sc->pid);
	if (sc->handle == NULL) {
		EPRINTLN("failed to open usb device with %0lx %0lx", sc->vid,
		    sc->pid);
		free(sc);
		return (NULL);
	}
	dev = libusb_get_device(sc->handle);
	if (libusb_get_device_descriptor(dev, &dev_desc) != LIBUSB_SUCCESS) {
		EPRINTLN("failed to get usb device descriptor with %0lx %0lx",
		    sc->vid, sc->pid);
		free(sc);
		return (NULL);
	}
	if (dev_desc.bcdUSB >= 0x0300) {
		hci->hci_usbver = 3;
	} else {
		hci->hci_usbver = 2;
	}
	memset(sc->endpoint_types, -1, sizeof(sc->endpoint_types));

	return (sc);
}

static int
usb_passthru_init(void *scarg)
{
	struct usb_passthru_softc *sc = (struct usb_passthru_softc *)scarg;
	struct usb_hci *hci;
	enum libusb_speed speed;
	int error;

	hci = sc->hci;
	pthread_mutex_init(&sc->mtx, NULL);

	speed = libusb_get_device_speed(libusb_get_device(sc->handle));
	switch (speed) {
	case LIBUSB_SPEED_LOW:
		hci->hci_speed = 2;
		break;
	case LIBUSB_SPEED_FULL:
		hci->hci_speed = 1;
		break;
	case LIBUSB_SPEED_HIGH:
		hci->hci_speed = 3;
		break;
	default:
		break;
	}

	if ((error = usb_passthru_guest_attach_device(sc)) != LIBUSB_SUCCESS)
		goto failed;

	error = libusb_hotplug_register_callback(NULL,
	    LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
		LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
	    0, sc->vid, sc->pid, LIBUSB_HOTPLUG_MATCH_ANY,
	    usb_passthru_hotplug_callback, (void *)sc, &sc->cb);
	if (error != LIBUSB_SUCCESS) {
		EPRINTLN("failed to create callback for usb device %s",
		    libusb_error_name(error));
		goto failed;
	}

	if (libusb_thread == NULL) {
		error = pthread_create(&libusb_thread, NULL, libusb_pull_thread,
		    NULL);
		if (error)
			goto failed;
	}

	LIST_INSERT_HEAD(&devices, sc, next);
	atexit(usb_passthru_exit);

	return (error);

failed:
	usb_passthru_remove(&sc);
	pthread_mutex_destroy(&sc->mtx);
	free(sc);
	return (1);
}

#define	UREQ(x,y)	((x) | ((y) << 8))

static int
usb_passthru_request(void *scarg, struct usb_data_xfer *xfer)
{
	struct usb_passthru_softc *sc = scarg;
	struct usb_data_xfer_block *data;
	int i, cur, err, value, index, len;

	data = NULL;
	cur = xfer->head;
	err = USB_ERR_NORMAL_COMPLETION;

	for (i = 0; i < xfer->ndata; i++) {
		xfer->data[cur].bdone = 0;
		if (data == NULL && USB_DATA_OK(xfer, i)) {
			data = &xfer->data[cur];
		}
		xfer->data[cur].processed = 1;
		cur = (cur + 1) % USB_MAX_XFER_BLOCKS;
	}

	if (!xfer->ureq) {
		DPRINTF(("usb_passthru_request not found: port %d",
		    sc->hci->hci_port));
		goto done;
	}

	value = UGETW(xfer->ureq->wValue);
	index = UGETW(xfer->ureq->wIndex);
	len = UGETW(xfer->ureq->wLength);
	if (data == NULL && len != 0) {
		err = LIBUSB_ERROR_NO_DEVICE;
		goto done;
	}

	pthread_mutex_lock(&sc->mtx);

	if (sc->handle == NULL) {
		err = LIBUSB_ERROR_INVALID_PARAM;
		goto done_locked;
	}

	switch (UREQ(xfer->ureq->bRequest, xfer->ureq->bmRequestType)) {
	case UREQ(UR_SET_ADDRESS, UT_WRITE_DEVICE):
		err = 0;
		goto done_locked;
	case UREQ(UR_SET_CONFIG, UT_WRITE_DEVICE):
		err = usb_passthru_guest_detach_device_on_host(sc);
		if (err)
			goto done_locked;
		err = libusb_set_configuration(sc->handle, value & 0xff);
		if (err)
			goto done_locked;
		err = usb_passthru_guest_attach_device(sc);
		if (err)
			goto done_locked;
		goto done_locked;
	case UREQ(UR_SET_INTERFACE, UT_WRITE_INTERFACE):
		err = libusb_set_interface_alt_setting(sc->handle, index,
		    value);
		goto done_locked;
	case UREQ(UR_CLEAR_FEATURE, UT_WRITE_ENDPOINT):
		err = libusb_clear_halt(sc->handle, index);
		goto done_locked;
	}

	if (data) {
		data->blen = len;
		data->bdone = 0;
	}
	DPRINTF((
	    "usb_passthru_request: bRequest: %x bmRequestType: %x wValue: %x wIndex: %d wLength: %x",
	    xfer->ureq->bRequest, xfer->ureq->bmRequestType, value, index,
	    len));

	err = libusb_control_transfer(sc->handle, xfer->ureq->bmRequestType,
	    xfer->ureq->bRequest, UGETW(xfer->ureq->wValue),
	    UGETW(xfer->ureq->wIndex), data ? data->buf : NULL, len, 1000);

	if (err < 0) {
		if (err == LIBUSB_ERROR_INTERRUPTED ||
		    err == LIBUSB_ERROR_PIPE) {
			if (data)
				USB_DATA_SET_ERRCODE(data, USB_STALL);
			err = LIBUSB_ERROR_NOT_FOUND;
		} else {
			if (data)
				USB_DATA_SET_ERRCODE(data, USB_ERR);
			err = LIBUSB_ERROR_NOT_FOUND;
		}
		goto done_locked;
	}
	if (data) {
		data->blen -= err;
		data->bdone = err;
	}
	err = 0;

done_locked:
	pthread_mutex_unlock(&sc->mtx);
done:
	err = libusb_error_to_usb_error(err);

	if (xfer->ureq && (xfer->ureq->bmRequestType & UT_WRITE) &&
	    (err == USB_ERR_NORMAL_COMPLETION) && (data != NULL))
		data->blen = 0;

	DPRINTF(("usb_passthru request error code %d (0=ok), blen %u txlen %u",
	    err, (data ? data->blen : 0), (data ? data->bdone : 0)));

	return (err);
}

static void
usb_passthru_data_fill_xfer_iso(struct usb_data_xfer *xfer,
    struct libusb_transfer *lusb_xfer)
{
	int i, cur, idx;

	for (i = 0, cur = xfer->head, idx = 0; i < xfer->ndata;
	    i = (i + 1) % USB_MAX_XFER_BLOCKS) {
		if (xfer->data[cur].status == USB_LAST_DATA) {
			lusb_xfer->iso_packet_desc[idx].length +=
			    xfer->data[cur].blen;
		} else if (xfer->data[cur].status == USB_NEXT_DATA) {
			lusb_xfer->iso_packet_desc[idx].length +=
			    xfer->data[cur].blen;
			continue;
		} else {
			continue;
		}
		++idx;
	}
}

static int
usb_passthru_data_handler(void *scarg, struct usb_data_xfer *xfer, int dir,
    int epctx)
{
	struct usb_passthru_softc *sc = scarg;
	struct usb_passthru_libusb_xfer *up_xfer;
	int err, cur, len, ep, head, tail, offset, ep_type, nframe;

	ep_type = sc->endpoint_types[epctx << 1 | dir].type;
	dir = sc->endpoint_types[epctx << 1 | dir].inout;
	assert(ep_type != -1);

	err = USB_ERR_NORMAL_COMPLETION;
	ep = (dir ? LIBUSB_ENDPOINT_IN : 0) | epctx;

	if (ep_type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
		usb_passthru_data_calculate_num_isos(xfer, &head, &nframe,
		    &len);
	else
		usb_passthru_calculate_xfer_ptr(xfer, &head, &tail, &len);

	if (len == 0)
		goto done;

	DPRINTF((
	    "usb_passthru handle data - DIR=%s|EP=%d, blen %d, transfer_type: %d, ndata: %d",
	    dir ? "IN" : "OUT", epctx, len,
	    sc->endpoint_types[epctx << 1 | dir].type, xfer->ndata));

	pthread_mutex_lock(&sc->mtx);
	if (sc->handle == NULL || xfer->tr_softc)
		goto done_locked;
	pthread_mutex_unlock(&sc->mtx);

	up_xfer = usb_passthru_xfer_alloc(sc, dir, xfer, len, ep,
	    ep_type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS ? nframe : 0);

	if (ep_type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
		usb_passthru_data_fill_xfer_iso(xfer, up_xfer->lusb_xfer);

	if (!dir) {
		for (cur = head, offset = 0; offset < len;
		    cur = (cur + 1) % USB_MAX_XFER_BLOCKS) {
			memcpy(&up_xfer->buffer[offset], xfer->data[cur].buf,
			    xfer->data[cur].blen);
			offset += xfer->data[cur].blen;
			xfer->data[cur].bdone = xfer->data[cur].blen = 0;
			xfer->data[cur].blen = 0;
		}
	}

	pthread_mutex_lock(&sc->mtx);
	switch (ep_type) {
	case LIBUSB_TRANSFER_TYPE_BULK:
		libusb_fill_bulk_transfer(up_xfer->lusb_xfer, sc->handle, ep,
		    up_xfer->buffer, len, usb_passthru_data_callback, up_xfer,
		    0);
		break;
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		libusb_fill_interrupt_transfer(up_xfer->lusb_xfer, sc->handle,
		    ep, up_xfer->buffer, len, usb_passthru_data_callback,
		    up_xfer, 0);
		break;
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		libusb_fill_iso_transfer(up_xfer->lusb_xfer, sc->handle, ep,
		    up_xfer->buffer, len, nframe, usb_passthru_data_callback,
		    up_xfer, 0);
		break;
	}
	up_xfer->lusb_xfer->flags = LIBUSB_TRANSFER_FREE_TRANSFER |
	    LIBUSB_TRANSFER_FREE_BUFFER;
	err = libusb_submit_transfer(up_xfer->lusb_xfer);
	if (err)
		goto done_locked;
	xfer->tr_softc = up_xfer;
done_locked:
	pthread_mutex_unlock(&sc->mtx);
done:
	return (libusb_error_to_usb_error(err));
}

static int
usb_passthru_reset(void *scarg __unused)
{
	struct usb_passthru_softc *sc = scarg;
	int err = 0;

	DPRINTF(("%s", __FUNCTION__));

	pthread_mutex_lock(&sc->mtx);

	if (sc->handle) {
		err = libusb_reset_device(sc->handle);
		if (err != LIBUSB_SUCCESS)
			goto done;
		err = usb_passthru_guest_attach_device(sc);
	}
done:
	pthread_mutex_unlock(&sc->mtx);
	return (libusb_error_to_usb_error(err));
}

static int
usb_passthru_remove(void *scarg)
{
	struct usb_passthru_softc *sc = scarg;
	int err;
	if (sc == NULL)
		return (USB_ERR_NORMAL_COMPLETION);

	LIST_REMOVE(sc, next);
	pthread_mutex_lock(&sc->mtx);
	err = usb_passthru_guest_detach_device(sc);
	if (err)
		goto done;
	libusb_hotplug_deregister_callback(NULL, sc->cb);
	if ((err = usb_passthru_guest_detach_device_on_host(sc)) !=
	    LIBUSB_SUCCESS) {
		goto done;
	}
	libusb_close(sc->handle);

done:
	pthread_mutex_unlock(&sc->mtx);

	return (err);
}

static int
usb_passthru_stop(void *scarg __unused)
{
	return (0);
}

static int
usb_passthru_configure_ep(void *scarg, int epid, struct xhci_endp_ctx *ctx,
    int configure)
{
	struct usb_passthru_softc *sc = scarg;
	int type;

	if (configure) {
		type = XHCI_EPCTX_1_EPTYPE_GET(ctx->dwEpCtx1);
		sc->endpoint_types[epid].inout = type >= 5;
		type &= 3;
		sc->endpoint_types[epid].type = type;
	} else {
		sc->endpoint_types[epid].inout = sc->endpoint_types[epid].type =
		    -1;
	}

	return (0);
}

static int
usb_passthru_cancel(struct usb_data_xfer *xfer)
{
	struct usb_passthru_libusb_xfer *up_xfer;
	int err;

	up_xfer = xfer->tr_softc;
	if (up_xfer == NULL) {
		return (0);
	}
	up_xfer->usb_xfer = NULL;

	DPRINTF(("%s", __FUNCTION__));

	err = libusb_cancel_transfer(up_xfer->lusb_xfer);
	xfer->tr_softc = NULL;

	return (libusb_error_to_usb_error(err));
}

static struct usb_devemu ue_passthru = {
	.ue_emu = "passthru",
	.ue_static = 0,
	.ue_usbver = 3,
	.ue_usbspeed = USB_SPEED_HIGH,
	.ue_probe = usb_passthru_probe,
	.ue_init = usb_passthru_init,
	.ue_request = usb_passthru_request,
	.ue_data = usb_passthru_data_handler,
	.ue_reset = usb_passthru_reset,
	.ue_remove = usb_passthru_remove,
	.ue_stop = usb_passthru_stop,
	.ue_cancel = usb_passthru_cancel,
	.ue_configure_ep = usb_passthru_configure_ep,
#ifdef BHYVE_SNAPSHOT
	.ue_snapshot = usb_passthru_snapshot,
#endif
};

USB_EMUL_SET(ue_passthru);
