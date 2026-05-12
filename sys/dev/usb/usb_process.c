/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2008 Hans Petter Selasky. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef USB_GLOBAL_INCLUDE_FILE
#include USB_GLOBAL_INCLUDE_FILE
#else
#include <sys/stdint.h>
#include <sys/stddef.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>
#include <sys/unistd.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/priv.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usb_process.h>

#define	USB_DEBUG_VAR usb_proc_debug
#include <dev/usb/usb_debug.h>
#include <dev/usb/usb_util.h>

#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/sched.h>
#endif			/* USB_GLOBAL_INCLUDE_FILE */

static int usb_pcount;

#define	USB_THREAD_SUSPEND_CHECK() kthread_suspend_check()
#define	USB_THREAD_SUSPEND(p)   kthread_suspend(p,0)
#define	USB_THREAD_EXIT(err)	kthread_exit()

#ifdef USB_DEBUG
static int usb_proc_debug;

static SYSCTL_NODE(_hw_usb, OID_AUTO, proc, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "USB process");
SYSCTL_INT(_hw_usb_proc, OID_AUTO, debug, CTLFLAG_RWTUN, &usb_proc_debug, 0,
    "Debug level");
#endif

/*------------------------------------------------------------------------*
 *	usb_proc_create
 *
 * This function will create a process using the given "prio" that can
 * execute callbacks. The mutex pointed to by "p_mtx" will be applied
 * before calling the callbacks and released after that the callback
 * has returned. The structure pointed to by "up" is assumed to be
 * zeroed before this function is called.
 *
 * Return values:
 *    0: success
 * Else: failure
 *------------------------------------------------------------------------*/
int
usb_proc_create(struct usb_process *up, struct mtx *p_mtx,
    const char *pmesg, uint8_t prio)
{
	up->up_mtx = p_mtx;
	if ((up->tq = taskqueue_create(pmesg, M_WAITOK,
	    &taskqueue_thread_enqueue, &up->tq)) == NULL) {
		DPRINTFN(0, "Unable to create taskqueue");
		goto error;
	}
	if (taskqueue_start_threads(&up->tq, 1, prio, "%s taskq", pmesg) != 0) {
		DPRINTFN(0, "Unable to create USB process.");
		goto error;
	}

	usb_pcount++;
	return (0);

error:
	usb_proc_free(up);
	return (ENOMEM);
}

/*------------------------------------------------------------------------*
 *	usb_proc_free
 *
 * NOTE: If the structure pointed to by "up" is all zero, this
 * function does nothing.
 *
 * NOTE: Messages that are pending on the process queue will not be
 * removed nor called.
 *------------------------------------------------------------------------*/
void
usb_proc_free(struct usb_process *up)
{
	if (up->tq == NULL)
		return;
	taskqueue_drain_all(up->tq);
	taskqueue_free(up->tq);
	up->tq = NULL;
	usb_pcount--;
}

/*------------------------------------------------------------------------*
 *	usb_proc_msignal
 *
 * This function will queue one of the passed USB process messages on
 * the USB process queue. The first message that is not already queued
 * will get queued. If both messages are already queued the one queued
 * last will be removed from the queue and queued in the end. The USB
 * process mutex must be locked when calling this function. This
 * function exploits the fact that a process can only do one callback
 * at a time. The message that was queued is returned.
 *------------------------------------------------------------------------*/
void
usb_proc_msignal(struct usb_process *up, struct usb_proc_msg *msg)
{
	taskqueue_enqueue(up->tq, &msg->task);
}

int
usb_proc_msignal_pending(struct usb_process *up, struct usb_proc_msg *msg)
{
	return (taskqueue_enqueue_flags(up->tq, &msg->task,
	    TASKQUEUE_FAIL_IF_PENDING));
}

/*------------------------------------------------------------------------*
 *	usb_proc_is_gone
 *
 * Return values:
 *    0: USB process is running
 * Else: USB process is tearing down
 *------------------------------------------------------------------------*/
uint8_t
usb_proc_is_gone(struct usb_process *up)
{
	if (up->up_mtx != NULL)
		USB_MTX_ASSERT(up->up_mtx, MA_OWNED);
	return (up->tq == NULL);
}

/*------------------------------------------------------------------------*
 *	usb_proc_mwait
 *
 * This function will return when the USB process message pointed to
 * by "pm" is no longer on a queue.
 *------------------------------------------------------------------------*/
void
usb_proc_mwait(struct usb_process *up, struct usb_proc_msg *msg)
{
	taskqueue_drain(up->tq, &msg->task);
}

/*------------------------------------------------------------------------*
 *	usb_proc_drain
 *
 * This function will tear down an USB process, waiting for the
 * currently executing command to return.
 *
 * NOTE: If the structure pointed to by "up" is all zero,
 * this function does nothing.
 *------------------------------------------------------------------------*/
void
usb_proc_drain(struct usb_process *up)
{
	taskqueue_drain_all(up->tq);
}

/*------------------------------------------------------------------------*
 *	usb_proc_rewakeup
 *
 * This function is called to re-wakeup the given USB
 * process. This usually happens after that the USB system has been in
 * polling mode, like during a panic. This function must be called
 * having "up->up_mtx" locked.
 *------------------------------------------------------------------------*/
void
usb_proc_rewakeup(struct usb_process *up)
{
	if (up->tq == NULL)
		return;
	taskqueue_unblock(up->tq);
}
