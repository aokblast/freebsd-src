/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005 Nate Lawson
 * Copyright (c) 2004 Colin Percival
 * Copyright (c) 2004-2005 Bruno Durcot
 * Copyright (c) 2004 FUKUDA Nobuhiko
 * Copyright (c) 2009 Michael Reifenberger
 * Copyright (c) 2009 Norikatsu Shigemura
 * Copyright (c) 2008-2009 Gen Otsuji
 *
 * This code is depending on kern_cpu.c, est.c, powernow.c, p4tcc.c, smist.c
 * in various parts. The authors of these files are Nate Lawson,
 * Colin Percival, Bruno Durcot, and FUKUDA Nobuhiko.
 * This code contains patches by Michael Reifenberger and Norikatsu Shigemura.
 * Thank you.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * For more info:
 * BIOS and Kernel Developer's Guide(BKDG) for AMD Family 10h Processors
 * 31116 Rev 3.20  February 04, 2009
 * BIOS and Kernel Developer's Guide(BKDG) for AMD Family 11h Processors
 * 41256 Rev 3.00 - July 07, 2008
 * Processor Programming Reference (PPR) for AMD Family 1Ah Model 02h,
 * Revision C1 Processors Volume 1 of 7 - Sep 29, 2024
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/sched.h>

#include <machine/md_var.h>
#include <machine/cputypes.h>
#include <machine/specialreg.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>

#include "acpi_if.h"
#include "cpufreq_if.h"

#define	MSR_AMD_10H_11H_LIMIT	0xc0010061
#define	MSR_AMD_10H_11H_CONTROL	0xc0010062
#define	MSR_AMD_10H_11H_STATUS	0xc0010063
#define	MSR_AMD_10H_11H_CONFIG	0xc0010064

#define	MSR_AMD_CPPC_CAPS_1	0xc00102b0
#define	MSR_AMD_CPPC_ENABLE	0xc00102b1
#define	MSR_AMD_CPPC_CAPS_2	0xc00102b2
#define	MSR_AMD_CPPC_REQUEST	0xc00102b3
#define	MSR_AMD_CPPC_STATUS	0xc00102b4

#define	MSR_AMD_PWR_ACC		0xc001007a
#define	MSR_AMD_PWR_ACC_MX	0xc001007b

#define	AMD_10H_11H_MAX_STATES	16

/* for MSR_AMD_10H_11H_LIMIT C001_0061 */
#define	AMD_10H_11H_GET_PSTATE_MAX_VAL(msr)	(((msr) >> 4) & 0x7)
#define	AMD_10H_11H_GET_PSTATE_LIMIT(msr)	(((msr)) & 0x7)
/* for MSR_AMD_10H_11H_CONFIG 10h:C001_0064:68 / 11h:C001_0064:6B */
#define	AMD_10H_11H_CUR_VID(msr)		(((msr) >> 9) & 0x7F)
#define	AMD_10H_11H_CUR_DID(msr)		(((msr) >> 6) & 0x07)
#define	AMD_10H_11H_CUR_FID(msr)		((msr) & 0x3F)

#define	AMD_17H_CUR_IDIV(msr)			(((msr) >> 30) & 0x03)
#define	AMD_17H_CUR_IDD(msr)			(((msr) >> 22) & 0xFF)
#define	AMD_17H_CUR_VID(msr)			(((msr) >> 14) & 0xFF)
#define	AMD_17H_CUR_DID(msr)			(((msr) >> 8) & 0x3F)
#define	AMD_17H_CUR_FID(msr)			((msr) & 0xFF)

#define	AMD_1AH_CUR_FID(msr)			((msr) & 0xFFF)

#define	AMD_CPPC_LOW_PERF(msr)			((msr >> 0) & 0xFF)
#define	AMD_CPPC_LOW_NONLIN_PERF(msr)		((msr >> 8) & 0xFF)
#define	AMD_CPPC_NOMINAL_PERF(msr)		((msr >> 16) & 0xFF)
#define	AMD_CPPC_HIGH_PERF(msr)			((msr >> 24) & 0xFF)

#define	AMD_CPPC_ENERGY_PERF_BITS		0xff000000
#define	AMD_CPPC_DES_PERF_BITS			0x00ff0000
#define	AMD_CPPC_MIN_PERF_BITS			0x0000ff00
#define	AMD_CPPC_MAX_PERF_BITS			0x000000ff

#define	HWPSTATE_DEBUG(dev, msg...)			\
	do {						\
		if (hwpstate_verbose)			\
			device_printf(dev, msg);	\
	} while (0)

struct hwpstate_setting {
	int	freq;		/* CPU clock in Mhz or 100ths of a percent. */
	int	volts;		/* Voltage in mV. */
	int	power;		/* Power consumed in mW. */
	int	lat;		/* Transition latency in us. */
	int	pstate_id;	/* P-State id */
};

struct hwpstate_cppc_setting {
	uint8_t high;
	uint8_t guaranteed;
	uint8_t efficient;
	uint8_t low;
};

struct hwpstate_softc {
	device_t		dev;
	union {
		struct hwpstate_setting
		    hwpstate_settings[AMD_10H_11H_MAX_STATES];
		struct hwpstate_cppc_setting cppc_settings;
	};
	int			cfnum;
	bool cppc;
	bool pwr_calc;
	uint64_t req;
};

static void	hwpstate_identify(driver_t *driver, device_t parent);
static int	hwpstate_probe(device_t dev);
static int	hwpstate_attach(device_t dev);
static int	hwpstate_detach(device_t dev);
static int	hwpstate_set(device_t dev, const struct cf_setting *cf);
static int	hwpstate_get(device_t dev, struct cf_setting *cf);
static int	hwpstate_settings(device_t dev, struct cf_setting *sets, int *count);
static int	hwpstate_type(device_t dev, int *type);
static int	hwpstate_shutdown(device_t dev);
static int	hwpstate_features(driver_t *driver, u_int *features);
static int	hwpstate_get_info_from_acpi_perf(device_t dev, device_t perf_dev);
static int	hwpstate_get_info_from_msr(device_t dev);
static int	hwpstate_goto_pstate(device_t dev, int pstate_id);

static int	hwpstate_verbose;
SYSCTL_INT(_debug, OID_AUTO, hwpstate_verbose, CTLFLAG_RWTUN,
    &hwpstate_verbose, 0, "Debug hwpstate");

static int	hwpstate_verify;
SYSCTL_INT(_debug, OID_AUTO, hwpstate_verify, CTLFLAG_RWTUN,
    &hwpstate_verify, 0, "Verify P-state after setting");

static bool	hwpstate_pstate_limit;
SYSCTL_BOOL(_debug, OID_AUTO, hwpstate_pstate_limit, CTLFLAG_RWTUN,
    &hwpstate_pstate_limit, 0,
    "If enabled (1), limit administrative control of P-states to the value in "
    "CurPstateLimit");

static device_method_t hwpstate_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	hwpstate_identify),
	DEVMETHOD(device_probe,		hwpstate_probe),
	DEVMETHOD(device_attach,	hwpstate_attach),
	DEVMETHOD(device_detach,	hwpstate_detach),
	DEVMETHOD(device_shutdown,	hwpstate_shutdown),

	/* cpufreq interface */
	DEVMETHOD(cpufreq_drv_set,	hwpstate_set),
	DEVMETHOD(cpufreq_drv_get,	hwpstate_get),
	DEVMETHOD(cpufreq_drv_settings,	hwpstate_settings),
	DEVMETHOD(cpufreq_drv_type,	hwpstate_type),

	/* ACPI interface */
	DEVMETHOD(acpi_get_features,	hwpstate_features),
	{0, 0}
};

static driver_t hwpstate_driver = {
	"hwpstate",
	hwpstate_methods,
	sizeof(struct hwpstate_softc),
};

DRIVER_MODULE(hwpstate, cpu, hwpstate_driver, 0, 0);

static int
hwpstate_amd_iscale(int val, int div)
{
	switch (div) {
	case 3: /* divide by 1000 */
		val /= 10;
	case 2: /* divide by 100 */
		val /= 10;
	case 1: /* divide by 10 */
		val /= 10;
	case 0: /* divide by 1 */
	    ;
	}

	return (val);
}

/*
 * Go to Px-state on all cpus, considering the limit register (if so
 * configured).
 */
static int
hwpstate_goto_pstate(device_t dev, int id)
{
	sbintime_t sbt;
	uint64_t msr;
	int cpu, i, j, limit;

	if (hwpstate_pstate_limit) {
		/* get the current pstate limit */
		msr = rdmsr(MSR_AMD_10H_11H_LIMIT);
		limit = AMD_10H_11H_GET_PSTATE_LIMIT(msr);
		if (limit > id) {
			HWPSTATE_DEBUG(dev, "Restricting requested P%d to P%d "
			    "due to HW limit\n", id, limit);
			id = limit;
		}
	}

	cpu = curcpu;
	HWPSTATE_DEBUG(dev, "setting P%d-state on cpu%d\n", id, cpu);
	/* Go To Px-state */
	wrmsr(MSR_AMD_10H_11H_CONTROL, id);

	/*
	 * We are going to the same Px-state on all cpus.
	 * Probably should take _PSD into account.
	 */
	CPU_FOREACH(i) {
		if (i == cpu)
			continue;

		/* Bind to each cpu. */
		thread_lock(curthread);
		sched_bind(curthread, i);
		thread_unlock(curthread);
		HWPSTATE_DEBUG(dev, "setting P%d-state on cpu%d\n", id, i);
		/* Go To Px-state */
		wrmsr(MSR_AMD_10H_11H_CONTROL, id);
	}

	/*
	 * Verify whether each core is in the requested P-state.
	 */
	if (hwpstate_verify) {
		CPU_FOREACH(i) {
			thread_lock(curthread);
			sched_bind(curthread, i);
			thread_unlock(curthread);
			/* wait loop (100*100 usec is enough ?) */
			for (j = 0; j < 100; j++) {
				/* get the result. not assure msr=id */
				msr = rdmsr(MSR_AMD_10H_11H_STATUS);
				if (msr == id)
					break;
				sbt = SBT_1MS / 10;
				tsleep_sbt(dev, PZERO, "pstate_goto", sbt,
				    sbt >> tc_precexp, 0);
			}
			HWPSTATE_DEBUG(dev, "result: P%d-state on cpu%d\n",
			    (int)msr, i);
			if (msr != id) {
				HWPSTATE_DEBUG(dev,
				    "error: loop is not enough.\n");
				return (ENXIO);
			}
		}
	}

	return (0);
}

static int
hwpstate_set(device_t dev, const struct cf_setting *cf)
{
	struct hwpstate_softc *sc;
	struct hwpstate_setting *set;
	int i;

	if (cf == NULL)
		return (EINVAL);
	sc = device_get_softc(dev);
	if (sc->cppc)
		return (EOPNOTSUPP);
	set = sc->hwpstate_settings;
	for (i = 0; i < sc->cfnum; i++)
		if (CPUFREQ_CMP(cf->freq, set[i].freq))
			break;
	if (i == sc->cfnum)
		return (EINVAL);

	return (hwpstate_goto_pstate(dev, set[i].pstate_id));
}

static int
hwpstate_calc_power(struct hwpstate_softc *sc)
{
	device_t dev;
	struct pcpu *pc;
	uint64_t jx, tx, jy, ty, jmax, jdelta;
	register_t reg;

	dev = sc->dev;
	pc = cpu_get_pcpu(dev);

	thread_lock(curthread);
	sched_bind(curthread, pc->pc_cpuid);
	thread_unlock(curthread);

	reg = intr_disable();
	jx = rdmsr(MSR_AMD_PWR_ACC);
	tx = rdtsc();
	DELAY(1000);
	jy = rdmsr(MSR_AMD_PWR_ACC);
	ty = rdtsc();
	jmax = rdmsr(MSR_AMD_PWR_ACC_MX);
	intr_restore(reg);
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);

	if (jy < jx)
		jdelta = jy + jmax - jx;
	else
		jdelta = jy - jx;

	return amd_pwrsamplerate * jdelta / (ty - tx);
}

static int
hwpstate_get(device_t dev, struct cf_setting *cf)
{
	struct hwpstate_softc *sc;
	struct hwpstate_setting set;
	struct pcpu *pc;
	uint64_t msr;
	uint64_t rate;
	int ret;

	sc = device_get_softc(dev);
	if (cf == NULL)
		return (EINVAL);

	if (sc->cppc) {
		pc = cpu_get_pcpu(dev);
		if (pc == NULL)
			return (ENXIO);

		memset(cf, CPUFREQ_VAL_UNKNOWN, sizeof(*cf));
		cf->dev = dev;
		if ((ret = cpu_est_clockrate(pc->pc_cpuid, &rate)))
			return (ret);
		cf->freq = rate / 1000000;
		if (sc->pwr_calc)
			cf->power = hwpstate_calc_power(sc);
		return (0);
	}

	msr = rdmsr(MSR_AMD_10H_11H_STATUS);
	if (msr >= sc->cfnum)
		return (EINVAL);
	set = sc->hwpstate_settings[msr];

	cf->freq = set.freq;
	cf->volts = set.volts;
	cf->power = set.power;
	cf->lat = set.lat;
	cf->dev = dev;

	return (0);
}

static int
hwpstate_settings(device_t dev, struct cf_setting *sets, int *count)
{
	struct hwpstate_softc *sc;
	struct hwpstate_setting set;
	int i;

	if (sets == NULL || count == NULL)
		return (EINVAL);
	sc = device_get_softc(dev);
	if (sc->cppc)
		return (EOPNOTSUPP);

	if (*count < sc->cfnum)
		return (E2BIG);
	for (i = 0; i < sc->cfnum; i++, sets++) {
		set = sc->hwpstate_settings[i];
		sets->freq = set.freq;
		sets->volts = set.volts;
		sets->power = set.power;
		sets->lat = set.lat;
		sets->dev = dev;
	}
	*count = sc->cfnum;

	return (0);
}

static int
hwpstate_type(device_t dev, int *type)
{
	struct hwpstate_softc *sc;

	if (type == NULL)
		return (EINVAL);
	sc = device_get_softc(dev);

	*type = CPUFREQ_TYPE_ABSOLUTE;
	*type |= sc->cppc ? CPUFREQ_FLAG_INFO_ONLY | CPUFREQ_FLAG_UNCACHED : 0;
	return (0);
}

static void
hwpstate_identify(driver_t *driver, device_t parent)
{

	if (device_find_child(parent, "hwpstate", -1) != NULL)
		return;

	if ((cpu_vendor_id != CPU_VENDOR_AMD || CPUID_TO_FAMILY(cpu_id) < 0x10) &&
	    cpu_vendor_id != CPU_VENDOR_HYGON)
		return;

	/*
	 * Check if hardware pstate enable bit is set.
	 */
	if ((amd_pminfo & AMDPM_HW_PSTATE) == 0) {
		HWPSTATE_DEBUG(parent, "hwpstate enable bit is not set.\n");
		return;
	}

	if (resource_disabled("hwpstate", 0))
		return;

	if (BUS_ADD_CHILD(parent, 10, "hwpstate", device_get_unit(parent))
	    == NULL)
		device_printf(parent, "hwpstate: add child failed\n");
}

static int
amd_set_autonomous_hwp(struct hwpstate_softc *sc)
{
	struct pcpu *pc;
	device_t dev;
	uint64_t caps;
	int ret;

	dev = sc->dev;
	pc = cpu_get_pcpu(dev);
	if (pc == NULL)
		return (ENXIO);

	thread_lock(curthread);
	sched_bind(curthread, pc->pc_cpuid);
	thread_unlock(curthread);

	ret = wrmsr_safe(MSR_AMD_CPPC_ENABLE, 1);
	if (ret) {
		device_printf(dev, "Failed to enable cppc for cpu%d (%d)\n",
		    pc->pc_cpuid, ret);
		goto out;
	}

	ret = rdmsr_safe(MSR_AMD_CPPC_REQUEST, &sc->req);
	if (ret) {
		device_printf(dev,
		    "Failed to read CPPC request MSR for cpu%d (%d)\n",
		    pc->pc_cpuid, ret);
		goto out;
	}

	ret = rdmsr_safe(MSR_AMD_CPPC_CAPS_1, &caps);
	if (ret) {
		device_printf(dev,
		    "Failed to read HWP capabilities MSR for cpu%d (%d)\n",
		    pc->pc_cpuid, ret);
		goto out;
	}
	sc->cppc_settings.high = AMD_CPPC_HIGH_PERF(caps);
	sc->cppc_settings.guaranteed = AMD_CPPC_NOMINAL_PERF(caps);
	sc->cppc_settings.efficient = AMD_CPPC_LOW_NONLIN_PERF(caps);
	sc->cppc_settings.low = AMD_CPPC_LOW_PERF(caps);

	/* enable autonomous mode by setting desired performance to 0 */
	sc->req &= ~AMD_CPPC_DES_PERF_BITS;

	sc->req &= ~AMD_CPPC_ENERGY_PERF_BITS;
	sc->req |= sc->cppc_settings.efficient << 24;

	sc->req &= ~AMD_CPPC_MIN_PERF_BITS;
	sc->req |= sc->cppc_settings.low << 8;

	sc->req &= ~AMD_CPPC_MAX_PERF_BITS;
	sc->req |= sc->cppc_settings.high;

	ret = wrmsr_safe(MSR_AMD_CPPC_REQUEST, sc->req);
	if (ret) {
		device_printf(dev,
		    "Failed to setup autonomous HWP for cpu%d\n",
		    pc->pc_cpuid);
		goto out;
	}
out:
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);

	if (!ret)
		device_set_desc(dev, "Cool`n'Quiet 2.0");

	return (ret ? ret : BUS_PROBE_NOWILDCARD);
}

static int
hwpstate_probe(device_t dev)
{
	struct hwpstate_softc *sc;
	device_t perf_dev;
	uint64_t msr;
	int error, type;

	sc = device_get_softc(dev);

	if (amd_extended_feature_extensions & AMDFEID_CPPC) {
		sc->cppc = true;
	} else {
		/*
		 * No CPPC support, failed back to ACPI or hwp so only contains
		 * hwpstate0.
		 */
		if (device_get_unit(dev) != 0)
			return (ENXIO);
	}

	if (amd_pminfo & AMDPM_PWR_REPORT)
		sc->pwr_calc = true;

	sc->dev = dev;
	if (sc->cppc)
		return amd_set_autonomous_hwp(sc);

	/*
	 * Check if acpi_perf has INFO only flag.
	 */
	perf_dev = device_find_child(device_get_parent(dev), "acpi_perf", -1);
	error = TRUE;
	if (perf_dev && device_is_attached(perf_dev)) {
		error = CPUFREQ_DRV_TYPE(perf_dev, &type);
		if (error == 0) {
			if ((type & CPUFREQ_FLAG_INFO_ONLY) == 0) {
				/*
				 * If acpi_perf doesn't have INFO_ONLY flag,
				 * it will take care of pstate transitions.
				 */
				HWPSTATE_DEBUG(dev, "acpi_perf will take care of pstate transitions.\n");
				return (ENXIO);
			} else {
				/*
				 * If acpi_perf has INFO_ONLY flag, (_PCT has FFixedHW)
				 * we can get _PSS info from acpi_perf
				 * without going into ACPI.
				 */
				HWPSTATE_DEBUG(dev, "going to fetch info from acpi_perf\n");
				error = hwpstate_get_info_from_acpi_perf(dev, perf_dev);
			}
		}
	}

	if (error == 0) {
		/*
		 * Now we get _PSS info from acpi_perf without error.
		 * Let's check it.
		 */
		msr = rdmsr(MSR_AMD_10H_11H_LIMIT);
		if (sc->cfnum != 1 + AMD_10H_11H_GET_PSTATE_MAX_VAL(msr)) {
			HWPSTATE_DEBUG(dev, "MSR (%jd) and ACPI _PSS (%d)"
			    " count mismatch\n", (intmax_t)msr, sc->cfnum);
			error = TRUE;
		}
	}

	/*
	 * If we cannot get info from acpi_perf,
	 * Let's get info from MSRs.
	 */
	if (error)
		error = hwpstate_get_info_from_msr(dev);
	if (error)
		return (error);

	device_set_desc(dev, "Cool`n'Quiet 2.0");
	return (0);
}

static int
hwpstate_attach(device_t dev)
{

	return (cpufreq_register(dev));
}

static int
hwpstate_get_info_from_msr(device_t dev)
{
	struct hwpstate_softc *sc;
	struct hwpstate_setting *hwpstate_set;
	uint64_t msr;
	int family, i, fid, did;

	family = CPUID_TO_FAMILY(cpu_id);
	sc = device_get_softc(dev);
	/* Get pstate count */
	msr = rdmsr(MSR_AMD_10H_11H_LIMIT);
	sc->cfnum = 1 + AMD_10H_11H_GET_PSTATE_MAX_VAL(msr);
	hwpstate_set = sc->hwpstate_settings;
	for (i = 0; i < sc->cfnum; i++) {
		msr = rdmsr(MSR_AMD_10H_11H_CONFIG + i);
		if ((msr & ((uint64_t)1 << 63)) == 0) {
			HWPSTATE_DEBUG(dev, "msr is not valid.\n");
			return (ENXIO);
		}
		did = AMD_10H_11H_CUR_DID(msr);
		fid = AMD_10H_11H_CUR_FID(msr);

		hwpstate_set[i].volts = CPUFREQ_VAL_UNKNOWN;
		hwpstate_set[i].power = CPUFREQ_VAL_UNKNOWN;
		hwpstate_set[i].lat = CPUFREQ_VAL_UNKNOWN;
		/* Convert fid/did to frequency. */
		switch (family) {
		case 0x11:
			hwpstate_set[i].freq = (100 * (fid + 0x08)) >> did;
			break;
		case 0x10:
		case 0x12:
		case 0x15:
		case 0x16:
			hwpstate_set[i].freq = (100 * (fid + 0x10)) >> did;
			break;
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1A:
			/* calculate freq */
			if (family == 0x1A) {
				fid = AMD_1AH_CUR_FID(msr);
				/* 1Ah CPU don't use a divisor */
				hwpstate_set[i].freq = fid;
				if (fid > 0x0f)
					hwpstate_set[i].freq *= 5;
				else {
					HWPSTATE_DEBUG(dev,
					    "unexpected fid: %d\n", fid);
					return (ENXIO);
				}
			} else {
				did = AMD_17H_CUR_DID(msr);
				if (did == 0) {
					HWPSTATE_DEBUG(dev,
					    "unexpected did: 0\n");
					did = 1;
				}
				fid = AMD_17H_CUR_FID(msr);
				hwpstate_set[i].freq = (200 * fid) / did;
			}

			/* Vid step is 6.25mV, so scale by 100. */
			hwpstate_set[i].volts =
			    (155000 - (625 * AMD_17H_CUR_VID(msr))) / 100;
			/*
			 * Calculate current first.
			 * This equation is mentioned in
			 * "BKDG for AMD Family 15h Models 70h-7fh Processors",
			 * section 2.5.2.1.6.
			 */
			hwpstate_set[i].power = AMD_17H_CUR_IDD(msr) * 1000;
			hwpstate_set[i].power = hwpstate_amd_iscale(
			    hwpstate_set[i].power, AMD_17H_CUR_IDIV(msr));
			hwpstate_set[i].power *= hwpstate_set[i].volts;
			/* Milli amps * milli volts to milli watts. */
			hwpstate_set[i].power /= 1000;
			break;
		default:
			HWPSTATE_DEBUG(dev, "get_info_from_msr: %s family"
			    " 0x%02x CPUs are not supported yet\n",
			    cpu_vendor_id == CPU_VENDOR_HYGON ? "Hygon" : "AMD",
			    family);
			return (ENXIO);
		}
		hwpstate_set[i].pstate_id = i;
	}
	return (0);
}

static int
hwpstate_get_info_from_acpi_perf(device_t dev, device_t perf_dev)
{
	struct hwpstate_softc *sc;
	struct cf_setting *perf_set;
	struct hwpstate_setting *hwpstate_set;
	int count, error, i;

	perf_set = malloc(MAX_SETTINGS * sizeof(*perf_set), M_TEMP, M_NOWAIT);
	if (perf_set == NULL) {
		HWPSTATE_DEBUG(dev, "nomem\n");
		return (ENOMEM);
	}
	/*
	 * Fetch settings from acpi_perf.
	 * Now it is attached, and has info only flag.
	 */
	count = MAX_SETTINGS;
	error = CPUFREQ_DRV_SETTINGS(perf_dev, perf_set, &count);
	if (error) {
		HWPSTATE_DEBUG(dev, "error: CPUFREQ_DRV_SETTINGS.\n");
		goto out;
	}
	sc = device_get_softc(dev);
	sc->cfnum = count;
	hwpstate_set = sc->hwpstate_settings;
	for (i = 0; i < count; i++) {
		if (i == perf_set[i].spec[0]) {
			hwpstate_set[i].pstate_id = i;
			hwpstate_set[i].freq = perf_set[i].freq;
			hwpstate_set[i].volts = perf_set[i].volts;
			hwpstate_set[i].power = perf_set[i].power;
			hwpstate_set[i].lat = perf_set[i].lat;
		} else {
			HWPSTATE_DEBUG(dev, "ACPI _PSS object mismatch.\n");
			error = ENXIO;
			goto out;
		}
	}
out:
	if (perf_set)
		free(perf_set, M_TEMP);
	return (error);
}

static int
hwpstate_detach(device_t dev)
{
	struct hwpstate_softc *sc;

	sc = device_get_softc(dev);
	if (!sc->cppc)
		hwpstate_goto_pstate(dev, 0);
	return (cpufreq_unregister(dev));
}

static int
hwpstate_shutdown(device_t dev)
{

	/* hwpstate_goto_pstate(dev, 0); */
	return (0);
}

static int
hwpstate_features(driver_t *driver, u_int *features)
{

	/* Notify the ACPI CPU that we support direct access to MSRs */
	*features = ACPI_CAP_PERF_MSRS;
	return (0);
}
