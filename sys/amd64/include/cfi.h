#ifndef _MACHINE_CFI_H
#define _MACHINE_CFI_H

#include <sys/cdefs.h>

#include <sys/stdint.h>
#include <sys/types.h>

#include <machine/proc.h>


bool
decode_cfi(struct trapframe *, unsigned long *, uint32_t *);

#endif
