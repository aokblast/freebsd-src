#ifndef _MACHINE_CFI_H
#define _MACHINE_CFI_H

#include <sys/types.h>

#include <machine/proc.h>
#include <machine/reg.h>

bool decode_cfi_frame(struct trapframe *, uintptr_t *, uint32_t *);
void post_cfi(struct trapframe *);

#endif
