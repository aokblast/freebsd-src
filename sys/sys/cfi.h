/*
 */
#ifndef _SYS_CFI_H_
#define _SYS_CFI_H_

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/proc.h>

#ifdef KCFI
#define __NOCFI __attribute__((__no_sanitize__("kcfi")))
#else
#define __NOCFI
#endif

bool cfi_handler(struct trapframe *);

#endif /* _KERNEL */

#endif /* _SYS_CFI_H_ */
