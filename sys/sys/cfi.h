#ifndef _SYS_CFI_H_
#define _SYS_CFI_H_

#include <sys/cdefs.h>
#include <sys/proc.h>

__BEGIN_DECLS
int
cfi_handler(struct trapframe *);
__END_DECLS

#endif
