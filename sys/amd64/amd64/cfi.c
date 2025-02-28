#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <machine/cfi.h>
#include <machine/cpu.h>
#include <machine/frame.h>

static int
regoff(int reg)
{
#define _MATCH_REG(i, reg) \
	case i:            \
		return (   \
		    offsetof(struct trapframe, tf_##reg) / sizeof(register_t))
	switch (reg) {
		_MATCH_REG(0, rax);
		_MATCH_REG(1, rcx);
		_MATCH_REG(2, rdx);
		_MATCH_REG(3, rbx);
		_MATCH_REG(4, rsp); /* SIB when mod != 3 */
		_MATCH_REG(5, rbp);
		_MATCH_REG(6, rsi);
		_MATCH_REG(7, rdi);
		_MATCH_REG(8, r8); /* REX.R is set */
		_MATCH_REG(9, r9);
		_MATCH_REG(10, r10);
		_MATCH_REG(11, r11);
		_MATCH_REG(12, r12);
		_MATCH_REG(13, r13);
		_MATCH_REG(14, r14);
		_MATCH_REG(15, r15);
	}
#undef _MATCH_REG
	return (0);
}

bool
decode_cfi_frame(struct trapframe *tf, uintptr_t *callee_addr, uint32_t *type)
{
	unsigned char buffer[13];

	memcpy(buffer, (unsigned char *)(tf->tf_rip - 12), sizeof(buffer));
	/*
	 * clang generates following instructions:
	 *
	 * mov $typeid, %reg
	 * add $callee-16, %reg
	 * je .Lcorrect
	 * ud2
	 * .Lcorrect
	 *
	 * What we do is to compare if the previous context is trigger by
	 * mov(0xba) and following with one add(0x03), if it is, we can
	 * identified it maybe CFI fault
	 */

	if (buffer[1] != 0xba)
		return (false);

	if (buffer[7] != 0x03)
		return (false);

	*type = *((uint32_t *)(buffer + 2));

	// Decode register(prefix & REX.R) | (MODRM.rm(3bit))
	*callee_addr = ((register_t *)tf)[regoff(
	    (((buffer[6] >> 2) & 0x1) << 3) | (buffer[8] & 0x7))];
	return (true);
}

void
post_cfi(struct trapframe *frame)
{
	TRAPF_PC(frame) += 2;
}
