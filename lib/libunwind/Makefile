# Install the shared library in /lib (where the gcc-style libgcc_s.so.1 used to
# live); the static libunwind.a still installs to LIBDIR (/usr/lib) for link
# time.  Must be set before src.opts.mk, which otherwise defaults SHLIBDIR to
# LIBDIR.
SHLIBDIR?=	/lib

.include <src.opts.mk>

# The LLVM libunwind, built with the upstream naming so that the clang driver's
# default --rtlib=compiler-rt --unwindlib=libunwind finds it natively as
# -l:libunwind.a / -l:libunwind.so / -lunwind.  It also installs the gcc-style
# unwinder names libgcc_s.so.1 and libgcc_eh.a as symlinks (see SYMLINKS below),
# replacing the removed lib/libgcc_s and lib/libgcc_eh.
#
# This library contains only the unwinder (no builtins): in the clang model the
# builtins come from libclang_rt.builtins instead.  Note this drops the GCC_*
# versioned symbols the old from-source libgcc_s.so.1 exported.

PACKAGE=	clibs
LIB=		unwind
SHLIB_MAJOR=	1
MK_SSP=		no
WARNS?=		2

# Enabling UBSan triggers "undefined reference to vtable for
# __cxxabiv1::__function_type_info".
MK_UBSAN:=	no

# Build with hidden visibility so that only the libunwind public API (marked
# _LIBUNWIND_EXPORT) is exported, matching the upstream shared library.
CFLAGS+=	-fvisibility=hidden
CXXFLAGS+=	-fvisibility=hidden
CXXFLAGS+=	-fvisibility-inlines-hidden

# Provide a self-contained unwinder: link only libc and the builtins, not the
# gcc-style unwinder.
LDFLAGS+=	-nodefaultlibs
LDFLAGS+=	-Wl,-Bsymbolic
LIBADD+=	c
LIBADD+=	compiler_rt

SRCS_EXC+=	int_util.c
.include "${.CURDIR}/unwind.mk"

# Export the GCC personality routine from the shared library; it is otherwise
# hidden by -fvisibility=hidden.
CFLAGS.gcc_personality_v0.c+=	-fvisibility=default

# gcc has incompatible internal declarations for __divtc3 and __multc3, but has
# no option to silence its warning, so make warnings non-fatal.
MK_WERROR.gcc=	no

# Install the libunwind public headers (previously installed by lib/libgcc_eh);
# libc, libthr and others include <unwind.h>.
INCS+=		${UNWINDINCDIR}/__libunwind_config.h
INCS+=		${UNWINDINCDIR}/libunwind.h
INCS+=		${UNWINDINCDIR}/unwind.h
INCS+=		${UNWINDINCDIR}/unwind_arm_ehabi.h
INCS+=		${UNWINDINCDIR}/unwind_itanium.h

# Install the gcc-compatible unwinder names as symlinks: libgcc_eh.a (static)
# replaces lib/libgcc_eh, and libgcc_s.so.1 / libgcc_s.so (shared) replace
# lib/libgcc_s, so that -lgcc_eh / -lgcc_s and existing NEEDED libgcc_s.so.1
# binaries resolve to libunwind.
.if ${MK_INSTALLLIB} != "no"
SYMLINKS+=	libunwind.a ${LIBDIR}/libgcc_eh.a
.endif
.if !defined(NO_PIC)
SYMLINKS+=	libunwind.so.1 ${SHLIBDIR}/libgcc_s.so.1
SYMLINKS+=	libunwind.so ${LIBDIR}/libgcc_s.so
.endif

.include <bsd.lib.mk>
