# Install the shared library in /lib (where the gcc-style libgcc_s.so.1 used to
# live); the static libunwind.a still installs to LIBDIR (/usr/lib) for link
# time.  Must be set before src.opts.mk, which otherwise defaults SHLIBDIR to
# LIBDIR.
SHLIBDIR?=	/lib

.include <src.opts.mk>

# The LLVM libunwind, built with the upstream naming so that the clang driver's
# default --rtlib=compiler-rt --unwindlib=libunwind finds it natively as
# -l:libunwind.a / -l:libunwind.so / -lunwind.  It also installs the static
# gcc-style name libgcc_eh.a as a symlink (replacing the removed lib/libgcc_eh);
# libunwind.a has the same objects the old libgcc_eh.a did.
#
# This library contains only the unwinder (no builtins).  The shared
# gcc-compatible libgcc_s.so.1 is a real DSO built from source in lib/libgcc_s
# (it bundles the builtins and exports the GCC_*/FBSD_* versioned symbols), so it
# is NOT provided here as a symlink.

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

# Install the static gcc-compatible name libgcc_eh.a as a symlink (replacing the
# removed lib/libgcc_eh), so -lgcc_eh resolves to libunwind.a.  The shared
# libgcc_s.so.1 is a real DSO from lib/libgcc_s, not a symlink.
.if ${MK_INSTALLLIB} != "no"
SYMLINKS+=	libunwind.a ${LIBDIR}/libgcc_eh.a
.endif

.include <bsd.lib.mk>
