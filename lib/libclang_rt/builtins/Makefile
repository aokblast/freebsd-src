.include <bsd.init.mk>

# The compiler-rt builtins library, installed under the clang resource
# directory using the upstream LLVM naming convention so that the clang
# driver's default -rtlib=compiler-rt finds it natively.  The gcc-style names
# libcompiler_rt.a and libgcc.a are installed as symlinks to this archive (see
# SYMLINKS below) so that explicit -lcompiler_rt / -lgcc linkage keeps working;
# the clang driver does not assume FreeBSD uses clang_rt.builtins for those.
#
# bsd.init.mk pulls in ../Makefile.inc (and compiler-rt-vars.mk), which sets
# CRTARCH to the clang runtime arch suffix and LIBDIR to the sanitizer/resource
# library directory.  Capture that suffix now, because the shared builtins
# source list below redefines CRTARCH to match the builtins source tree layout.
CLANGRT_ARCH:=	${CRTARCH}
LIB=		clang_rt.builtins-${CLANGRT_ARCH}

# builtins-specific flags.
CFLAGS+=	-fvisibility=hidden
CFLAGS+=	-DVISIBILITY_HIDDEN
CFLAGS+=	-I${SRCTOP}/contrib/llvm-project/libunwind/include

# gcc has incompatible internal declarations for __divtc3 and __multc3, but has
# no option to silence its warning, so make warnings non-fatal.
MK_WERROR.gcc=	no

# List of compiler-rt builtins sources.  This redefines CRTARCH/CRTSRC to point
# at the builtins source tree.
.include "${.CURDIR}/builtins.mk"

# Out-of-line LSE atomics helpers for aarch64
.if ${MACHINE_CPUARCH} == "aarch64"
. for pat in cas swp ldadd ldclr ldeor ldset
.  for size in 1 2 4 8 16
.   for model in 1 2 3 4 5
.    if ${pat} == "cas" || ${size} != "16"
# Use .for to define lse_name, to get a special loop-local variable
.     for lse_name in outline_atomic_${pat}${size}_${model}.S
CLEANFILES+=	${lse_name}
STATICOBJS+=	${lse_name:R}.o
ACFLAGS.${lse_name}+= -DL_${pat} -DSIZE=${size} -DMODEL=${model} -I${CRTSRC}
${lse_name}: lse.S
	ln -sf ${.ALLSRC} ${.TARGET}
.     endfor # lse_name
.    endif
.   endfor # model
.  endfor # size
. endfor # pat
.endif

# Install the gcc-compatible names (libcompiler_rt.a, libgcc.a) as symlinks in
# the default library path so that -lcompiler_rt and -lgcc resolve to this
# builtins archive.
#
# The archive always lands in the clang resource directory (SANITIZER_LIBDIR,
# /usr/lib/clang/<ver>/lib/freebsd) for both the native and the lib32 compat
# build: the libclang_rt Makefile.inc sets LIBDIR= explicitly, which overrides
# the compat LIB32WMAKEENV LIBDIR=/usr/lib32.  The symlinks themselves go into
# LIBDIR_BASE, which is /usr/lib natively and /usr/libNN for compat.  Both are
# children of /usr, so a "../<resource-relative-to-/usr>" target resolves to the
# archive from either /usr/lib or /usr/lib32.
.if ${MK_INSTALLLIB} != "no"
_BUILTINS_SYMLINK=	../${SANITIZER_LIBDIR:S,^/usr/,,}/lib${LIB}.a
SYMLINKS+=	${_BUILTINS_SYMLINK} ${LIBDIR_BASE}/libcompiler_rt.a
SYMLINKS+=	${_BUILTINS_SYMLINK} ${LIBDIR_BASE}/libgcc.a
.endif

.include <bsd.lib.mk>
