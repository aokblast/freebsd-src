# Locations and naming for the clang compiler-rt runtime installed under the
# clang resource directory: the builtins library (libclang_rt.builtins-${CRTARCH}.a,
# to which the compiler_rt libname resolves) and the sanitizer libraries.
#
# Keep CLANG_SUBDIR's version in sync with the clang version in
# lib/clang/include/clang/Basic/Version.inc.

.if !defined(_CLANG_RT_MK_)
_CLANG_RT_MK_=

CLANG_SUBDIR?=		clang/21
CLANGDIR?=		/usr/lib/${CLANG_SUBDIR}
SANITIZER_LIBDIR?=	${CLANGDIR}/lib/freebsd
SANITIZER_SHAREDIR?=	${CLANGDIR}/share

# The architecture suffix used by the clang runtime library names, e.g.
# libclang_rt.builtins-${CRTARCH}.a.  armv[67] is special since a soft-float
# variant is allowed via CPUTYPE matching *soft*.
.if ${MACHINE_CPUARCH} == "arm" && \
    (!defined(CPUTYPE) || ${CPUTYPE:M*soft*} == "")
CRTARCH?=	armhf
.else
CRTARCH?=	${MACHINE_ARCH:S/amd64/x86_64/}
.endif

.endif # !defined(_CLANG_RT_MK_)
