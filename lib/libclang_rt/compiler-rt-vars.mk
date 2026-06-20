# Resource-dir paths (CLANG_SUBDIR, CLANGDIR, SANITIZER_LIBDIR, CRTARCH) are
# shared with the compiler_rt libname mapping in bsd.libnames.mk.
.include <clang-rt.mk>

.if ${COMPILER_TYPE} == "clang"
# The only way to set the path to the sanitizer libraries with clang is to
# override the resource directory.
# Note: lib/freebsd is automatically appended to the -resource-dir value.
SANITIZER_LDFLAGS+=	-resource-dir=${SYSROOT}${CLANGDIR}
# Also set RPATH to ensure that the dynamically linked runtime libs are found.
SANITIZER_LDFLAGS+=	-Wl,--enable-new-dtags
SANITIZER_LDFLAGS+=	-Wl,-rpath,${SANITIZER_LIBDIR}
.elif ${COMPILER_TYPE} != "none"
# This file can be included with COMPILER_TYPE=none during the cleandir phase,
# only emit an error when trying to compile with an unsupported compiler such
# as GCC.
.error "Unknown link flags for -fsanitize=... COMPILER_TYPE=${COMPILER_TYPE}"
.endif
