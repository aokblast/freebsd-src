.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/tools/ctf/common
.PATH: ${SRCTOP}/cddl/contrib/opensolaris/tools/ctf/cvt

PACKAGE=	ctf-tools
PROG=		ctfdiff	
SRCS=		main.c \
			binary_extract.c \
			diff.c \
			ctf.c

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR} \
		-I${OPENSOLARIS_SYS_DISTDIR} \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/tools/ctf/common \
		-I${OPENSOLARIS_USR_DISTDIR}/tools/ctf/cvt \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common
CFLAGS+= -DHAVE_ISSETUGID 

LIBADD=		spl dwarf elf z pthread

# HAS_TESTS=
# SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
