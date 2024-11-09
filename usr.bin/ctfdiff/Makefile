.include <Makefile.inc>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/tools/ctf/common

PACKAGE=	ctf-tools
PROG_CXX=	ctfdiff
SRCS=		ctfdiff.cc \
		ctfdata.cc \
		ctftype.cc  \
		metadata.cc\
		utility.cc \

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+=	-I${OPENSOLARIS_USR_DISTDIR} \
		-I${OPENSOLARIS_SYS_DISTDIR} \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/cmd/mdb/tools/common \
		-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/tools/ctf/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common

CXXFLAGS+= -std=c++17
CFLAGS+= -DHAVE_ISSETUGID

LIBADD=		elf z

.include <bsd.prog.mk>
