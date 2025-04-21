PACKAGE=	bluetooth
CONFS=		rtlbtfw.conf
CONFSDIR=       /etc/devd
PROG=		rtlbtfw
MAN=		rtlbtfw.8
LIBADD+=	usb
SRCS=		main.c rtlbt_fw.c rtlbt_hw.c
CFLAGS+=	-DRTLBTFW_SUPPORTS_FW_V2

.include <bsd.prog.mk>
