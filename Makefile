# simple makefile, installs to $PWD/run

CRITFLAGS =	-I${.CURDIR}/libmowgli-2/run/include -L${.CURDIR}/libmowgli-2/run/lib -lmowgli-2 -g
PREFIX = 	${.CURDIR}/run
MOWGLI_PREFIX =	${.CURDIR}/libmowgli-2/run

dl-mowgli:
	git submodule init
	git submodule update

cfg-mowgli:
	@
