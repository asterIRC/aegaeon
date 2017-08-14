# simple makefile, installs to $PWD/run

CRITFLAGS =	-I ${.CURDIR}/libmowgli-2/run/include -I ${.CURDIR}/src 
CRITFLAGS+=	-I ${.CURDIR}/include
CRITLDFLAGS =	 -L ${.CURDIR}/libmowgli-2/run/lib
PREFIX = 	${.CURDIR}/run
MOWGLI_PREFIX =	${.CURDIR}/libmowgli-2/run

dl-mowgli:
	git submodule init
	git submodule update

cfg-mowgli: dl-mowgli
	@echo Entering directory libmowgli-2...
	@(cd libmowgli-2 ; ./configure --prefix=${MOWGLI_PREFIX} --enable-static)

make-mowgli: cfg-mowgli
	@echo Running Mowgli build system and installer
	@(cd libmowgli-2; make; make install)

aegaeon-pkg:
	@echo "critcl::cflags ${CRITFLAGS}" > critflags.tcl
	@echo "critcl::cheaders ${MOWGLI_PREFIX}/include" >> critflags.tcl
	@echo "critcl::ldflags -L${MOWGLI_PREFIX}/lib ${MOWGLI_PREFIX}/lib/libmowgli-2.a" >> critflags.tcl
	critcl -debug all -force ${CRITFLAGS} ${CRITLDFLAGS} -pkg aegaeon src/aegaeon.tcl.c
