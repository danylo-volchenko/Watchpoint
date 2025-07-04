SUMMARY = "Watchpoint Kernel Module"
DESCRIPTION = "A kernel module that sets a watchpoint on a specified memory address."
LICENSE = "GPL-3.0-or-later"
LIC_FILES_CHKSUM = "file://COPYING;md5=1ebbd3e34237af26da5dc08a4e440464"

SRC_URI = "file://src/watchpoint.c;subdir=files \
		   file://Makefile;subdir=files         \
		   file://COPYING;subdir=files"

S = "${WORKDIR}/files"

inherit module

EXTRA_OEMAKE = "KERNEL_SRC=${STAGING_KERNEL_DIR} KBUILD_EXTMOD=${S}"

do_compile() {
	unset CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
	oe_runmake
}

do_install() {
	install -d ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra
	install -m 0644 ${S}/watchpoint.ko ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra/
}

FILES_${PN} += "${base_libdir}/modules/${KERNEL_VERSION}/extra/watchpoint.ko"
