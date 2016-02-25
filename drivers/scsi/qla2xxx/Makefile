#
#  Qlogic 2x00 SCSI driver makefile
#
#  Copyright (C) 2015 SanDisk Corporation
#  Copyright (C) 2015 QLogic Corporation
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation, version 2
#  of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#
# Main targets:
#    all (the default) : make all
#    all-local 		: make all out-of-tree
#    clean             : clean files
#    extraclean        : clean + clean dependencies
#    install           : install 
#    uninstall         : uninstall 
#
# Notes :
#    - install and uninstall must be made as root
#



# BUILD_2X_MODULE := y set to build out of tree

ifeq ($(BUILD_2X_MODULE),)

qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o qla_bsg.o \
		qla_nx.o qla_mr.o qla_nx2.o qla_tmpl.o qla_sriov.o


obj-$(CONFIG_SCSI_QLA_FC) += qla2xxx.o

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend *~ Modules.symvers \
		Module.symvers Module.markers modules.order
	rm -rf .tmp_versions

extraclean: clean
	rm -f *.orig *.rej

.PHONY: clean extraclean

else
######### BEGIN OUT-OF-TREE RULES #########

SHELL=/bin/bash

KMOD := $(shell pwd)/kernel

enable-Wextra = $(shell uname_r="$$(uname -r)"; if [ "$${uname_r%.el5}" = "$${uname_r}" ]; then echo "$(1)"; fi)

EXTRA_CFLAGS += $(call enable-Wextra,-Wextra -Wno-unused-parameter \
	-Wno-missing-field-initializers -g)

ifneq ($(CONFIG_SCSI_QLA2XXX_TARGET),)
EXTRA_CFLAGS += -DCONFIG_SCSI_QLA2XXX_TARGET=$(CONFIG_SCSI_QLA2XXX_TARGET)
endif

ifeq ($(KVER),)
  ifeq ($(KDIR),)
    KVER := $(shell uname -r)
    KDIR := /lib/modules/$(KVER)/build
  else
    KVER := $(strip $(shell						\
	cat $(KDIR)/include/config/kernel.release 2>/dev/null ||	\
	make -s -C $(KDIR) kernelversion))
  endif
else
  KDIR := /lib/modules/$(KVER)/build
endif

ifeq ($(INSTALL_MOD_PATH),)
  export INSTALL_MOD_PATH := $(DESTDIR)
endif

INSTALL_DIR := $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/extra

ifneq ($(PATCHLEVEL),)
obj-m := qla2xxx_scst.o
qla2xxx_scst-objs := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o qla_bsg.o \
		qla_nx.o qla_mr.o qla_nx2.o qla_tmpl.o qla_sriov.o
else

all:
	@echo "qla: all"
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

all-local:
	@echo "qla: all out-of-tree"
	$(MAKE) BUILD_2X_MODULE=$(BUILD_2X_MODULE) CONFIG_SCSI_QLA2XXX_TARGET=y  -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m

UDEV_RULE_DIR=/etc/udev/rules.d
UDEV_RULE_FILE=99-qla2xxx.rules
UDEV_SCRIPT_DIR=/lib/udev
UDEV_SCRIPT=qla2xxx_udev.sh

udev_install:
	@echo "qla2xxx_scst -- Installing udev rule to capture FW dump..."
	@cp ./extras/$(UDEV_RULE_FILE) $(UDEV_RULE_DIR)/$(UDEV_RULE_FILE)
	@cp ./extras/$(UDEV_SCRIPT) $(UDEV_SCRIPT_DIR)/$(UDEV_SCRIPT)
	@udevadm control --reload-rules

udev_remove:
	@echo "qla2xxx_scst -- Removing FW capture udev rule..."
	@rm -f $(UDEV_RULE_DIR)/$(UDEV_RULE_FILE)
	@rm -f $(UDEV_SCRIPT_DIR)/$(UDEV_SCRIPT)
	@udevadm control --reload-rules

install: all
	@echo "qla: install"
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) BUILD_INI=m \
		$$([ -n "$(DESTDIR)$(INSTALL_MOD_PATH)" ] && echo DEPMOD=true) \
		modules_install
	$(MAKE) udev_install

uninstall:
	rm -f $(INSTALL_DIR)/qla2xxx_scst.ko
	-/sbin/depmod -b $(INSTALL_MOD_PATH)/ -a $(KVER)
	$(MAKE) udev_remove

########## END OUT-OF-TREE RULES ##########
endif

clean:
	@$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) clean
	@$(RM) tags Modules.symvers module.symvers Module.markers modules.order

extraclean: clean
	rm -f *.orig *.rej

.PHONY: all tgt install uninstall clean extraclean

endif

release-archive:
	../scripts/generate-release-archive qla2x00t "$$(sed -n 's/^#define[[:blank:]]Q2T_VERSION_STRING[[:blank:]]*\"\([^\"]*\)\".*/\1/p' qla2x00-target/qla2x00t.h)"

ifeq ($(CONFIG_ZADARA),y)

install_extras:
	@install -v -d -o root -g root -m 755 $(PKG_ROOT_DIR)/etc/modprobe.d
	@install -v -d -o root -g root -m 755 $(PKG_ROOT_DIR)/lib/udev/rules.d
	@install -v -d -o root -g root -m 755 $(PKG_ROOT_DIR)/usr/sbin
	@install -v -D -o root -g root -m 644 ./extras/qla2xxx.conf     $(PKG_ROOT_DIR)/etc/modprobe.d
	@install -v -D -o root -g root -m 644 ./extras/99-qla2xxx.rules $(PKG_ROOT_DIR)/lib/udev/rules.d
	@install -v -D -o root -g root -m 755 ./extras/qla2xxx_udev.sh  $(PKG_ROOT_DIR)/lib/udev
	@install -v -D -o root -g root -m 755 ./extras/qla_dmp.sh       $(PKG_ROOT_DIR)/usr/sbin
	#TEMP: install debug firmware
	@install -v -d -o root -g root -m 755 $(PKG_ROOT_DIR)/lib/firmware
	@install -v -D -o root -g root -m 644 ./extras/ql2700_fw.bin $(PKG_ROOT_DIR)/lib/firmware

ccflags-y += -DCONFIG_QLA2XXX_ZADARA
ccflags-y += -Wall -g

endif

