#
# Makefile for the Zadara tools kernel module
#

ifneq ($(CONFIG_ZADARA),y)
$(error zadara-utils should be built only when CONFIG_ZADARA is enabled.)
endif

ccflags-y += -Wall 			# Enable most warning messages
ccflags-y += -Werror		# Error out the compiler on warnings
ccflags-y += -g

obj-m += zadara-utils.o

zadara-utils-objs := zutils.o zbio.o zklog.o zkmsg.o zchrdev.o
