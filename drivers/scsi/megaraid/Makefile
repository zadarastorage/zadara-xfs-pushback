ccflags-y := -DCONFIG_MEGASAS_ZADARA
EXTRA_CFLAGS=-I/usr/local/include -g

obj-$(CONFIG_MEGARAID_MM)	+= megaraid_mm.o
obj-$(CONFIG_MEGARAID_MAILBOX)	+= megaraid_mbox.o
obj-$(CONFIG_MEGARAID_SAS)	+= megaraid_sas.o
megaraid_sas-objs := megaraid_sas_base.o megaraid_sas_fusion.o \
	megaraid_sas_fp.o
