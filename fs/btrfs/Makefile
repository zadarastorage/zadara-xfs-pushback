
obj-$(CONFIG_BTRFS_FS) := btrfs.o

btrfs-y += super.o ctree.o extent-tree.o print-tree.o root-tree.o dir-item.o \
	   file-item.o inode-item.o inode-map.o disk-io.o \
	   transaction.o inode.o file.o tree-defrag.o \
	   extent_map.o sysfs.o struct-funcs.o xattr.o ordered-data.o \
	   extent_io.o volumes.o async-thread.o ioctl.o locking.o orphan.o \
	   export.o tree-log.o free-space-cache.o zlib.o lzo.o \
	   compression.o delayed-ref.o relocation.o delayed-inode.o scrub.o \
	   reada.o backref.o ulist.o qgroup.o send.o dev-replace.o raid56.o \
	   uuid-tree.o props.o hash.o

btrfs-$(CONFIG_BTRFS_FS_POSIX_ACL) += acl.o
btrfs-$(CONFIG_BTRFS_FS_CHECK_INTEGRITY) += check-integrity.o

btrfs-$(CONFIG_BTRFS_FS_RUN_SANITY_TESTS) += tests/free-space-tests.o \
	tests/extent-buffer-tests.o tests/btrfs-tests.o \
	tests/extent-io-tests.o tests/inode-tests.o tests/qgroup-tests.o

####### Zadara ##############
ifeq ($(CONFIG_BTRFS_FS_RUN_SANITY_TESTS),y)
ccflags-y += -DCONFIG_BTRFS_FS_RUN_SANITY_TESTS
endif

ifeq ($(CONFIG_ZADARA),y)
KBUILD_EXTRA_SYMBOLS := $(src)/../../drivers/zadara/Module.symvers
ccflags-y += -I$(src)/../../drivers/zadara
ccflags-y += -Wall                      # Enable most warning messages
ccflags-y += -g
ccflags-y += -DCONFIG_BTRFS_ZADARA
ccflags-y += -DCONFIG_BTRFS_ASSERT

btrfs-y += zbtrfs.o zstats.o
btrfs-y += zbtrfs-control.o
btrfs-y += zbtrfs-block-virt.o
btrfs-y += ztenant-tree.o
btrfs-y += zchanged-chunks.o
btrfs-y += zjournal.o          \
           zjournal_mount.o    \
           zjournal_open.o     \
           zjournal_pool.o     \
           zjournal_replay.o   \
           zjournal_write.o

btrfs-$(CONFIG_BTRFS_FS_RUN_SANITY_TESTS) += tests/ztenant-tests.o tests/zjournal-tests.o

endif

