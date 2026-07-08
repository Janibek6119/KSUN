#ifndef __KSU_H_SUSFS
#define __KSU_H_SUSFS

#include <linux/fs.h>
#include <linux/version.h>

#include "uapi/susfs.h"

#ifndef d_backing_inode
#define d_backing_inode(dentry) d_inode(dentry)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KSU_SUSFS_IDMAP_ARG struct mnt_idmap *idmap,
#define KSU_SUSFS_IDMAP_CALL idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KSU_SUSFS_IDMAP_ARG struct user_namespace *mnt_userns,
#define KSU_SUSFS_IDMAP_CALL mnt_userns,
#else
#define KSU_SUSFS_IDMAP_ARG
#define KSU_SUSFS_IDMAP_CALL
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define KSU_SUSFS_ACTOR_RET bool
#define KSU_SUSFS_ACTOR_CONTINUE true
#else
#define KSU_SUSFS_ACTOR_RET int
#define KSU_SUSFS_ACTOR_CONTINUE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define KSU_SUSFS_XATTR_FLAGS_ARG , int flags
#define KSU_SUSFS_XATTR_FLAGS_VAL , flags
#else
#define KSU_SUSFS_XATTR_FLAGS_ARG
#define KSU_SUSFS_XATTR_FLAGS_VAL
#endif

void ksu_susfs_init(void);
void ksu_susfs_exit(void);
bool ksu_susfs_handle_compat(unsigned int cmd, void __user *arg);
void ksu_susfs_apply_default_rules(void);
void ksu_susfs_handle_boot_completed(void);

#endif // __KSU_H_SUSFS
