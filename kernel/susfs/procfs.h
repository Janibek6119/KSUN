#ifndef __KSU_H_SUSFS_PROCFS
#define __KSU_H_SUSFS_PROCFS

#include <linux/types.h>
#include <linux/uaccess.h>

int ksu_susfs_procfs_init(void);
void ksu_susfs_procfs_exit(void);

bool ksu_susfs_handle_mount_compat(void __user *arg);
bool ksu_susfs_handle_cmdline_compat(void __user *arg);
bool ksu_susfs_handle_uname_compat(void __user *arg);
bool ksu_susfs_handle_avc_compat(void __user *arg);
void ksu_susfs_handle_setuid(uid_t old_uid, uid_t new_uid);

#endif // __KSU_H_SUSFS_PROCFS
