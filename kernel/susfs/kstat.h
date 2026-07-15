#ifndef __KSU_H_SUSFS_KSTAT
#define __KSU_H_SUSFS_KSTAT

#include <linux/types.h>
#include <linux/uaccess.h>

struct kstat;
struct path;

int ksu_susfs_kstat_init(void);
void ksu_susfs_kstat_exit(void);

bool ksu_susfs_handle_kstat_compat(unsigned int cmd, void __user *arg);
bool ksu_susfs_handle_sus_map_compat(void __user *arg);

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
void ksu_susfs_handle_vfs_getattr_nosec(const struct path *path,
					struct kstat *stat, long ret);
void ksu_susfs_set_getattr_ready(bool ready);
#endif

#endif // __KSU_H_SUSFS_KSTAT
