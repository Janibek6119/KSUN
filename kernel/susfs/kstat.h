#ifndef __KSU_H_SUSFS_KSTAT
#define __KSU_H_SUSFS_KSTAT

#include <linux/types.h>
#include <linux/uaccess.h>

int ksu_susfs_kstat_init(void);
void ksu_susfs_kstat_exit(void);

bool ksu_susfs_handle_kstat_compat(unsigned int cmd, void __user *arg);
bool ksu_susfs_handle_sus_map_compat(void __user *arg);

#endif // __KSU_H_SUSFS_KSTAT
