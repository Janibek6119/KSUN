#ifndef __KSU_SU_MOUNT_NS_H
#define __KSU_SU_MOUNT_NS_H

#include <linux/sched.h>
#include <linux/types.h>

#define KSU_NS_INHERITED 0
#define KSU_NS_GLOBAL 1
#define KSU_NS_INDIVIDUAL 2

struct ksu_mns_tw {
    struct callback_head cb;
    int32_t ns_mode;
};

void setup_mount_ns(int32_t ns_mode);
int ksu_join_task_mount_ns(struct task_struct *task);

#endif
