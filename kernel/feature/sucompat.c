#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/ptrace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif

#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "compat/kernel_compat.h"

#ifdef CONFIG_KSU_MANUAL_HOOK
#include "feature/adb_root.h"
#else
#include "hook/syscall_hook.h"
#endif

#include "tiny_sulog.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the stack
	// pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
		int *mode, int *__unused_flags)
{
	const char su[] = SU_PATH;

	if (!ksu_su_compat_enabled) return 0;
    if (!ksu_is_allow_uid_for_current(current_uid().val)) return 0;
    if (unlikely(!filename_user || !*filename_user)) return 0;

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		write_sulog('a');
		pr_info("faccessat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	// const char sh[] = SH_PATH;
	const char su[] = SU_PATH;

	if (!ksu_su_compat_enabled) return 0;
    if (!ksu_is_allow_uid_for_current(current_uid().val)) return 0;
    if (unlikely(!filename_user || !*filename_user)) return 0;

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		write_sulog('s');
		pr_info("newfstatat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#ifdef CONFIG_KSU_KPROBES_HOOK
long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, const struct pt_regs *regs)
{
	const char su[] = SU_PATH;
	const char __user *fn;
	char path[sizeof(su) + 1];
	long ret;
	unsigned long addr;

	if (!ksu_su_compat_enabled) goto do_orig_execve;
    if (unlikely(!filename_user || !*filename_user)) goto do_orig_execve;
    if (!ksu_is_allow_uid_for_current(current_uid().val)) goto do_orig_execve;

	addr = untagged_addr((unsigned long)*filename_user);
	fn = (const char __user *)addr;
	memset(path, 0, sizeof(path));
	ret = strncpy_from_user(path, fn, sizeof(path));

	if (ret < 0) {
		pr_warn("Access filename when execve failed: %ld", ret);
		goto do_orig_execve;
	}

	if (likely(memcmp(path, su, sizeof(su))))
		goto do_orig_execve;

	write_sulog('x');

	pr_info("sys_execve su found\n");
	*filename_user = ksud_user_path();

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
		goto do_orig_execve;
	}

	ret = ksu_syscall_table[orig_nr](regs);
	if (ret < 0) {
		pr_err("failed to execve ksud as su: %ld, fallback to sh\n", ret);
		*filename_user = sh_user_path();
	} else {
		return ret;
	}

do_orig_execve:
	return ksu_syscall_table[orig_nr](regs);
}

#else // CONFIG_KSU_MANUAL_HOOK

extern bool ksud_execve_key;

static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, void *argv)
{
    struct path kpath;
    bool is_allowed = ksu_is_allow_uid_for_current(current_uid().val);

    if (!ksu_su_compat_enabled) return 0;
    if (!is_allowed) return 0;
    if (likely(memcmp(filename, SU_PATH, sizeof(SU_PATH)))) return 0;

    write_sulog('x');
    pr_info("do_execveat_common su found\n");
    escape_with_root_profile();

    if (kern_path(KSUD_PATH, LOOKUP_FOLLOW, &kpath)) {
        pr_info("sucompat: /data/adb/ksud not found, fallback to /system/bin/sh");
        memcpy((void *)filename, SH_PATH, sizeof(SH_PATH));
    } else {
        path_put(&kpath);
        memcpy((void *)filename, KSUD_PATH, sizeof(KSUD_PATH));
    }

    return 0;
}

int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags)
{
    if (current->pid != 1 && is_init(current_cred())) {
        if (unlikely(strcmp(filename, KSUD_PATH) == 0)) {
            pr_info("hook_manager: escape to root for init executing ksud\n");
            escape_to_root_for_init();
        }
        int ret = ksu_adb_root_handle_execve(filename, (struct user_arg_ptr *)envp);
        if (ret) pr_err("adb root failed: %d\n", ret);
    }

    if (unlikely(ksud_execve_key)) {
        ksu_handle_execveat_ksud(filename, argv);
    }

    if (current_uid().val == 0) {
        write_sulog('x');
    }

    return do_ksu_handle_execveat_sucompat(fd, filename, argv);
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
    if (IS_ERR(*filename_ptr)) return 0;
    return ksu_handle_execve(fd, (*filename_ptr)->name, argv, envp, flags);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
                 void *__never_use_argv, void *__never_use_envp,
                 int *__never_use_flags)
{
    return ksu_handle_execveat(fd, filename_ptr, __never_use_argv, __never_use_envp, __never_use_flags);
}

#endif // CONFIG_KSU_MANUAL_HOOK

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
