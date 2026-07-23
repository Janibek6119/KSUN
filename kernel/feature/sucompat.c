#include <linux/file.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/build_bug.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include <linux/ptrace.h>

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "compat/kernel_compat.h"
#ifdef CONFIG_KSU_KPROBES_HOOK
#include "hook/syscall_hook.h"
#endif
#if !defined(CONFIG_KSU_KPROBES_HOOK) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#include "feature/adb_root.h"
#endif
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#include "hook/syscall_event_bridge.h"
#include "hook/tp_marker.h"
#endif
#include "sulog/event.h"
#include "ksu.h"
#include "util.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"
#define KSU_SU_PATH_WORDS 2
#define KSU_SU_PATH_PREFIX ((u16)'/' | ((u16)'s' << 8))
#define KSU_SU_TAIL_MASK 0x00ffffffffffffffULL

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_su_compat_enabled)
		return 0;

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

static __always_inline bool ksu_sucompat_current_allowed(void)
{
	uid_t uid = current_uid().val;

	if (!uid)
		return is_ksu_domain_fast() || unlikely(is_ksu_domain());

	return __ksu_is_allow_uid(uid);
}

#ifdef CONFIG_KSU_KPROBES_HOOK
static const char su_path_cmp[KSU_SU_PATH_WORDS * sizeof(u64)]
	__aligned(sizeof(u64)) = SU_PATH;

static __always_inline bool
ksu_sucompat_user_path_matches(const char __user *filename)
{
	const u64 *su_words = (const u64 *)su_path_cmp;
	const char __user *path;
	const u64 __user *user_words;
	u16 prefix;
	u64 word;

	if (!filename)
		return false;

	BUILD_BUG_ON(sizeof(SU_PATH) + 1 != sizeof(su_path_cmp));
	path = (const char __user *)untagged_addr((unsigned long)filename);
	if (get_user(prefix, (const u16 __user *)path))
		return false;
	if (likely(prefix != KSU_SU_PATH_PREFIX))
		return false;

	user_words = (const u64 __user *)path;

	if (get_user(word, &user_words[KSU_SU_PATH_WORDS - 1]))
		return false;
	if (likely((word & KSU_SU_TAIL_MASK) !=
		   (su_words[KSU_SU_PATH_WORDS - 1] & KSU_SU_TAIL_MASK)))
		return false;
	if (unlikely(get_user(word, &user_words[0])))
		return false;
	return word == su_words[0];
}

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the stack
	// pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
	return userspace_stack_buffer("", sizeof(""));
}

static bool is_ksud_exists()
{
	struct path path;

	if (kern_path(KSUD_PATH, 0, &path) < 0) {
		return false;
	}
	path_put(&path);
	return true;
}

long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		goto do_orig_facessat;
	if (!ksu_sucompat_current_allowed())
		goto do_orig_facessat;
	old_cred = override_creds(ksu_cred);
	if (!is_ksud_exists()) {
		revert_creds(old_cred);
		goto do_orig_facessat;
	}
	ksu_compat_sulog('a');
	pr_info("faccessat su->ksud!\n");
	orig_filename = *filename_user;
	*filename_user = ksud_user_path();
	ret = ksu_invoke_syscall_nr(orig_nr, regs);
	revert_creds(old_cred);
	*filename_user = orig_filename;
	return ret;

do_orig_facessat:
	return ksu_invoke_syscall_nr(orig_nr, regs);
}

long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		goto do_orig_stat;
	if (!ksu_sucompat_current_allowed())
		goto do_orig_stat;
	old_cred = override_creds(ksu_cred);
	if (!is_ksud_exists()) {
		revert_creds(old_cred);
		goto do_orig_stat;
	}
	ksu_compat_sulog('s');
	pr_info("newfstatat su->ksud!\n");
	orig_filename = *filename_user;
	*filename_user = ksud_user_path();
	ret = ksu_invoke_syscall_nr(orig_nr, regs);
	revert_creds(old_cred);
	*filename_user = orig_filename;
	return ret;

do_orig_stat:
	return ksu_invoke_syscall_nr(orig_nr, regs);
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
static bool ksu_redirect_su_path(const char __user **filename_user, char event,
				 const struct cred **old_cred_out)
{
	const char __user *new_filename;
	const struct cred *old_cred;
	bool exists;

	if (!old_cred_out) {
		pr_err("sucompat: redirect called without old_cred_out\n");
		return false;
	}
	*old_cred_out = NULL;

	if (unlikely(!ksu_su_compat_enabled))
		return false;
	if (!filename_user) {
		pr_err("sucompat: redirect called without filename_user\n");
		return false;
	}

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		return false;
	if (!ksu_sucompat_current_allowed())
		return false;

	old_cred = override_creds(ksu_cred);
	exists = is_ksud_exists();
	if (!exists) {
		revert_creds(old_cred);
		return false;
	}

	new_filename = ksud_user_path();
	if (!new_filename) {
		revert_creds(old_cred);
		return false;
	}

	ksu_compat_sulog(event);
	*filename_user = new_filename;
	*old_cred_out = old_cred;
	return true;
}

bool ksu_handle_faccessat(int *dfd, const char __user **filename_user,
			  int *mode, int *flags,
			  const struct cred **old_cred_out)
{
	(void)dfd;
	(void)mode;
	(void)flags;

	if (ksu_redirect_su_path(filename_user, 'a', old_cred_out)) {
		pr_info("faccessat su->ksud!\n");
		return true;
	}
	return false;
}

bool ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags,
		     const struct cred **old_cred_out)
{
	(void)dfd;
	(void)flags;

	if (ksu_redirect_su_path(filename_user, 's', old_cred_out)) {
		pr_info("newfstatat su->ksud!\n");
		return true;
	}
	return false;
}

bool ksu_handle_stat_kernel_filename(char *filename,
				     const struct cred **old_cred_out)
{
	const struct cred *old_cred;
	bool exists;

	if (!old_cred_out) {
		pr_err("sucompat: stat_kernel_filename called without old_cred_out\n");
		return false;
	}
	*old_cred_out = NULL;

	if (unlikely(!ksu_su_compat_enabled))
		return false;
	if (!filename) {
		pr_err("sucompat: stat_kernel_filename called without filename\n");
		return false;
	}
	if (likely(memcmp(filename, SU_PATH, sizeof(SU_PATH))))
		return false;
	if (!ksu_sucompat_current_allowed())
		return false;

	old_cred = override_creds(ksu_cred);
	exists = is_ksud_exists();
	if (!exists) {
		revert_creds(old_cred);
		return false;
	}

	if (sizeof(KSUD_PATH) > sizeof(SU_PATH)) {
		revert_creds(old_cred);
		return false;
	}
	ksu_compat_sulog('s');
	memcpy(filename, KSUD_PATH, sizeof(KSUD_PATH));
	pr_info("stat filename su->ksud!\n");
	*old_cred_out = old_cred;
	return true;
}
#endif

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
	const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	long ret, orig_regs[5];
	int tmp_fd;
	struct file *ksud_file;
	const struct cred *old_cred;

	if (unlikely(!filename_user))
		goto do_orig_execve;
	if (unlikely(!*filename_user))
		goto do_orig_execve;

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		goto do_orig_execve;
	if (!ksu_sucompat_current_allowed())
		goto do_orig_execve;

	ksu_compat_sulog('x');
	pr_info("sys_execve su found\n");

	tmp_fd = get_unused_fd_flags(O_CLOEXEC);
	if (tmp_fd < 0) {
		pr_err("alloc tmp fd err: %d\n", tmp_fd);
		goto do_orig_execve;
	}

	old_cred = override_creds(ksu_cred);
	ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
	revert_creds(old_cred);
	if (IS_ERR(ksud_file)) {
		pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
		put_unused_fd(tmp_fd);
		goto do_orig_execve;
	}

	fd_install(tmp_fd, ksud_file);

	pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	// execve(file, argv, environ)
	// execveat(fd, file, argv, environ, flags)
	orig_regs[0] = regs->__PT_PARM1_REG;
	orig_regs[1] = regs->__PT_PARM2_REG;
	orig_regs[2] = regs->__PT_PARM3_REG;
	orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
	orig_regs[4] = regs->__PT_PARM5_REG;
	regs->__PT_PARM5_REG = AT_EMPTY_PATH;
	regs->__PT_SYSCALL_PARM4_REG = regs->__PT_PARM3_REG;
	regs->__PT_PARM3_REG = regs->__PT_PARM2_REG;
	regs->__PT_PARM2_REG = empty_user_path();
	regs->__PT_PARM1_REG = tmp_fd;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
	}
	ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

	ret = ksu_invoke_syscall_nr(__NR_execveat, regs);
	if (ret < 0) {
		ksu_close_fd(tmp_fd);
		regs->__PT_PARM1_REG = orig_regs[0];
		regs->__PT_PARM2_REG = orig_regs[1];
		regs->__PT_PARM3_REG = orig_regs[2];
		regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
		regs->__PT_PARM5_REG = orig_regs[4];
	}
	return ret;

do_orig_execve:
	return ksu_invoke_syscall_nr(orig_nr, regs);
}

#endif // CONFIG_KSU_KPROBES_HOOK

#if !defined(CONFIG_KSU_KPROBES_HOOK) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#ifndef CONFIG_KSU_KPROBES_HOOK
extern bool ksud_execve_key;
static inline bool ksu_ksud_execve_hook_enabled(void)
{
	return ksud_execve_key;
}
#endif

static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, void *argv)
{
	struct path kpath;

	(void)fd;
	(void)argv;

	if (unlikely(!ksu_su_compat_enabled))
		return 0;
	if (!filename)
		return 0;
	if (likely(memcmp(filename, SU_PATH, sizeof(SU_PATH))))
		return 0;
	if (!ksu_sucompat_current_allowed())
		return 0;

	ksu_compat_sulog('x');
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

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
static void ksu_handle_execveat_init_mark_tracker(const char *filename)
{
	if (!filename)
		return;

	if (unlikely(strcmp(filename, KSUD_PATH) == 0)) {
		pr_info("hook_manager: escape to root for init executing ksud\n");
		escape_to_root_for_init();
	} else if (likely(!strstr(filename, "/app_process") &&
			  !strstr(filename, "/adbd"))) {
		pr_info("hook_manager: unmark %d exec %s\n", current->pid,
			filename);
		ksu_clear_task_tracepoint_flag_if_needed(current);
	}
}
#endif

int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags)
{
	long ret;

	(void)flags;

	if (current->pid != 1 && is_init(current_cred())) {
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
		ksu_handle_execveat_init_mark_tracker(filename);
#endif
		ret = ksu_adb_root_handle_execveat(filename, (struct user_arg_ptr *)envp);
		if (ret)
			pr_err("adb root failed: %ld\n", ret);
	}

	if (unlikely(ksu_ksud_execve_hook_enabled())) {
		ksu_handle_execveat_ksud(filename, (struct user_arg_ptr *)argv);
	}

	if (current_uid().val == 0) {
		ksu_compat_sulog('x');
	}

	return do_ksu_handle_execveat_sucompat(fd, filename, argv);
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	if (!filename_ptr || !*filename_ptr || IS_ERR(*filename_ptr))
		return 0;

	return ksu_handle_execve(fd, (*filename_ptr)->name, argv, envp, flags);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	return ksu_handle_execveat(fd, filename_ptr, __never_use_argv, __never_use_envp,
				   __never_use_flags);
}

#endif // !CONFIG_KSU_KPROBES_HOOK || CONFIG_KSU_HACK_ARM64_BRANCH_LINK

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
