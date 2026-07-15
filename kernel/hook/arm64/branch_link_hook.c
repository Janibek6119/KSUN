#ifdef __aarch64__

#include "branch_link_hook.h"

#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "pnode.h"
#include "../patch_memory.h"
#include "compat/kernel_compat.h"
#include "feature/sucompat.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#ifdef CONFIG_KSU_KPROBES_SUSFS
#include "susfs/kstat.h"
#include "susfs/procfs.h"
#endif

#define KSU_BL_SCAN_WIDTH (128 * sizeof(void *))
#define KSU_BL_MAX_RECORDS 48
#define KSU_AARCH64_B_OPCODE 0x14000000U
#define KSU_AARCH64_BL_OPCODE 0x94000000U
#define KSU_AARCH64_BL_MASK 0xfc000000U
#define KSU_AARCH64_BRANCH_IMM_MASK 0x03ffffffU

struct ksu_bl_record {
	const char *name;
	unsigned long site;
	unsigned long original;
	unsigned long hook;
};

static DEFINE_MUTEX(ksu_bl_lock);
static struct ksu_bl_record ksu_bl_records[KSU_BL_MAX_RECORDS];
static int ksu_bl_record_count;
static bool ksu_bl_initialized;

static unsigned long ksu_bl_lookup(const char *name)
{
	unsigned long addr;

	addr = find_kernel_symbol_exact(name);
	if (!addr)
		addr = (unsigned long)ksu_resolve_symbol_for_functable_hook(name);

	pr_info("branch_link: %s=0x%lx\n", name, addr);
	return addr;
}

static bool ksu_aarch64_insn_is_bl(u32 instruction)
{
	return (instruction & KSU_AARCH64_BL_MASK) == KSU_AARCH64_BL_OPCODE;
}

static bool ksu_aarch64_insn_is_branch_imm(u32 instruction)
{
	u32 opcode = instruction & KSU_AARCH64_BL_MASK;

	return opcode == KSU_AARCH64_B_OPCODE ||
	       opcode == KSU_AARCH64_BL_OPCODE;
}

static long ksu_aarch64_get_branch_offset(u32 instruction)
{
	s32 imm26 = instruction & KSU_AARCH64_BRANCH_IMM_MASK;

	if (imm26 & (1 << 25))
		imm26 |= ~KSU_AARCH64_BRANCH_IMM_MASK;

	return (long)imm26 << 2;
}

static u32 ksu_aarch64_gen_branch(unsigned long site, unsigned long destination,
				  bool link)
{
	long offset = (long)destination - (long)site;
	s32 imm26 = (s32)(offset >> 2);

	return (link ? KSU_AARCH64_BL_OPCODE : KSU_AARCH64_B_OPCODE) |
	       (imm26 & KSU_AARCH64_BRANCH_IMM_MASK);
}

static int ksu_arm64_bl_replace_at(unsigned long site, unsigned long expected,
				   unsigned long replacement)
{
	const long bl_max_delta = (1L << 25) * sizeof(u32);
	long delta = (long)replacement - (long)site;
	unsigned long destination;
	u32 raw_instruction;
	u32 instruction;
	long offset;
	int ret;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)site,
				     sizeof(raw_instruction)))
		return -EFAULT;
	if (!ksu_aarch64_insn_is_branch_imm(raw_instruction))
		return -EINVAL;

	offset = ksu_aarch64_get_branch_offset(raw_instruction);
	destination = site + offset;
	if (destination != expected)
		return -ENOENT;

	if (delta >= bl_max_delta || delta < -bl_max_delta) {
		pr_info("branch_link: site 0x%lx -> 0x%lx out of range (%ld)\n",
			site, replacement, delta);
		return -ERANGE;
	}
	if (delta & 0x3)
		return -EINVAL;

	instruction = ksu_aarch64_gen_branch(site, replacement,
					     ksu_aarch64_insn_is_bl(raw_instruction));
	ret = ksu_patch_text((void *)site, &instruction, sizeof(instruction),
			     KSU_PATCH_TEXT_FLUSH_ICACHE);
	pr_info("branch_link: patch site 0x%lx 0x%lx -> 0x%lx: %d\n",
		site, expected, replacement, ret);
	return ret;
}

static int ksu_arm64_bl_patch(unsigned long start, size_t width,
			      unsigned long original, unsigned long hook,
			      unsigned long *site_out)
{
	unsigned long site;
	unsigned long end = start + width;
	u32 raw_instruction;
	long offset;

	if (!start || !original || !hook)
		return -EINVAL;

	might_sleep();

	for (site = start; site < end; site += sizeof(raw_instruction)) {
		if (copy_from_kernel_nofault(&raw_instruction, (void *)site,
					     sizeof(raw_instruction)))
			continue;
		if (!ksu_aarch64_insn_is_branch_imm(raw_instruction))
			continue;

		offset = ksu_aarch64_get_branch_offset(raw_instruction);
		if (site + offset != original)
			continue;

		if (site_out)
			*site_out = site;
		return ksu_arm64_bl_replace_at(site, original, hook);
	}

	pr_info("branch_link: callsite for 0x%lx not found from 0x%lx\n",
		original, start);
	return -ENOENT;
}

static int ksu_bl_record_patch(const char *name, unsigned long start,
			       unsigned long original, unsigned long hook)
{
	struct ksu_bl_record *record;
	unsigned long site = 0;
	int ret;

	ret = ksu_arm64_bl_patch(start, KSU_BL_SCAN_WIDTH, original, hook, &site);
	if (ret)
		return ret;

	if (ksu_bl_record_count >= ARRAY_SIZE(ksu_bl_records))
		return -ENOSPC;

	record = &ksu_bl_records[ksu_bl_record_count++];
	record->name = name;
	record->site = site;
	record->original = original;
	record->hook = hook;
	return 0;
}

static int ksu_bl_record_patch_all(const char *name, unsigned long start,
				   unsigned long original, unsigned long hook)
{
	int count = 0;
	int ret;

	do {
		ret = ksu_bl_record_patch(name, start, original, hook);
		if (!ret)
			count++;
	} while (!ret);

	if (count && ret == -ENOENT)
		return count;

	return count ? count : ret;
}

static int ksu_bl_record_patch_callers(const char *name,
				       const char * const *callers,
				       size_t caller_count,
				       unsigned long original,
				       unsigned long hook)
{
	int count = 0;
	size_t i;

	for (i = 0; i < caller_count; i++) {
		unsigned long caller_addr = ksu_bl_lookup(callers[i]);
		int ret;

		if (!caller_addr)
			continue;

		ret = ksu_bl_record_patch_all(name, caller_addr, original, hook);
		if (ret > 0)
			count += ret;
		else
			pr_info("branch_link: %s from %s: %d\n", name,
				callers[i], ret);
	}

	return count ? count : -ENOENT;
}

static void ksu_bl_restore_records(void)
{
	while (ksu_bl_record_count > 0) {
		struct ksu_bl_record *record =
			&ksu_bl_records[--ksu_bl_record_count];
		int ret;

		ret = ksu_arm64_bl_replace_at(record->site, record->hook,
					      record->original);
		pr_info("branch_link: restore %s: %d\n", record->name, ret);
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_HAS_FACCESSAT2)
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode,
			       int flags);
static long __nocfi ksu_do_faccessat(int dfd, const char __user *filename,
				     int mode, int flags)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, &flags);
	return do_faccessat_fn(dfd, filename, mode, flags);
}
#else
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode);
static long __nocfi ksu_do_faccessat(int dfd, const char __user *filename,
				     int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return do_faccessat_fn(dfd, filename, mode);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int (*vfs_fstatat_fn)(int dfd, const char __user *filename,
			     struct kstat *stat, int flags);
static int __nocfi ksu_vfs_fstatat(int dfd, const char __user *filename,
				   struct kstat *stat, int flags)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_fstatat_fn(dfd, filename, stat, flags);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
static int (*vfs_statx_fn)(int dfd, struct filename *filename, int flags,
			   struct kstat *stat, u32 request_mask);
static int __nocfi ksu_vfs_statx(int dfd, struct filename *filename,
				 int flags, struct kstat *stat,
				 u32 request_mask)
{
	if (filename && !IS_ERR(filename))
		ksu_handle_stat_kernel_filename((char *)filename->name);
	return vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}
#else
static int (*vfs_statx_fn)(int dfd, const char __user *filename, int flags,
			   struct kstat *stat, u32 request_mask);
static int __nocfi ksu_vfs_statx(int dfd, const char __user *filename,
				 int flags, struct kstat *stat,
				 u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}
#endif
#else
static int (*vfs_statx_fn)(int dfd, const char __user *filename, int flags,
			   struct kstat *stat, u32 request_mask);
static int __nocfi ksu_vfs_statx(int dfd, const char __user *filename,
				 int flags, struct kstat *stat,
				 u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_statx_fn(dfd, filename, flags, stat, request_mask);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static int (*do_execveat_common_fn)(int fd, struct filename *filename,
				    struct user_arg_ptr argv,
				    struct user_arg_ptr envp, int flags);
static int __nocfi ksu_do_execveat_common(int fd, struct filename *filename,
					  struct user_arg_ptr argv,
					  struct user_arg_ptr envp, int flags)
{
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return do_execveat_common_fn(fd, filename, argv, envp, flags);
}
#else
static int (*__do_execve_file_fn)(int fd, struct filename *filename,
				  struct user_arg_ptr argv,
				  struct user_arg_ptr envp, int flags,
				  struct file *file);
static int __nocfi ksu_do_execve_file(int fd, struct filename *filename,
				      struct user_arg_ptr argv,
				      struct user_arg_ptr envp, int flags,
				      struct file *file)
{
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return __do_execve_file_fn(fd, filename, argv, envp, flags, file);
}

static int (*do_execve_fn)(struct filename *filename,
			   const char __user *const __user *__argv,
			   const char __user *const __user *__envp);
static int __nocfi ksu_do_execve(struct filename *filename,
				 const char __user *const __user *__argv,
				 const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	int fd = AT_FDCWD;
	int flags = 0;

	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return do_execve_fn(filename, argv.ptr.native, envp.ptr.native);
}

#ifdef CONFIG_COMPAT
static int (*compat_do_execve_fn)(struct filename *filename,
				  const compat_uptr_t __user *__argv,
				  const compat_uptr_t __user *__envp);
static int __nocfi ksu_compat_do_execve(struct filename *filename,
					const compat_uptr_t __user *__argv,
					const compat_uptr_t __user *__envp)
{
	struct user_arg_ptr argv = { .is_compat = true, .ptr.compat = __argv };
	struct user_arg_ptr envp = { .is_compat = true, .ptr.compat = __envp };
	int fd = AT_FDCWD;
	int flags = 0;

	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return compat_do_execve_fn(filename, argv.ptr.compat, envp.ptr.compat);
}
#endif
#endif

#ifdef CONFIG_KSU_KPROBES_SUSFS
static int (*vfs_getattr_nosec_fn)(const struct path *path, struct kstat *stat,
				   u32 request_mask, unsigned int query_flags);
static int __nocfi ksu_vfs_getattr_nosec(const struct path *path,
					 struct kstat *stat, u32 request_mask,
					 unsigned int query_flags)
{
	int ret = vfs_getattr_nosec_fn(path, stat, request_mask, query_flags);

	ksu_susfs_handle_vfs_getattr_nosec(path, stat, ret);
	return ret;
}

static struct vfsmount *(*vfs_create_mount_fn)(struct fs_context *fc);
static struct vfsmount *__nocfi ksu_vfs_create_mount(struct fs_context *fc)
{
	bool hide = ksu_susfs_should_hide_new_vfsmount();
	struct vfsmount *mnt = vfs_create_mount_fn(fc);

	ksu_susfs_mark_vfsmount_hidden(mnt, hide);
	return mnt;
}

static struct mount *(*clone_mnt_fn)(struct mount *old, struct dentry *root,
				     int flag);
static struct mount *__nocfi ksu_clone_mnt(struct mount *old,
					  struct dentry *root, int flag)
{
	bool hide = ksu_susfs_should_hide_cloned_mount(old);
	struct mount *mnt = clone_mnt_fn(old, root, flag);

	ksu_susfs_mark_mount_hidden(mnt, hide);
	return mnt;
}

static void (*cleanup_mnt_fn)(struct mount *mnt);
static void __nocfi ksu_cleanup_mnt(struct mount *mnt)
{
	ksu_susfs_handle_cleanup_mnt(mnt);
	cleanup_mnt_fn(mnt);
}

static void ksu_branch_link_patch_susfs(void)
{
	static const char * const vfs_create_mount_callers[] = {
		"fc_mount",
		"do_new_mount_fc",
		"__do_sys_fsmount",
		"__se_sys_fsmount",
		"__arm64_sys_fsmount",
		"fuse_dentry_automount",
	};
	static const char * const clone_mnt_callers[] = {
		"mnt_clone_internal",
		"copy_tree",
		"clone_private_mount",
		"__do_loopback",
	};
	static const char * const cleanup_mnt_callers[] = {
		"__cleanup_mnt",
		"delayed_mntput",
		"mntput_no_expire",
	};
	unsigned long caller_addr;
	unsigned long target_addr;
	int create_count;
	int clone_count;
	int cleanup_count;
	int ret;

	caller_addr = ksu_bl_lookup("vfs_getattr");
	target_addr = ksu_bl_lookup("vfs_getattr_nosec");
	vfs_getattr_nosec_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("susfs/vfs_getattr_nosec", caller_addr,
				  target_addr,
				  (unsigned long)ksu_vfs_getattr_nosec);
	pr_info("branch_link: susfs/vfs_getattr_nosec: %d\n", ret);
	ksu_susfs_set_getattr_ready(!ret);

	target_addr = ksu_bl_lookup("vfs_create_mount");
	vfs_create_mount_fn = (void *)target_addr;
	create_count = ksu_bl_record_patch_callers(
		"susfs/vfs_create_mount", vfs_create_mount_callers,
		ARRAY_SIZE(vfs_create_mount_callers), target_addr,
		(unsigned long)ksu_vfs_create_mount);
	pr_info("branch_link: susfs/vfs_create_mount patched: %d\n",
		create_count);

	target_addr = ksu_bl_lookup("clone_mnt");
	clone_mnt_fn = (void *)target_addr;
	clone_count = ksu_bl_record_patch_callers(
		"susfs/clone_mnt", clone_mnt_callers,
		ARRAY_SIZE(clone_mnt_callers), target_addr,
		(unsigned long)ksu_clone_mnt);
	pr_info("branch_link: susfs/clone_mnt patched: %d\n", clone_count);

	target_addr = ksu_bl_lookup("cleanup_mnt");
	cleanup_mnt_fn = (void *)target_addr;
	cleanup_count = ksu_bl_record_patch_callers(
		"susfs/cleanup_mnt", cleanup_mnt_callers,
		ARRAY_SIZE(cleanup_mnt_callers), target_addr,
		(unsigned long)ksu_cleanup_mnt);
	pr_info("branch_link: susfs/cleanup_mnt patched: %d\n",
		cleanup_count);

	ksu_susfs_set_mount_runtime_ready(create_count > 0 && clone_count > 0 &&
					  cleanup_count > 0);
}
#endif

int ksu_branch_link_patch_init(void)
{
	unsigned long caller_addr;
	unsigned long target_addr;
	int ret;

	mutex_lock(&ksu_bl_lock);
	if (ksu_bl_initialized) {
		mutex_unlock(&ksu_bl_lock);
		return 0;
	}

	caller_addr = ksu_bl_lookup("__arm64_sys_faccessat");
	target_addr = ksu_bl_lookup("do_faccessat");
	do_faccessat_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("faccessat/do_faccessat", caller_addr,
				  target_addr, (unsigned long)ksu_do_faccessat);
	pr_info("branch_link: faccessat/do_faccessat: %d\n", ret);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	caller_addr = ksu_bl_lookup("__arm64_sys_newfstatat");
	target_addr = ksu_bl_lookup("vfs_fstatat");
	vfs_fstatat_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("newfstatat/vfs_fstatat", caller_addr,
				  target_addr, (unsigned long)ksu_vfs_fstatat);
	pr_info("branch_link: newfstatat/vfs_fstatat: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("vfs_statx");
		vfs_statx_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("newfstatat/vfs_statx", caller_addr,
					  target_addr,
					  (unsigned long)ksu_vfs_statx);
		pr_info("branch_link: newfstatat/vfs_statx: %d\n", ret);
	}
#else
	caller_addr = ksu_bl_lookup("__arm64_sys_newfstatat");
	target_addr = ksu_bl_lookup("vfs_statx");
	vfs_statx_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("newfstatat/vfs_statx", caller_addr,
				  target_addr, (unsigned long)ksu_vfs_statx);
	pr_info("branch_link: newfstatat/vfs_statx: %d\n", ret);
#endif

#ifdef CONFIG_COMPAT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	caller_addr = ksu_bl_lookup("__arm64_sys_fstatat64");
	target_addr = ksu_bl_lookup("vfs_fstatat");
	vfs_fstatat_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("fstatat64/vfs_fstatat", caller_addr,
				  target_addr, (unsigned long)ksu_vfs_fstatat);
	pr_info("branch_link: fstatat64/vfs_fstatat: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("vfs_statx");
		vfs_statx_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("fstatat64/vfs_statx", caller_addr,
					  target_addr,
					  (unsigned long)ksu_vfs_statx);
		pr_info("branch_link: fstatat64/vfs_statx: %d\n", ret);
	}
#else
	caller_addr = ksu_bl_lookup("__arm64_sys_fstatat64");
	target_addr = ksu_bl_lookup("vfs_statx");
	vfs_statx_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("fstatat64/vfs_statx", caller_addr,
				  target_addr, (unsigned long)ksu_vfs_statx);
	pr_info("branch_link: fstatat64/vfs_statx: %d\n", ret);
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	caller_addr = ksu_bl_lookup("__arm64_sys_execve");
	target_addr = ksu_bl_lookup("do_execveat_common");
	do_execveat_common_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("execve/do_execveat_common", caller_addr,
				  target_addr,
				  (unsigned long)ksu_do_execveat_common);
	pr_info("branch_link: execve/do_execveat_common: %d\n", ret);
#ifdef CONFIG_COMPAT
	caller_addr = ksu_bl_lookup("__arm64_compat_sys_execve");
	ret = ksu_bl_record_patch("compat_execve/do_execveat_common",
				  caller_addr, target_addr,
				  (unsigned long)ksu_do_execveat_common);
	pr_info("branch_link: compat_execve/do_execveat_common: %d\n", ret);
#endif
#else
	caller_addr = ksu_bl_lookup("__arm64_sys_execve");
	target_addr = ksu_bl_lookup("__do_execve_file");
	__do_execve_file_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("execve/__do_execve_file", caller_addr,
				  target_addr, (unsigned long)ksu_do_execve_file);
	pr_info("branch_link: execve/__do_execve_file: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("do_execve");
		do_execve_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("execve/do_execve", caller_addr,
					  target_addr,
					  (unsigned long)ksu_do_execve);
		pr_info("branch_link: execve/do_execve: %d\n", ret);
	}
#ifdef CONFIG_COMPAT
	caller_addr = ksu_bl_lookup("__arm64_compat_sys_execve");
	target_addr = ksu_bl_lookup("__do_execve_file");
	__do_execve_file_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("compat_execve/__do_execve_file",
				  caller_addr, target_addr,
				  (unsigned long)ksu_do_execve_file);
	pr_info("branch_link: compat_execve/__do_execve_file: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("compat_do_execve");
		compat_do_execve_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("compat_execve/compat_do_execve",
					  caller_addr, target_addr,
					  (unsigned long)ksu_compat_do_execve);
		pr_info("branch_link: compat_execve/compat_do_execve: %d\n",
			ret);
	}
#endif
#endif

#ifdef CONFIG_KSU_KPROBES_SUSFS
	ksu_branch_link_patch_susfs();
#endif

	ksu_bl_initialized = true;
	mutex_unlock(&ksu_bl_lock);
	return 0;
}

void ksu_branch_link_patch_exit(void)
{
	mutex_lock(&ksu_bl_lock);
	if (!ksu_bl_initialized) {
		mutex_unlock(&ksu_bl_lock);
		return;
	}

#ifdef CONFIG_KSU_KPROBES_SUSFS
	ksu_susfs_set_getattr_ready(false);
	ksu_susfs_set_mount_runtime_ready(false);
#endif
	ksu_bl_restore_records();
	ksu_bl_initialized = false;
	mutex_unlock(&ksu_bl_lock);
}

#endif /* __aarch64__ */
