#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/version.h>

#include <asm/unistd.h>

#include "pnode.h"
#include "proc/internal.h"
#include "proc/fd.h"

#include "arch.h"
#include "hook/patch_memory.h"
#include "hook/syscall_hook.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "policy/feature.h"
#include "selinux/selinux.h"
#include "susfs/procfs.h"
#include "susfs/susfs.h"

#define KSU_SUSFS_MOUNT_HASH_BITS 8

extern const struct file_operations proc_mounts_operations;
extern const struct file_operations proc_mountinfo_operations;
extern const struct file_operations proc_mountstats_operations;

struct ksu_susfs_hidden_mount {
	struct hlist_node node;
	struct mount *mnt;
};

struct ksu_susfs_vfs_create_mount_ctx {
	bool hide;
};

struct ksu_susfs_clone_mnt_ctx {
	struct mount *old;
	bool hide;
};

static DEFINE_HASHTABLE(ksu_susfs_hidden_mounts, KSU_SUSFS_MOUNT_HASH_BITS);
static DEFINE_SPINLOCK(ksu_susfs_hidden_mounts_lock);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_mount_hide_enabled);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_cmdline_spoof_enabled);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_uname_spoof_enabled);
static DEFINE_SEQLOCK(ksu_susfs_cmdline_lock);
static DEFINE_SEQLOCK(ksu_susfs_uname_lock);

static char ksu_susfs_fake_cmdline[KSU_SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
static struct ksu_susfs_uname_cmd ksu_susfs_fake_uname;

static int (*ksu_susfs_orig_mounts_open)(struct inode *inode, struct file *file);
static int (*ksu_susfs_orig_mountinfo_open)(struct inode *inode,
					    struct file *file);
static int (*ksu_susfs_orig_mountstats_open)(struct inode *inode,
					     struct file *file);
static int (*ksu_susfs_orig_fdinfo_open)(struct inode *inode, struct file *file);

static const struct file_operations *ksu_susfs_fdinfo_fops;
static struct kretprobe *ksu_susfs_vfs_create_mount_rp;
static struct kretprobe *ksu_susfs_clone_mnt_rp;
static struct kprobe *ksu_susfs_cleanup_mnt_kp;
static bool ksu_susfs_cmdline_ready;
static bool ksu_susfs_mount_runtime_ready;
static bool ksu_susfs_uname_hook_ready;

static bool ksu_susfs_compat_root_allowed(void)
{
	return current_uid().val == 0 || is_ksu_domain();
}

static bool ksu_susfs_mount_hidden_exact(struct mount *mnt)
{
	struct ksu_susfs_hidden_mount *entry;
	unsigned long flags;
	bool found = false;

	if (!mnt) {
		return false;
	}

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_possible(ksu_susfs_hidden_mounts, entry, node,
			       (unsigned long)mnt) {
		if (entry->mnt == mnt) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);

	return found;
}

static bool ksu_susfs_mount_hidden_or_ancestor(struct mount *mnt)
{
	struct mount *cursor;
	unsigned seq;
	bool hidden;

	if (!mnt) {
		return false;
	}

	do {
		seq = read_seqbegin(&mount_lock);
		cursor = mnt;
		hidden = false;

		while (cursor) {
			if (ksu_susfs_mount_hidden_exact(cursor)) {
				hidden = true;
				break;
			}
			if (!mnt_has_parent(cursor)) {
				break;
			}
			cursor = cursor->mnt_parent;
		}
	} while (read_seqretry(&mount_lock, seq));

	return hidden;
}

static int ksu_susfs_visible_mnt_id(struct mount *mnt)
{
	struct mount *cursor;
	unsigned seq;
	int mnt_id = 0;

	if (!mnt) {
		return 0;
	}

	do {
		seq = read_seqbegin(&mount_lock);
		cursor = mnt;

		while (cursor && mnt_has_parent(cursor)) {
			if (!ksu_susfs_mount_hidden_exact(cursor) &&
			    !ksu_susfs_mount_hidden_exact(cursor->mnt_parent)) {
				break;
			}
			cursor = cursor->mnt_parent;
		}

		if (cursor) {
			mnt_id = cursor->mnt_id;
		}
	} while (read_seqretry(&mount_lock, seq));

	return mnt_id;
}

static bool ksu_susfs_mount_hide_view_enabled(void)
{
	if (!static_branch_unlikely(&ksu_susfs_mount_hide_enabled)) {
		return false;
	}

	return !is_ksu_domain();
}

static void ksu_susfs_mount_mark_hidden(struct mount *mnt)
{
	struct ksu_susfs_hidden_mount *entry;
	struct ksu_susfs_hidden_mount *existing;
	unsigned long flags;

	if (!mnt) {
		return;
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		pr_err("susfs: failed to allocate hidden mount entry\n");
		return;
	}

	entry->mnt = mnt;

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_possible(ksu_susfs_hidden_mounts, existing, node,
			       (unsigned long)mnt) {
		if (existing->mnt == mnt) {
			spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock,
					       flags);
			kfree(entry);
			return;
		}
	}
	hash_add(ksu_susfs_hidden_mounts, &entry->node, (unsigned long)mnt);
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);
}

static void ksu_susfs_mount_unmark_hidden(struct mount *mnt)
{
	struct ksu_susfs_hidden_mount *entry;
	unsigned long flags;

	if (!mnt) {
		return;
	}

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_possible(ksu_susfs_hidden_mounts, entry, node,
			       (unsigned long)mnt) {
		if (entry->mnt == mnt) {
			hash_del(&entry->node);
			kfree(entry);
			break;
		}
	}
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);
}

static void ksu_susfs_mount_clear_hidden_all(void)
{
	struct ksu_susfs_hidden_mount *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long flags;

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_safe(ksu_susfs_hidden_mounts, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);
}

static int ksu_susfs_patch_fop_open(const struct file_operations *fops,
				    int (*new_open)(struct inode *,
						    struct file *),
				    int (**old_open)(struct inode *,
						    struct file *))
{
	int (*orig_open)(struct inode *inode, struct file *file);
	void *dst;

	if (!fops || !new_open) {
		return -EINVAL;
	}

	orig_open = READ_ONCE(fops->open);
	if (!orig_open) {
		return -EINVAL;
	}

	if (old_open) {
		*old_open = orig_open;
	}

	dst = (void *)&((struct file_operations *)fops)->open;
	return ksu_patch_text(dst, &new_open, sizeof(new_open),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_fop_open(const struct file_operations *fops,
				       int (**old_open)(struct inode *,
							struct file *))
{
	int (*orig_open)(struct inode *inode, struct file *file);
	void *dst;

	if (!fops || !old_open || !*old_open) {
		return;
	}

	orig_open = *old_open;
	dst = (void *)&((struct file_operations *)fops)->open;
	if (ksu_patch_text(dst, &orig_open, sizeof(orig_open),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore file_operations open\n");
	}

	*old_open = NULL;
}

static void ksu_susfs_show_mnt_opts(struct seq_file *m, struct vfsmount *mnt)
{
	static const struct {
		int flag;
		const char *str;
	} mnt_info[] = {
		{ MNT_NOSUID, ",nosuid" },
		{ MNT_NODEV, ",nodev" },
		{ MNT_NOEXEC, ",noexec" },
		{ MNT_NOATIME, ",noatime" },
		{ MNT_NODIRATIME, ",nodiratime" },
		{ MNT_RELATIME, ",relatime" },
		{ 0, NULL }
	};
	const typeof(mnt_info[0]) *info;

	for (info = mnt_info; info->flag; info++) {
		if (mnt->mnt_flags & info->flag) {
			seq_puts(m, info->str);
		}
	}
}

static int ksu_susfs_show_sb_opts(struct seq_file *m, struct super_block *sb)
{
	static const struct {
		int flag;
		const char *str;
	} fs_info[] = {
		{ SB_SYNCHRONOUS, ",sync" },
		{ SB_DIRSYNC, ",dirsync" },
		{ SB_MANDLOCK, ",mand" },
		{ SB_LAZYTIME, ",lazytime" },
		{ 0, NULL }
	};
	const typeof(fs_info[0]) *info;

	for (info = fs_info; info->flag; info++) {
		if (sb->s_flags & info->flag) {
			seq_puts(m, info->str);
		}
	}

	return security_sb_show_options(m, sb);
}

static inline void ksu_susfs_mangle(struct seq_file *m, const char *s)
{
	seq_escape(m, s, " \t\n\\");
}

static void ksu_susfs_show_type(struct seq_file *m, struct super_block *sb)
{
	ksu_susfs_mangle(m, sb->s_type->name);
	if (sb->s_subtype) {
		seq_putc(m, '.');
		ksu_susfs_mangle(m, sb->s_subtype);
	}
}

static int ksu_susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)
{
	struct proc_mounts *p = m->private;
	struct mount *r = real_mount(mnt);
	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt,
	};
	struct super_block *sb = mnt_path.dentry->d_sb;
	int err;

	if (ksu_susfs_mount_hidden_or_ancestor(r)) {
		return 0;
	}

	if (sb->s_op->show_devname) {
		err = sb->s_op->show_devname(m, mnt_path.dentry);
		if (err) {
			goto out;
		}
	} else {
		ksu_susfs_mangle(m, r->mnt_devname ? r->mnt_devname : "none");
	}
	seq_putc(m, ' ');

	err = seq_path_root(m, &mnt_path, &p->root, " \t\n\\");
	if (err) {
		goto out;
	}
	seq_putc(m, ' ');

	ksu_susfs_show_type(m, sb);
	seq_puts(m, __mnt_is_readonly(mnt) ? " ro" : " rw");

	err = ksu_susfs_show_sb_opts(m, sb);
	if (err) {
		goto out;
	}

	ksu_susfs_show_mnt_opts(m, mnt);
	if (sb->s_op->show_options2) {
		err = sb->s_op->show_options2(mnt, m, mnt_path.dentry);
	} else if (sb->s_op->show_options) {
		err = sb->s_op->show_options(m, mnt_path.dentry);
	}
	seq_puts(m, " 0 0\n");

out:
	return err;
}

static int ksu_susfs_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
	struct proc_mounts *p = m->private;
	struct mount *r = real_mount(mnt);
	struct super_block *sb = mnt->mnt_sb;
	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt,
	};
	int err;

	if (ksu_susfs_mount_hidden_or_ancestor(r)) {
		return 0;
	}

	seq_printf(m, "%i %i %u:%u ", r->mnt_id, r->mnt_parent->mnt_id,
		   MAJOR(sb->s_dev), MINOR(sb->s_dev));
	if (sb->s_op->show_path) {
		err = sb->s_op->show_path(m, mnt->mnt_root);
		if (err) {
			goto out;
		}
	} else {
		seq_dentry(m, mnt->mnt_root, " \t\n\\");
	}
	seq_putc(m, ' ');

	err = seq_path_root(m, &mnt_path, &p->root, " \t\n\\");
	if (err) {
		goto out;
	}

	seq_puts(m, mnt->mnt_flags & MNT_READONLY ? " ro" : " rw");
	ksu_susfs_show_mnt_opts(m, mnt);

	if (IS_MNT_SHARED(r)) {
		seq_printf(m, " shared:%i", r->mnt_group_id);
	}
	if (IS_MNT_SLAVE(r)) {
		int master = r->mnt_master->mnt_group_id;
		int dom = get_dominating_id(r, &p->root);

		seq_printf(m, " master:%i", master);
		if (dom && dom != master) {
			seq_printf(m, " propagate_from:%i", dom);
		}
	}
	if (IS_MNT_UNBINDABLE(r)) {
		seq_puts(m, " unbindable");
	}

	seq_puts(m, " - ");
	ksu_susfs_show_type(m, sb);
	seq_putc(m, ' ');
	if (sb->s_op->show_devname) {
		err = sb->s_op->show_devname(m, mnt->mnt_root);
		if (err) {
			goto out;
		}
	} else {
		ksu_susfs_mangle(m, r->mnt_devname ? r->mnt_devname : "none");
	}
	seq_puts(m, sb_rdonly(sb) ? " ro" : " rw");

	err = ksu_susfs_show_sb_opts(m, sb);
	if (err) {
		goto out;
	}

	if (sb->s_op->show_options2) {
		err = sb->s_op->show_options2(mnt, m, mnt->mnt_root);
	} else if (sb->s_op->show_options) {
		err = sb->s_op->show_options(m, mnt->mnt_root);
	}
	seq_putc(m, '\n');

out:
	return err;
}

static int ksu_susfs_show_vfsstat(struct seq_file *m, struct vfsmount *mnt)
{
	struct proc_mounts *p = m->private;
	struct mount *r = real_mount(mnt);
	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt,
	};
	struct super_block *sb = mnt_path.dentry->d_sb;
	int err;

	if (ksu_susfs_mount_hidden_or_ancestor(r)) {
		return 0;
	}

	if (sb->s_op->show_devname) {
		seq_puts(m, "device ");
		err = sb->s_op->show_devname(m, mnt_path.dentry);
		if (err) {
			goto out;
		}
	} else if (r->mnt_devname) {
		seq_puts(m, "device ");
		ksu_susfs_mangle(m, r->mnt_devname);
	} else {
		seq_puts(m, "no device");
	}

	seq_puts(m, " mounted on ");
	err = seq_path_root(m, &mnt_path, &p->root, " \t\n\\");
	if (err) {
		goto out;
	}
	seq_putc(m, ' ');

	seq_puts(m, "with fstype ");
	ksu_susfs_show_type(m, sb);

	if (sb->s_op->show_stats) {
		seq_putc(m, ' ');
		err = sb->s_op->show_stats(m, mnt_path.dentry);
	}

	seq_putc(m, '\n');

out:
	return err;
}

static int ksu_susfs_mounts_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct proc_mounts *p;
	int ret;

	if (!ksu_susfs_orig_mounts_open) {
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_mounts_open(inode, file);
	if (ret || !ksu_susfs_mount_hide_view_enabled()) {
		return ret;
	}

	m = file->private_data;
	if (!m || !m->private) {
		return ret;
	}

	p = m->private;
	p->show = ksu_susfs_show_vfsmnt;
	return 0;
}

static int ksu_susfs_mountinfo_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct proc_mounts *p;
	int ret;

	if (!ksu_susfs_orig_mountinfo_open) {
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_mountinfo_open(inode, file);
	if (ret || !ksu_susfs_mount_hide_view_enabled()) {
		return ret;
	}

	m = file->private_data;
	if (!m || !m->private) {
		return ret;
	}

	p = m->private;
	p->show = ksu_susfs_show_mountinfo;
	return 0;
}

static int ksu_susfs_mountstats_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct proc_mounts *p;
	int ret;

	if (!ksu_susfs_orig_mountstats_open) {
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_mountstats_open(inode, file);
	if (ret || !ksu_susfs_mount_hide_view_enabled()) {
		return ret;
	}

	m = file->private_data;
	if (!m || !m->private) {
		return ret;
	}

	p = m->private;
	p->show = ksu_susfs_show_vfsstat;
	return 0;
}

static bool ksu_susfs_fdinfo_rewrite(struct file *file, int *mnt_id,
				     unsigned long *ino)
{
	struct path path;
	struct inode *inode;
	struct mount *mnt;
	char *buf;
	char *resolved;

	if (!file || !mnt_id || !ino) {
		return false;
	}

	mnt = real_mount(file->f_path.mnt);
	if (!ksu_susfs_mount_hidden_or_ancestor(mnt)) {
		return false;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		*mnt_id = ksu_susfs_visible_mnt_id(mnt);
		*ino = file_inode(file)->i_ino;
		return true;
	}

	resolved = d_path(&file->f_path, buf, PAGE_SIZE);
	if (!IS_ERR(resolved) && !kern_path(resolved, 0, &path)) {
		inode = d_backing_inode(path.dentry);
		*mnt_id = real_mount(path.mnt)->mnt_id;
		*ino = inode ? inode->i_ino : file_inode(file)->i_ino;
		path_put(&path);
		kfree(buf);
		return true;
	}

	*mnt_id = ksu_susfs_visible_mnt_id(mnt);
	*ino = file_inode(file)->i_ino;
	kfree(buf);
	return true;
}

static int ksu_susfs_fdinfo_show(struct seq_file *m, void *v)
{
	struct files_struct *files = NULL;
	struct file *file = NULL;
	struct task_struct *task;
	int f_flags = 0;
	int ret = -ENOENT;

	task = get_proc_task(m->private);
	if (!task) {
		return -ENOENT;
	}

	files = get_files_struct(task);
	put_task_struct(task);

	if (files) {
		unsigned int fd = proc_fd(m->private);

		spin_lock(&files->file_lock);
		file = fcheck_files(files, fd);
		if (file) {
			struct fdtable *fdt = files_fdtable(files);

			f_flags = file->f_flags;
			if (close_on_exec(fd, fdt)) {
				f_flags |= O_CLOEXEC;
			}

			get_file(file);
			ret = 0;
		}
		spin_unlock(&files->file_lock);
		put_files_struct(files);
	}

	if (ret) {
		return ret;
	}

	if (ksu_susfs_mount_hide_view_enabled()) {
		int mnt_id = 0;
		unsigned long ino = 0;

		if (ksu_susfs_fdinfo_rewrite(file, &mnt_id, &ino)) {
			seq_printf(m,
				   "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\nino:\t%lu\n",
				   (long long)file->f_pos, f_flags, mnt_id,
				   ino);
			goto out_tail;
		}
	}

	seq_printf(m, "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\nino:\t%lu\n",
		   (long long)file->f_pos, f_flags,
		   real_mount(file->f_path.mnt)->mnt_id, file_inode(file)->i_ino);

out_tail:
	show_fd_locks(m, file, files);
	if (!seq_has_overflowed(m) && file->f_op->show_fdinfo) {
		file->f_op->show_fdinfo(m, file);
	}

	fput(file);
	return 0;
}

static int ksu_susfs_fdinfo_open(struct inode *inode, struct file *file)
{
	return single_open(file, ksu_susfs_fdinfo_show, inode);
}

static int ksu_susfs_vfs_create_mount_entry(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	struct ksu_susfs_vfs_create_mount_ctx *ctx =
		(struct ksu_susfs_vfs_create_mount_ctx *)ri->data;

	ctx->hide = is_ksu_domain_fast();
	return 0;
}

static int ksu_susfs_vfs_create_mount_handler(struct kretprobe_instance *ri,
					      struct pt_regs *regs)
{
	struct ksu_susfs_vfs_create_mount_ctx *ctx =
		(struct ksu_susfs_vfs_create_mount_ctx *)ri->data;
	struct vfsmount *vfsmnt;

	if (!ctx->hide) {
		return 0;
	}

	vfsmnt = (struct vfsmount *)regs_return_value(regs);
	if (IS_ERR_OR_NULL(vfsmnt)) {
		return 0;
	}

	ksu_susfs_mount_mark_hidden(real_mount(vfsmnt));
	return 0;
}

static int ksu_susfs_clone_mnt_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct ksu_susfs_clone_mnt_ctx *ctx =
		(struct ksu_susfs_clone_mnt_ctx *)ri->data;

	ctx->old = (struct mount *)PT_REGS_PARM1(regs);
	ctx->hide = is_ksu_domain_fast() ||
		    ksu_susfs_mount_hidden_or_ancestor(ctx->old);
	return 0;
}

static int ksu_susfs_clone_mnt_handler(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	struct ksu_susfs_clone_mnt_ctx *ctx =
		(struct ksu_susfs_clone_mnt_ctx *)ri->data;
	struct mount *mnt;

	if (!ctx->hide) {
		return 0;
	}

	mnt = (struct mount *)regs_return_value(regs);
	if (IS_ERR_OR_NULL(mnt)) {
		return 0;
	}

	ksu_susfs_mount_mark_hidden(mnt);
	return 0;
}

static int ksu_susfs_cleanup_mnt_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct mount *mnt = (struct mount *)PT_REGS_PARM1(regs);

	ksu_susfs_mount_unmark_hidden(mnt);
	return 0;
}

static struct kretprobe *ksu_susfs_init_kretprobe(
	const char *name, kretprobe_handler_t entry_handler,
	kretprobe_handler_t handler, size_t data_size)
{
	struct kretprobe *rp;
	int ret;

	rp = kzalloc(sizeof(*rp), GFP_KERNEL);
	if (!rp) {
		return NULL;
	}

	rp->kp.symbol_name = name;
	rp->entry_handler = entry_handler;
	rp->handler = handler;
	rp->data_size = data_size;
	rp->maxactive = 0;

	ret = register_kretprobe(rp);
	if (ret) {
		pr_err("susfs: register_%s kretprobe failed: %d\n", name, ret);
		kfree(rp);
		return NULL;
	}

	return rp;
}

static void ksu_susfs_destroy_kretprobe(struct kretprobe **rp_ptr)
{
	struct kretprobe *rp = *rp_ptr;

	if (!rp) {
		return;
	}

	unregister_kretprobe(rp);
	synchronize_rcu();
	kfree(rp);
	*rp_ptr = NULL;
}

static struct kprobe *ksu_susfs_init_kprobe(const char *name,
					    kprobe_pre_handler_t handler)
{
	struct kprobe *kp;
	int ret;

	kp = kzalloc(sizeof(*kp), GFP_KERNEL);
	if (!kp) {
		return NULL;
	}

	kp->symbol_name = name;
	kp->pre_handler = handler;

	ret = register_kprobe(kp);
	if (ret) {
		pr_err("susfs: register_%s kprobe failed: %d\n", name, ret);
		kfree(kp);
		return NULL;
	}

	return kp;
}

static void ksu_susfs_destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;

	if (!kp) {
		return;
	}

	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}

static void ksu_susfs_mount_runtime_disable(void)
{
	ksu_susfs_restore_fop_open(&proc_mounts_operations,
				   &ksu_susfs_orig_mounts_open);
	ksu_susfs_restore_fop_open(&proc_mountinfo_operations,
				   &ksu_susfs_orig_mountinfo_open);
	ksu_susfs_restore_fop_open(&proc_mountstats_operations,
				   &ksu_susfs_orig_mountstats_open);
	if (ksu_susfs_fdinfo_fops) {
		ksu_susfs_restore_fop_open(ksu_susfs_fdinfo_fops,
					   &ksu_susfs_orig_fdinfo_open);
		ksu_susfs_fdinfo_fops = NULL;
	}

	ksu_susfs_destroy_kretprobe(&ksu_susfs_vfs_create_mount_rp);
	ksu_susfs_destroy_kretprobe(&ksu_susfs_clone_mnt_rp);
	ksu_susfs_destroy_kprobe(&ksu_susfs_cleanup_mnt_kp);
	ksu_susfs_mount_clear_hidden_all();

	if (static_key_enabled(&ksu_susfs_mount_hide_enabled)) {
		static_branch_disable(&ksu_susfs_mount_hide_enabled);
	}

	ksu_susfs_mount_runtime_ready = false;
}

static int ksu_susfs_mount_runtime_enable(void)
{
	unsigned long addr;
	int err;

	err = ksu_susfs_patch_fop_open(&proc_mounts_operations,
				       ksu_susfs_mounts_open,
				       &ksu_susfs_orig_mounts_open);
	if (err) {
		goto err_out;
	}

	err = ksu_susfs_patch_fop_open(&proc_mountinfo_operations,
				       ksu_susfs_mountinfo_open,
				       &ksu_susfs_orig_mountinfo_open);
	if (err) {
		goto err_out;
	}

	err = ksu_susfs_patch_fop_open(&proc_mountstats_operations,
				       ksu_susfs_mountstats_open,
				       &ksu_susfs_orig_mountstats_open);
	if (err) {
		goto err_out;
	}

	ksu_susfs_vfs_create_mount_rp = ksu_susfs_init_kretprobe(
		"vfs_create_mount", ksu_susfs_vfs_create_mount_entry,
		ksu_susfs_vfs_create_mount_handler,
		sizeof(struct ksu_susfs_vfs_create_mount_ctx));
	if (!ksu_susfs_vfs_create_mount_rp) {
		err = -ENOENT;
		goto err_out;
	}

	ksu_susfs_clone_mnt_rp = ksu_susfs_init_kretprobe(
		"clone_mnt", ksu_susfs_clone_mnt_entry,
		ksu_susfs_clone_mnt_handler,
		sizeof(struct ksu_susfs_clone_mnt_ctx));
	if (!ksu_susfs_clone_mnt_rp) {
		err = -ENOENT;
		goto err_out;
	}

	ksu_susfs_cleanup_mnt_kp = ksu_susfs_init_kprobe(
		"cleanup_mnt", ksu_susfs_cleanup_mnt_pre);
	if (!ksu_susfs_cleanup_mnt_kp) {
		err = -ENOENT;
		goto err_out;
	}

	addr = find_kernel_symbol_exact("proc_fdinfo_file_operations");
	if (addr) {
		ksu_susfs_fdinfo_fops =
			(const struct file_operations *)addr;
		err = ksu_susfs_patch_fop_open(ksu_susfs_fdinfo_fops,
					       ksu_susfs_fdinfo_open,
					       &ksu_susfs_orig_fdinfo_open);
		if (err) {
			pr_warn("susfs: fdinfo wrapper unavailable: %d\n", err);
			ksu_susfs_fdinfo_fops = NULL;
		}
	}

	ksu_susfs_mount_runtime_ready = true;
	return 0;

err_out:
	ksu_susfs_mount_runtime_disable();
	return err;
}

static int ksu_susfs_cmdline_orig_show(struct seq_file *m, void *v)
{
	seq_puts(m, saved_command_line);
	seq_putc(m, '\n');
	return 0;
}

static int ksu_susfs_cmdline_show(struct seq_file *m, void *v)
{
	unsigned seq;
	char *cmdline;

	if (static_branch_unlikely(&ksu_susfs_cmdline_spoof_enabled)) {
		cmdline = kmalloc(sizeof(ksu_susfs_fake_cmdline), GFP_KERNEL);
		if (!cmdline) {
			seq_puts(m, ksu_susfs_fake_cmdline);
			seq_putc(m, '\n');
			return 0;
		}

		do {
			seq = read_seqbegin(&ksu_susfs_cmdline_lock);
			strscpy(cmdline, ksu_susfs_fake_cmdline,
				sizeof(ksu_susfs_fake_cmdline));
		} while (read_seqretry(&ksu_susfs_cmdline_lock, seq));
		seq_puts(m, cmdline);
		seq_putc(m, '\n');
		kfree(cmdline);
		return 0;
	}

	return ksu_susfs_cmdline_orig_show(m, v);
}

static int ksu_susfs_cmdline_replace(bool spoofed)
{
	struct proc_dir_entry *pde;

	remove_proc_entry("cmdline", NULL);
	pde = proc_create_single("cmdline", 0, NULL,
				 spoofed ? ksu_susfs_cmdline_show :
					   ksu_susfs_cmdline_orig_show);
	if (!pde) {
		return -ENOMEM;
	}

	return 0;
}

static long __nocfi ksu_susfs_hook_uname(int orig_nr, const struct pt_regs *regs)
{
	struct new_utsname __user *name =
		(struct new_utsname __user *)PT_REGS_PARM1(regs);
	long ret;

	ret = ksu_syscall_table[orig_nr](regs);
	if (ret || !static_branch_unlikely(&ksu_susfs_uname_spoof_enabled)) {
		return ret;
	}

	if (name) {
		struct new_utsname tmp;
		unsigned seq;

		if (copy_from_user(&tmp, name, sizeof(tmp))) {
			return ret;
		}

		do {
			seq = read_seqbegin(&ksu_susfs_uname_lock);
			strscpy(tmp.release, ksu_susfs_fake_uname.release,
				sizeof(tmp.release));
			strscpy(tmp.version, ksu_susfs_fake_uname.version,
				sizeof(tmp.version));
		} while (read_seqretry(&ksu_susfs_uname_lock, seq));

		if (copy_to_user(name, &tmp, sizeof(tmp))) {
			return -EFAULT;
		}
	}

	return ret;
}

bool ksu_susfs_handle_mount_compat(void __user *arg)
{
	struct ksu_susfs_hide_mounts_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	if (!ksu_susfs_mount_runtime_ready) {
		cmd.err = -EOPNOTSUPP;
		goto out;
	}

	if (cmd.enabled) {
		if (!static_key_enabled(&ksu_susfs_mount_hide_enabled)) {
			static_branch_enable(&ksu_susfs_mount_hide_enabled);
		}
	} else if (static_key_enabled(&ksu_susfs_mount_hide_enabled)) {
		static_branch_disable(&ksu_susfs_mount_hide_enabled);
	}

	cmd.err = 0;

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: mount compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_cmdline_compat(void __user *arg)
{
	struct ksu_susfs_cmdline_cmd *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		return true;
	}

	if (copy_from_user(cmd, arg, sizeof(*cmd))) {
		cmd->err = -EFAULT;
		goto out;
	}

	cmd->fake_cmdline_or_bootconfig
		[sizeof(cmd->fake_cmdline_or_bootconfig) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd->err = -EPERM;
		goto out;
	}

	if (!ksu_susfs_cmdline_ready) {
		cmd->err = -EOPNOTSUPP;
		goto out;
	}

	if (!strcmp(cmd->fake_cmdline_or_bootconfig, "default")) {
		if (static_key_enabled(&ksu_susfs_cmdline_spoof_enabled)) {
			static_branch_disable(&ksu_susfs_cmdline_spoof_enabled);
		}
		memset(ksu_susfs_fake_cmdline, 0, sizeof(ksu_susfs_fake_cmdline));
		cmd->err = 0;
		goto out;
	}

	if (!cmd->fake_cmdline_or_bootconfig[0]) {
		cmd->err = -EINVAL;
		goto out;
	}

	write_seqlock(&ksu_susfs_cmdline_lock);
	strscpy(ksu_susfs_fake_cmdline, cmd->fake_cmdline_or_bootconfig,
		sizeof(ksu_susfs_fake_cmdline));
	write_sequnlock(&ksu_susfs_cmdline_lock);

	if (!static_key_enabled(&ksu_susfs_cmdline_spoof_enabled)) {
		static_branch_enable(&ksu_susfs_cmdline_spoof_enabled);
	}

	cmd->err = 0;

out:
	if (copy_to_user(arg, cmd, sizeof(*cmd))) {
		pr_err("susfs: cmdline compat copy_to_user failed\n");
	}
	kfree(cmd);
	return true;
}

bool ksu_susfs_handle_uname_compat(void __user *arg)
{
	struct ksu_susfs_uname_cmd cmd;
	char release[sizeof(ksu_susfs_fake_uname.release)];
	char version[sizeof(ksu_susfs_fake_uname.version)];

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	cmd.release[sizeof(cmd.release) - 1] = '\0';
	cmd.version[sizeof(cmd.version) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	if (!ksu_susfs_uname_hook_ready) {
		cmd.err = -EOPNOTSUPP;
		goto out;
	}

	if (!cmd.release[0] || !cmd.version[0]) {
		cmd.err = -EINVAL;
		goto out;
	}

	if (!strcmp(cmd.release, "default")) {
		down_read(&uts_sem);
		strscpy(release, utsname()->release, sizeof(release));
		up_read(&uts_sem);
	} else {
		strscpy(release, cmd.release, sizeof(release));
	}

	if (!strcmp(cmd.version, "default")) {
		down_read(&uts_sem);
		strscpy(version, utsname()->version, sizeof(version));
		up_read(&uts_sem);
	} else {
		strscpy(version, cmd.version, sizeof(version));
	}

	write_seqlock(&ksu_susfs_uname_lock);
	strscpy(ksu_susfs_fake_uname.release, release,
		sizeof(ksu_susfs_fake_uname.release));
	strscpy(ksu_susfs_fake_uname.version, version,
		sizeof(ksu_susfs_fake_uname.version));
	write_sequnlock(&ksu_susfs_uname_lock);

	if (!static_key_enabled(&ksu_susfs_uname_spoof_enabled)) {
		static_branch_enable(&ksu_susfs_uname_spoof_enabled);
	}

	cmd.err = 0;

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: uname compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_avc_compat(void __user *arg)
{
	struct ksu_susfs_avc_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	cmd.err = ksu_set_feature(KSU_FEATURE_AVC_SPOOF, cmd.enabled ? 1 : 0);

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: avc compat copy_to_user failed\n");
	}
	return true;
}

int ksu_susfs_procfs_init(void)
{
	int ret;

	hash_init(ksu_susfs_hidden_mounts);
	memset(&ksu_susfs_fake_uname, 0, sizeof(ksu_susfs_fake_uname));
	memset(ksu_susfs_fake_cmdline, 0, sizeof(ksu_susfs_fake_cmdline));

	ret = ksu_susfs_cmdline_replace(true);
	if (ret) {
		pr_err("susfs: failed to replace /proc/cmdline: %d\n", ret);
	} else {
		ksu_susfs_cmdline_ready = true;
	}

	ret = ksu_susfs_mount_runtime_enable();
	if (ret) {
		pr_warn("susfs: mount runtime unavailable: %d\n", ret);
	}

#ifdef __NR_uname
	ret = ksu_register_syscall_hook(__NR_uname, ksu_susfs_hook_uname);
	if (ret && ret != -EEXIST) {
		pr_warn("susfs: uname hook unavailable: %d\n", ret);
	} else {
		ksu_susfs_uname_hook_ready = true;
	}
#endif

	return 0;
}

void ksu_susfs_procfs_exit(void)
{
	if (ksu_susfs_uname_hook_ready) {
#ifdef __NR_uname
		ksu_unregister_syscall_hook(__NR_uname);
#endif
		ksu_susfs_uname_hook_ready = false;
	}

	if (static_key_enabled(&ksu_susfs_uname_spoof_enabled)) {
		static_branch_disable(&ksu_susfs_uname_spoof_enabled);
	}

	if (ksu_susfs_cmdline_ready) {
		if (ksu_susfs_cmdline_replace(false)) {
			pr_err("susfs: failed to restore /proc/cmdline\n");
		}
		ksu_susfs_cmdline_ready = false;
	}

	if (static_key_enabled(&ksu_susfs_cmdline_spoof_enabled)) {
		static_branch_disable(&ksu_susfs_cmdline_spoof_enabled);
	}

	ksu_susfs_mount_runtime_disable();
}
