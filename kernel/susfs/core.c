#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/jhash.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/xattr.h>

#include "compat/kernel_compat.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "susfs/compat.h"
#include "susfs/kstat.h"
#include "susfs/procfs.h"
#include "susfs/susfs.h"
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
#include "nomount/nomount.h"
#endif

#define KSU_SUSFS_HASH_BITS 8
#define KSU_SUSFS_SB_HASH_BITS 4
#define KSU_SUSFS_SIGNATURE 0x53555346534b5355ULL
#define KSU_SUSFS_VARIANT "hookless"
#define KSU_SUSFS_VERSION "v0.2"

static const char *const ksu_susfs_default_hide_paths[] = {
	"/product/overlay/LineageSDKOverlaySM8350.apk",
};

enum ksu_susfs_rule_type {
	KSU_SUSFS_RULE_HIDE = 0,
	KSU_SUSFS_RULE_REDIRECT = 1,
};

struct ksu_susfs_redirect_priv {
	struct inode *backend_inode;
	char backend_path[KSU_SUSFS_MAX_PATHNAME];
	char visible_path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_file_proxy {
	struct file *backend_file;
};

struct ksu_susfs_rule {
	struct hlist_node path_node;
	struct list_head parent_list;
	struct list_head free_list;
	struct rcu_head rcu;
	u32 path_hash;
	s8 uid_scheme;
	u8 type;
	char name[KSU_SUSFS_MAX_PATHNAME];
	char visible_path[KSU_SUSFS_MAX_PATHNAME];
	char backend_path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_parent {
	struct hlist_node node;
	struct list_head all_list;
	struct list_head rules;
	struct inode *dir_inode;
	char path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_iop {
	struct inode_operations fake_iop;
	const struct inode_operations *orig_iop;
	u64 signature;
	struct ksu_susfs_parent *parent;
	bool had_private_flag;
	struct rcu_head rcu;
};

struct ksu_susfs_fop {
	struct file_operations fake_fop;
	const struct file_operations *orig_fop;
	u64 signature;
	struct ksu_susfs_parent *parent;
	struct rcu_head rcu;
};

struct ksu_susfs_sop {
	struct super_operations fake_sop;
	const struct super_operations *orig_sop;
	const struct xattr_handler **orig_xattr;
	const struct xattr_handler **fake_xattr;
	u64 signature;
	struct super_block *sb;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct ksu_susfs_xattr_proxy {
	struct xattr_handler fake;
	const struct xattr_handler *orig;
};

struct ksu_susfs_proxy_ctx {
	struct dir_context ctx;
	struct dir_context *orig_ctx;
	struct ksu_susfs_parent *parent;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	bool nomount_active;
#endif
};

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
struct ksu_susfs_redirect_proxy_ctx {
	struct dir_context ctx;
	struct dir_context *orig_ctx;
	const char *visible_path;
};
#endif

static DEFINE_HASHTABLE(ksu_susfs_rules_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_parents_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_sb_ht, KSU_SUSFS_SB_HASH_BITS);
static LIST_HEAD(ksu_susfs_parent_list);
static DEFINE_MUTEX(ksu_susfs_lock);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_active);
static atomic_t ksu_susfs_rule_count = ATOMIC_INIT(0);

#define __ksu_susfs_get(ptr, type, member)                                   \
	({                                                                    \
		type *__target = NULL;                                        \
		u64 __sig = 0;                                                \
		if (likely(ptr)) {                                            \
			type *__outer = container_of(ptr, type, member);      \
			if (copy_from_kernel_nofault(&__sig,                  \
					     &__outer->signature,         \
					     sizeof(__sig)) == 0 &&       \
			    __sig == KSU_SUSFS_SIGNATURE) {                 \
				__target = __outer;                         \
			}                                                     \
		}                                                             \
		__target;                                                     \
	})

static u32 ksu_susfs_hash_path(const char *path)
{
	return jhash(path, strlen(path), 0);
}

static bool ksu_susfs_should_skip(void)
{
	if (!static_branch_unlikely(&ksu_susfs_active)) {
		return true;
	}
	if (unlikely(in_interrupt() || oops_in_progress)) {
		return true;
	}
	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) {
		return true;
	}
	return false;
}

static bool ksu_susfs_should_hide_current(void)
{
	uid_t uid;

	if (ksu_susfs_should_skip()) {
		return false;
	}

	uid = current_uid().val;
	if (!is_appuid(uid) && !is_isolated_process(uid)) {
		return false;
	}

	return ksu_uid_should_umount(uid);
}

static bool ksu_susfs_uid_scheme_matches(int uid_scheme)
{
	uid_t uid;

	if (ksu_susfs_should_skip()) {
		return false;
	}

	uid = current_uid().val;

	switch (uid_scheme) {
	case KSU_SUSFS_UID_NON_APP_PROC:
		return (uid % PER_USER_RANGE) < FIRST_APPLICATION_UID;
	case KSU_SUSFS_UID_ROOT_PROC_EXCEPT_SU_PROC:
		return uid == 0 && !is_ksu_domain();
	case KSU_SUSFS_UID_NON_SU_PROC:
		return !is_ksu_domain();
	case KSU_SUSFS_UID_UMOUNTED_APP_PROC:
		return (is_appuid(uid) || is_isolated_process(uid)) &&
		       ksu_uid_should_umount(uid);
	case KSU_SUSFS_UID_UMOUNTED_PROC:
		return (uid == 0 && !is_ksu_domain()) ||
		       ksu_uid_should_umount(uid);
	default:
		return false;
	}
}

static int ksu_susfs_normalize_path(char *dst, size_t dst_size, const char *src)
{
	size_t len;

	if (!src || !*src || src[0] != '/') {
		return -EINVAL;
	}

	if (strscpy(dst, src, dst_size) < 0) {
		return -ENAMETOOLONG;
	}

	len = strlen(dst);
	while (len > 1 && dst[len - 1] == '/') {
		dst[len - 1] = '\0';
		len--;
	}

	return 0;
}

static int ksu_susfs_split_path(const char *path, char *parent, size_t parent_size,
				char *name, size_t name_size)
{
	const char *slash;
	size_t parent_len;

	if (!path || path[0] != '/' || path[1] == '\0') {
		return -EINVAL;
	}

	slash = strrchr(path, '/');
	if (!slash || slash[1] == '\0') {
		return -EINVAL;
	}

	if (strscpy(name, slash + 1, name_size) < 0) {
		return -ENAMETOOLONG;
	}

	if (slash == path) {
		return strscpy(parent, "/", parent_size) < 0 ? -ENAMETOOLONG : 0;
	}

	parent_len = slash - path;
	if (parent_len >= parent_size) {
		return -ENAMETOOLONG;
	}

	memcpy(parent, path, parent_len);
	parent[parent_len] = '\0';
	return 0;
}

static int ksu_susfs_resolve_path(const char *path, struct path *out)
{
	const struct cred *saved;
	int err;

	saved = override_creds(ksu_cred);
	err = kern_path(path, 0, out);
	revert_creds(saved);
	return err;
}

static struct ksu_susfs_parent *ksu_susfs_find_parent_locked(const char *path)
{
	struct ksu_susfs_parent *parent;
	u32 hash = ksu_susfs_hash_path(path);

	hash_for_each_possible(ksu_susfs_parents_ht, parent, node, hash) {
		if (!strcmp(parent->path, path)) {
			return parent;
		}
	}

	return NULL;
}

static struct ksu_susfs_rule *ksu_susfs_find_rule_locked(const char *path)
{
	struct ksu_susfs_rule *rule;
	u32 hash = ksu_susfs_hash_path(path);

	hash_for_each_possible(ksu_susfs_rules_ht, rule, path_node, hash) {
		if (!strcmp(rule->visible_path, path)) {
			return rule;
		}
	}

	return NULL;
}

static struct ksu_susfs_rule *
ksu_susfs_lookup_rule_rcu(struct ksu_susfs_parent *parent, const char *name,
			  size_t len)
{
	struct ksu_susfs_rule *rule;

	list_for_each_entry_rcu(rule, &parent->rules, parent_list) {
		if (rule->name[len] == '\0' &&
		    !memcmp(rule->name, name, len)) {
			return rule;
		}
	}

	return NULL;
}

static bool ksu_susfs_parent_has_hide_rules_rcu(struct ksu_susfs_parent *parent)
{
	struct ksu_susfs_rule *rule;

	list_for_each_entry_rcu(rule, &parent->rules, parent_list) {
		if (rule->type == KSU_SUSFS_RULE_HIDE) {
			return true;
		}
	}

	return false;
}

static void ksu_susfs_invalidate_path(const char *path, const char *parent_path)
{
	struct path resolved;

	if (!ksu_susfs_resolve_path(path, &resolved)) {
		shrink_dcache_parent(resolved.dentry);
		d_drop(resolved.dentry);
		path_put(&resolved);
		return;
	}

	if (!ksu_susfs_resolve_path(parent_path, &resolved)) {
		shrink_dcache_parent(resolved.dentry);
		path_put(&resolved);
	}
}

static inline void ksu_susfs_sync_inode_times(struct inode *v_inode,
					      struct inode *r_inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	v_inode->i_atime_sec = r_inode->i_atime_sec;
	v_inode->i_atime_nsec = r_inode->i_atime_nsec;
	v_inode->i_mtime_sec = r_inode->i_mtime_sec;
	v_inode->i_mtime_nsec = r_inode->i_mtime_nsec;
	v_inode->i_ctime_sec = r_inode->i_ctime_sec;
	v_inode->i_ctime_nsec = r_inode->i_ctime_nsec;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	v_inode->i_atime = r_inode->i_atime;
	v_inode->i_mtime = r_inode->i_mtime;
	inode_set_ctime_to_ts(v_inode, inode_get_ctime(r_inode));
#else
	v_inode->i_atime = r_inode->i_atime;
	v_inode->i_mtime = r_inode->i_mtime;
	v_inode->i_ctime = r_inode->i_ctime;
#endif
}

static struct inode *ksu_susfs_backend_inode(struct inode *inode)
{
	struct ksu_susfs_redirect_priv *priv = inode->i_private;

	if (!priv) {
		return NULL;
	}

	return priv->backend_inode;
}

static struct ksu_susfs_redirect_priv *
ksu_susfs_backend_priv(struct inode *inode)
{
	return inode->i_private;
}

static struct file *ksu_susfs_proxy_backend_file(struct file *file)
{
	struct ksu_susfs_file_proxy *proxy = file->private_data;

	return proxy ? proxy->backend_file : NULL;
}

static loff_t ksu_susfs_proxy_llseek(struct file *file, loff_t offset,
				      int whence)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);
	loff_t ret;

	if (!backend_file) {
		return -EIO;
	}

	ret = vfs_llseek(backend_file, offset, whence);
	if (ret >= 0) {
		file->f_pos = ret;
	}

	return ret;
}

static ssize_t ksu_susfs_proxy_read(struct file *file, char __user *buf,
				    size_t count, loff_t *pos)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file) {
		return -EIO;
	}

	return vfs_read(backend_file, buf, count, pos);
}

static ssize_t ksu_susfs_proxy_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *pos)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file) {
		return -EIO;
	}

	return vfs_write(backend_file, buf, count, pos);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
static __poll_t ksu_susfs_proxy_poll(struct file *file,
				     struct poll_table_struct *wait)
#else
static unsigned int ksu_susfs_proxy_poll(struct file *file,
					 struct poll_table_struct *wait)
#endif
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->poll) {
		return 0;
	}

	return backend_file->f_op->poll(backend_file, wait);
}

static long ksu_susfs_proxy_unlocked_ioctl(struct file *file, unsigned int cmd,
					   unsigned long arg)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op ||
	    !backend_file->f_op->unlocked_ioctl) {
		return -ENOTTY;
	}

	return backend_file->f_op->unlocked_ioctl(backend_file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long ksu_susfs_proxy_compat_ioctl(struct file *file, unsigned int cmd,
					 unsigned long arg)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op ||
	    !backend_file->f_op->compat_ioctl) {
		return -ENOTTY;
	}

	return backend_file->f_op->compat_ioctl(backend_file, cmd, arg);
}
#endif

static int ksu_susfs_proxy_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->mmap) {
		return -ENODEV;
	}

	return backend_file->f_op->mmap(backend_file, vma);
}

static int ksu_susfs_proxy_flush(struct file *file, fl_owner_t id)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->flush) {
		return 0;
	}

	return backend_file->f_op->flush(backend_file, id);
}

static int ksu_susfs_proxy_fsync(struct file *file, loff_t start, loff_t end,
				 int datasync)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->fsync) {
		return -EINVAL;
	}

	return backend_file->f_op->fsync(backend_file, start, end, datasync);
}

static int ksu_susfs_proxy_fasync(int fd, struct file *file, int on)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->fasync) {
		return -EINVAL;
	}

	return backend_file->f_op->fasync(fd, backend_file, on);
}

static int ksu_susfs_proxy_lock(struct file *file, int cmd,
				struct file_lock *fl)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->lock) {
		return -EINVAL;
	}

	return backend_file->f_op->lock(backend_file, cmd, fl);
}

static int ksu_susfs_proxy_flock(struct file *file, int cmd,
				 struct file_lock *fl)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op || !backend_file->f_op->flock) {
		return -EINVAL;
	}

	return backend_file->f_op->flock(backend_file, cmd, fl);
}

static ssize_t ksu_susfs_proxy_splice_read(struct file *file, loff_t *ppos,
					   struct pipe_inode_info *pipe,
					   size_t len, unsigned int flags)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op ||
	    !backend_file->f_op->splice_read) {
		return -EINVAL;
	}

	return backend_file->f_op->splice_read(backend_file, ppos, pipe, len,
					       flags);
}

static ssize_t ksu_susfs_proxy_splice_write(struct pipe_inode_info *pipe,
					    struct file *file, loff_t *ppos,
					    size_t len, unsigned int flags)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op ||
	    !backend_file->f_op->splice_write) {
		return -EINVAL;
	}

	return backend_file->f_op->splice_write(pipe, backend_file, ppos, len,
						flags);
}

static long ksu_susfs_proxy_fallocate(struct file *file, int mode,
				      loff_t offset, loff_t len)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (!backend_file || !backend_file->f_op ||
	    !backend_file->f_op->fallocate) {
		return -EOPNOTSUPP;
	}

	return backend_file->f_op->fallocate(backend_file, mode, offset, len);
}

static void ksu_susfs_proxy_show_fdinfo(struct seq_file *m, struct file *file)
{
	struct file *backend_file = ksu_susfs_proxy_backend_file(file);

	if (backend_file && backend_file->f_op && backend_file->f_op->show_fdinfo) {
		backend_file->f_op->show_fdinfo(m, backend_file);
	}
}

static int ksu_susfs_proxy_release(struct inode *inode, struct file *file)
{
	struct ksu_susfs_file_proxy *proxy = file->private_data;

	if (proxy) {
		if (proxy->backend_file) {
			fput(proxy->backend_file);
		}
		kfree(proxy);
		file->private_data = NULL;
	}

	return 0;
}

static const struct file_operations ksu_susfs_proxy_file_fops = {
	.llseek = ksu_susfs_proxy_llseek,
	.read = ksu_susfs_proxy_read,
	.write = ksu_susfs_proxy_write,
	.poll = ksu_susfs_proxy_poll,
	.unlocked_ioctl = ksu_susfs_proxy_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ksu_susfs_proxy_compat_ioctl,
#endif
	.mmap = ksu_susfs_proxy_mmap,
	.flush = ksu_susfs_proxy_flush,
	.release = ksu_susfs_proxy_release,
	.fsync = ksu_susfs_proxy_fsync,
	.fasync = ksu_susfs_proxy_fasync,
	.lock = ksu_susfs_proxy_lock,
	.flock = ksu_susfs_proxy_flock,
	.splice_read = ksu_susfs_proxy_splice_read,
	.splice_write = ksu_susfs_proxy_splice_write,
	.fallocate = ksu_susfs_proxy_fallocate,
	.show_fdinfo = ksu_susfs_proxy_show_fdinfo,
};

static int ksu_susfs_file_open(struct inode *inode, struct file *file)
{
	struct ksu_susfs_redirect_priv *priv = ksu_susfs_backend_priv(inode);
	struct ksu_susfs_file_proxy *proxy;
	struct file *backend_file;
	const struct cred *saved = NULL;
	int flags;

	if (!priv || !priv->backend_inode || !priv->backend_inode->i_fop) {
		return -ENODEV;
	}

	proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
	if (!proxy) {
		return -ENOMEM;
	}

	flags = file->f_flags;
	if (ksu_cred) {
		saved = override_creds(ksu_cred);
	}
	backend_file = filp_open(priv->backend_path, flags, 0);
	if (saved) {
		revert_creds(saved);
	}
	if (IS_ERR(backend_file)) {
		kfree(proxy);
		return PTR_ERR(backend_file);
	}

	proxy->backend_file = backend_file;
	file->private_data = proxy;
	file->f_mapping = backend_file->f_mapping;
	replace_fops(file, fops_get(&ksu_susfs_proxy_file_fops));
	return 0;
}

static int ksu_susfs_dir_open(struct inode *inode, struct file *file)
{
	struct inode *backend_inode = ksu_susfs_backend_inode(inode);
	int ret = 0;

	if (backend_inode && backend_inode->i_fop && backend_inode->i_fop->open) {
		file->f_inode = backend_inode;
		ret = backend_inode->i_fop->open(backend_inode, file);
		file->f_inode = inode;
	}

	return ret;
}

static int ksu_susfs_dir_release(struct inode *inode, struct file *file)
{
	struct inode *backend_inode = ksu_susfs_backend_inode(inode);
	int ret = 0;

	if (backend_inode && backend_inode->i_fop &&
	    backend_inode->i_fop->release) {
		file->f_inode = backend_inode;
		ret = backend_inode->i_fop->release(backend_inode, file);
		file->f_inode = inode;
	}

	return ret;
}

static int ksu_susfs_call_iterate(const struct file_operations *fops,
				  struct file *file,
				  struct dir_context *ctx)
{
#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
	if (fops->iterate_shared) {
		return fops->iterate_shared(file, ctx);
	}
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
	if (fops->iterate) {
		return fops->iterate(file, ctx);
	}
#endif
	return -ENOTDIR;
}

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
static KSU_SUSFS_ACTOR_RET
ksu_susfs_redirect_actor_proxy(struct dir_context *ctx, const char *name,
			       int namelen, loff_t offset, u64 ino,
			       unsigned int d_type)
{
	struct ksu_susfs_redirect_proxy_ctx *proxy =
		container_of(ctx, struct ksu_susfs_redirect_proxy_ctx, ctx);
	KSU_SUSFS_ACTOR_RET ret;

	if (ksu_nomount_filter_child(proxy->visible_path, name, namelen)) {
		return KSU_SUSFS_ACTOR_CONTINUE;
	}

	proxy->orig_ctx->pos = proxy->ctx.pos;
	ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino,
				     d_type);
	proxy->ctx.pos = proxy->orig_ctx->pos;
	return ret;
}
#endif

static int ksu_susfs_dir_iterate_shared(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct inode *backend_inode = ksu_susfs_backend_inode(inode);
	struct ksu_susfs_redirect_priv *priv = ksu_susfs_backend_priv(inode);
	int ret = -ENOTDIR;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	bool nomount_active = false;
#endif

	if (backend_inode && backend_inode->i_fop) {
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
		if (priv && ksu_nomount_dir_is_internal(priv->visible_path)) {
			ksu_nomount_emit_children(priv->visible_path, ctx);
			return 0;
		}

			nomount_active = priv && ksu_nomount_parent_active(priv->visible_path);
			if (nomount_active) {
				struct ksu_susfs_redirect_proxy_ctx proxy_ctx;

				if (ksu_nomount_pos_is_magic(ctx->pos)) {
					ksu_nomount_emit_children(priv->visible_path, ctx);
					return 0;
				}

				memset(&proxy_ctx, 0, sizeof(proxy_ctx));
				proxy_ctx.ctx.actor = ksu_susfs_redirect_actor_proxy;
				proxy_ctx.ctx.pos = ctx->pos;
				proxy_ctx.orig_ctx = ctx;
			proxy_ctx.visible_path = priv->visible_path;
			file->f_inode = backend_inode;
			ret = ksu_susfs_call_iterate(backend_inode->i_fop, file,
						     &proxy_ctx.ctx);
			file->f_inode = inode;
			ctx->pos = proxy_ctx.ctx.pos;
			if (ret >= 0) {
				ksu_nomount_emit_children(priv->visible_path, ctx);
			}
			return ret;
		}
#endif
		file->f_inode = backend_inode;
		ret = ksu_susfs_call_iterate(backend_inode->i_fop, file, ctx);
		file->f_inode = inode;
	}

	return ret;
}

#ifdef KSU_SUSFS_HAS_ITERATE
static int ksu_susfs_dir_iterate(struct file *file, struct dir_context *ctx)
{
	return ksu_susfs_dir_iterate_shared(file, ctx);
}
#endif

static const struct file_operations ksu_susfs_file_fops = {
	.open = ksu_susfs_file_open,
};

static int ksu_susfs_file_getattr(KSU_SUSFS_GETATTR_ARGS)
{
	struct inode *v_inode;
	struct inode *backend_inode;

	KSU_SUSFS_GETATTR_PREP();
	v_inode = d_backing_inode(KSU_SUSFS_GETATTR_DENTRY);
	backend_inode = ksu_susfs_backend_inode(v_inode);

	if (!backend_inode) {
		return -EIO;
	}

	v_inode->i_size = i_size_read(backend_inode);
	v_inode->i_blocks = backend_inode->i_blocks;
	v_inode->i_mode = backend_inode->i_mode;
	v_inode->i_uid = backend_inode->i_uid;
	v_inode->i_gid = backend_inode->i_gid;
	ksu_susfs_sync_inode_times(v_inode, backend_inode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	generic_fillattr(KSU_SUSFS_IDMAP_CALL request_mask, v_inode, stat);
#else
	generic_fillattr(KSU_SUSFS_IDMAP_CALL v_inode, stat);
#endif

	return 0;
}

static int ksu_susfs_file_setattr(KSU_SUSFS_IDMAP_ARG struct dentry *dentry,
				  struct iattr *attr)
{
	struct inode *v_inode = d_inode(dentry);
	struct inode *backend_inode = ksu_susfs_backend_inode(v_inode);
	struct dentry *backend_dentry;
	int err;

	if (!backend_inode) {
		return -EIO;
	}

	backend_dentry = d_find_alias(backend_inode);
	if (!backend_dentry) {
		backend_dentry = d_obtain_alias(igrab(backend_inode));
		if (IS_ERR(backend_dentry)) {
			return PTR_ERR(backend_dentry);
		}
	}

	inode_lock(backend_inode);
	err = notify_change(KSU_SUSFS_IDMAP_CALL backend_dentry, attr, NULL);
	inode_unlock(backend_inode);

	if (!err) {
		v_inode->i_size = i_size_read(backend_inode);
		v_inode->i_blocks = backend_inode->i_blocks;
		v_inode->i_mode = backend_inode->i_mode;
		v_inode->i_uid = backend_inode->i_uid;
		v_inode->i_gid = backend_inode->i_gid;
		ksu_susfs_sync_inode_times(v_inode, backend_inode);
	}

	dput(backend_dentry);
	return err;
}

static ssize_t ksu_susfs_file_listxattr(struct dentry *dentry, char *buffer,
					size_t size)
{
	struct inode *v_inode = d_inode(dentry);
	struct inode *backend_inode = ksu_susfs_backend_inode(v_inode);
	struct dentry *backend_dentry;
	ssize_t ret;

	if (!backend_inode || !backend_inode->i_op ||
	    !backend_inode->i_op->listxattr) {
		return -EOPNOTSUPP;
	}

	backend_dentry = d_find_alias(backend_inode);
	if (!backend_dentry) {
		struct inode *grabbed = igrab(backend_inode);

		if (!grabbed) {
			return -ENODATA;
		}

		backend_dentry = d_obtain_alias(grabbed);
		if (IS_ERR(backend_dentry)) {
			return PTR_ERR(backend_dentry);
		}
	}

	ret = backend_inode->i_op->listxattr(backend_dentry, buffer, size);
	dput(backend_dentry);
	return ret;
}

static const char *ksu_susfs_symlink_get_link(struct dentry *dentry,
					      struct inode *inode,
					      struct delayed_call *done)
{
	struct inode *backend_inode = ksu_susfs_backend_inode(inode);

	if (!dentry) {
		return ERR_PTR(-ECHILD);
	}

	if (backend_inode && backend_inode->i_op && backend_inode->i_op->get_link) {
		return backend_inode->i_op->get_link(dentry, backend_inode, done);
	}

	return ERR_PTR(-EINVAL);
}

static int ksu_susfs_build_child_path(const char *parent, const struct qstr *name,
				      char *out, size_t out_size)
{
	size_t parent_len = strlen(parent);
	size_t total = parent_len + 1 + name->len + 1;

	if (parent_len == 1 && parent[0] == '/') {
		total--;
	}

	if (total > out_size) {
		return -ENAMETOOLONG;
	}

	if (parent_len == 1 && parent[0] == '/') {
		out[0] = '/';
		memcpy(out + 1, name->name, name->len);
		out[name->len + 1] = '\0';
		return 0;
	}

	memcpy(out, parent, parent_len);
	out[parent_len] = '/';
	memcpy(out + parent_len + 1, name->name, name->len);
	out[parent_len + 1 + name->len] = '\0';
	return 0;
}

static struct inode *ksu_susfs_create_redirect_inode(struct super_block *sb,
						     struct inode *backend_inode,
						     const char *backend_path,
						     const char *visible_path,
						     u32 ino_seed);

static struct dentry *ksu_susfs_dir_lookup(struct inode *dir, struct dentry *dentry,
					   unsigned int flags)
{
	struct ksu_susfs_redirect_priv *priv = ksu_susfs_backend_priv(dir);
	struct path backend_path;
	struct inode *inode;
	char visible_child_path[KSU_SUSFS_MAX_PATHNAME];
	char child_path[KSU_SUSFS_MAX_PATHNAME];
	int err;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	unsigned int nomount_type;
	unsigned long nomount_ino;
	struct inode *nomount_inode = NULL;
	int nomount_match;
#endif

	if (!priv || !priv->backend_inode || !S_ISDIR(priv->backend_inode->i_mode)) {
		return ERR_PTR(-ENOTDIR);
	}

	err = ksu_susfs_build_child_path(priv->visible_path, &dentry->d_name,
					 visible_child_path,
					 sizeof(visible_child_path));
	if (err) {
		return ERR_PTR(err);
	}

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	nomount_match = ksu_nomount_lookup_child(
		priv->visible_path, dentry->d_name.name, dentry->d_name.len,
		child_path, sizeof(child_path), &nomount_inode, &nomount_ino,
		&nomount_type);
	if (nomount_match == KSU_NOMOUNT_LOOKUP_WHITEOUT) {
		d_add(dentry, NULL);
		return NULL;
	}
	if (nomount_match == KSU_NOMOUNT_LOOKUP_REDIRECT) {
		if (nomount_type != DT_REG && nomount_type != DT_DIR &&
		    nomount_type != DT_LNK) {
			if (nomount_inode) {
				iput(nomount_inode);
			}
			return ERR_PTR(-EOPNOTSUPP);
		}

		inode = nomount_inode;
		if (!inode || (!S_ISREG(inode->i_mode) &&
			       !S_ISDIR(inode->i_mode) &&
			       !S_ISLNK(inode->i_mode))) {
			if (nomount_inode) {
				iput(nomount_inode);
			}
			return ERR_PTR(-EOPNOTSUPP);
		}

		inode = ksu_susfs_create_redirect_inode(
			dir->i_sb, inode, child_path, visible_child_path,
			(u32)nomount_ino);
		iput(nomount_inode);
		if (!inode) {
			return ERR_PTR(-ENOMEM);
		}

		return d_splice_alias(inode, dentry);
	}
#endif

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	if (ksu_nomount_dir_is_internal(priv->visible_path)) {
		d_add(dentry, NULL);
		return NULL;
	}
#endif

	err = ksu_susfs_build_child_path(priv->backend_path, &dentry->d_name,
					 child_path, sizeof(child_path));
	if (err) {
		return ERR_PTR(err);
	}

	err = ksu_susfs_resolve_path(child_path, &backend_path);
	if (err) {
		if (err == -ENOENT) {
			d_add(dentry, NULL);
			return NULL;
		}
		return ERR_PTR(err);
	}

	inode = d_backing_inode(backend_path.dentry);
	if (!inode || (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode) &&
		       !S_ISLNK(inode->i_mode))) {
		path_put(&backend_path);
		return ERR_PTR(-EOPNOTSUPP);
	}

	inode = ksu_susfs_create_redirect_inode(dir->i_sb, inode, child_path,
						visible_child_path,
						ksu_susfs_hash_path(child_path));
	path_put(&backend_path);
	if (!inode) {
		return ERR_PTR(-ENOMEM);
	}

	return d_splice_alias(inode, dentry);
}

static const struct inode_operations ksu_susfs_file_iops = {
	.getattr = ksu_susfs_file_getattr,
	.setattr = ksu_susfs_file_setattr,
	.listxattr = ksu_susfs_file_listxattr,
};

static const struct inode_operations ksu_susfs_symlink_iops = {
	.getattr = ksu_susfs_file_getattr,
	.setattr = ksu_susfs_file_setattr,
	.get_link = ksu_susfs_symlink_get_link,
	.listxattr = ksu_susfs_file_listxattr,
};

static const struct file_operations ksu_susfs_dir_fops = {
	.open = ksu_susfs_dir_open,
	.release = ksu_susfs_dir_release,
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
	.iterate_shared = ksu_susfs_dir_iterate_shared,
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
	.iterate = ksu_susfs_dir_iterate,
#endif
};

static const struct inode_operations ksu_susfs_dir_iops = {
	.lookup = ksu_susfs_dir_lookup,
	.getattr = ksu_susfs_file_getattr,
	.setattr = ksu_susfs_file_setattr,
	.listxattr = ksu_susfs_file_listxattr,
};

static struct inode *ksu_susfs_create_redirect_inode(struct super_block *sb,
						     struct inode *backend_inode,
						     const char *backend_path,
						     const char *visible_path,
						     u32 ino_seed)
{
	struct inode *inode;
	struct ksu_susfs_redirect_priv *priv;

	inode = new_inode(sb);
	if (!inode) {
		return NULL;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		iput(inode);
		return NULL;
	}

	priv->backend_inode = igrab(backend_inode);
	if (!priv->backend_inode ||
	    strscpy(priv->backend_path, backend_path,
		    sizeof(priv->backend_path)) < 0 ||
	    strscpy(priv->visible_path, visible_path ? visible_path : backend_path,
		    sizeof(priv->visible_path)) < 0) {
		if (priv->backend_inode) {
			iput(priv->backend_inode);
		}
		kfree(priv);
		iput(inode);
		return NULL;
	}

	inode->i_ino = (unsigned long)ino_seed;
	inode->i_mode = backend_inode->i_mode;
	inode->i_size = i_size_read(backend_inode);
	inode->i_blocks = backend_inode->i_blocks;
	inode->i_uid = backend_inode->i_uid;
	inode->i_gid = backend_inode->i_gid;
	ksu_susfs_sync_inode_times(inode, backend_inode);

	if (S_ISDIR(backend_inode->i_mode)) {
		inode->i_op = &ksu_susfs_dir_iops;
		inode->i_fop = &ksu_susfs_dir_fops;
	} else if (S_ISLNK(backend_inode->i_mode) ||
		   (backend_inode->i_op && backend_inode->i_op->get_link)) {
		inode->i_op = &ksu_susfs_symlink_iops;
		inode->i_fop = &ksu_susfs_file_fops;
	} else {
		inode->i_op = &ksu_susfs_file_iops;
		inode->i_fop = &ksu_susfs_file_fops;
	}

	inode->i_mapping = backend_inode->i_mapping;
	inode->i_private = priv;
	inode->i_flags |= S_PRIVATE | S_NOATIME | S_NOCMTIME | S_NOSEC;
	inode->i_opflags |= IOP_XATTR;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	INIT_LIST_HEAD(&inode->i_data.i_private_list);
#else
	INIT_LIST_HEAD(&inode->i_data.private_list);
#endif
	insert_inode_hash(inode);
	return inode;
}

static int ksu_susfs_xattr_get(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, void *buffer, size_t size
			       KSU_SUSFS_XATTR_FLAGS_ARG)
{
	struct ksu_susfs_xattr_proxy *proxy =
		container_of(handler, struct ksu_susfs_xattr_proxy, fake);

	if (inode->i_op == &ksu_susfs_file_iops ||
	    inode->i_op == &ksu_susfs_dir_iops ||
	    inode->i_op == &ksu_susfs_symlink_iops) {
		struct inode *backend_inode = ksu_susfs_backend_inode(inode);

		if (!backend_inode) {
			return -ENODATA;
		}
		if (backend_inode->i_sb != inode->i_sb) {
			return -ENODATA;
		}
		return proxy->orig->get(proxy->orig, dentry, backend_inode, name,
					buffer, size KSU_SUSFS_XATTR_FLAGS_VAL);
	}

	return proxy->orig->get(proxy->orig, dentry, inode, name, buffer, size
				KSU_SUSFS_XATTR_FLAGS_VAL);
}

static int ksu_susfs_xattr_set(const struct xattr_handler *handler,
			       KSU_SUSFS_IDMAP_ARG struct dentry *dentry,
			       struct inode *inode, const char *name,
			       const void *buffer, size_t size, int flags)
{
	struct ksu_susfs_xattr_proxy *proxy =
		container_of(handler, struct ksu_susfs_xattr_proxy, fake);

	if (inode->i_op == &ksu_susfs_file_iops ||
	    inode->i_op == &ksu_susfs_dir_iops ||
	    inode->i_op == &ksu_susfs_symlink_iops) {
		struct inode *backend_inode = ksu_susfs_backend_inode(inode);

		if (!backend_inode) {
			return -ENODATA;
		}
		if (backend_inode->i_sb != inode->i_sb) {
			return -EOPNOTSUPP;
		}
		return proxy->orig->set(proxy->orig, KSU_SUSFS_IDMAP_CALL dentry,
					backend_inode, name, buffer, size, flags);
	}

	return proxy->orig->set(proxy->orig, KSU_SUSFS_IDMAP_CALL dentry, inode,
				name, buffer, size, flags);
}

static KSU_SUSFS_ACTOR_RET
ksu_susfs_actor_proxy(struct dir_context *ctx, const char *name, int namelen,
			      loff_t offset, u64 ino, unsigned int d_type)
{
	struct ksu_susfs_proxy_ctx *proxy =
		container_of(ctx, struct ksu_susfs_proxy_ctx, ctx);
	struct ksu_susfs_rule *rule;
	KSU_SUSFS_ACTOR_RET ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	if (proxy->nomount_active &&
	    ksu_nomount_filter_child(proxy->parent->path, name, namelen)) {
		return KSU_SUSFS_ACTOR_CONTINUE;
	}
#endif

	rcu_read_lock();
	rule = ksu_susfs_lookup_rule_rcu(proxy->parent, name, namelen);
	if (rule && rule->type == KSU_SUSFS_RULE_HIDE &&
	    ksu_susfs_should_hide_current()) {
		rcu_read_unlock();
		return KSU_SUSFS_ACTOR_CONTINUE;
	}
	rcu_read_unlock();

	proxy->orig_ctx->pos = proxy->ctx.pos;
	ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino,
				     d_type);
	proxy->ctx.pos = proxy->orig_ctx->pos;
	return ret;
}

static int ksu_susfs_hijacked_iterate_shared(struct file *file,
						     struct dir_context *ctx)
{
	struct ksu_susfs_fop *wrapped =
		__ksu_susfs_get(smp_load_acquire(&file->f_op),
				struct ksu_susfs_fop, fake_fop);
	struct ksu_susfs_proxy_ctx proxy_ctx;
	bool susfs_active;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	bool nomount_active;
#endif
	int ret;

	if (!wrapped || !wrapped->orig_fop) {
		return -ENOTDIR;
	}

	susfs_active = false;
	if (ksu_susfs_should_hide_current()) {
		rcu_read_lock();
		susfs_active =
			ksu_susfs_parent_has_hide_rules_rcu(wrapped->parent);
		rcu_read_unlock();
	}
	#ifdef CONFIG_KSU_KPROBES_NOMOUNT
		nomount_active = ksu_nomount_parent_active(wrapped->parent->path);
		if (nomount_active && ksu_nomount_pos_is_magic(ctx->pos)) {
			ksu_nomount_emit_children(wrapped->parent->path, ctx);
			return 0;
		}
		if (!susfs_active && !nomount_active) {
	#else
		if (!susfs_active) {
#endif
		goto do_real_iterate;
	}

	memset(&proxy_ctx, 0, sizeof(proxy_ctx));
	proxy_ctx.ctx.actor = ksu_susfs_actor_proxy;
	proxy_ctx.ctx.pos = ctx->pos;
	proxy_ctx.orig_ctx = ctx;
	proxy_ctx.parent = wrapped->parent;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	proxy_ctx.nomount_active = nomount_active;
#endif

	ret = ksu_susfs_call_iterate(wrapped->orig_fop, file, &proxy_ctx.ctx);
	ctx->pos = proxy_ctx.ctx.pos;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	if (ret >= 0 && nomount_active) {
		ksu_nomount_emit_children(wrapped->parent->path, ctx);
	}
#endif
	return ret;

do_real_iterate:
	return ksu_susfs_call_iterate(wrapped->orig_fop, file, ctx);
}

#ifdef KSU_SUSFS_HAS_ITERATE
static int ksu_susfs_hijacked_iterate(struct file *file, struct dir_context *ctx)
{
	return ksu_susfs_hijacked_iterate_shared(file, ctx);
}
#endif

static struct dentry *ksu_susfs_hijacked_lookup(struct inode *dir,
						struct dentry *dentry,
						unsigned int flags)
{
	struct ksu_susfs_iop *wrapped =
		__ksu_susfs_get(smp_load_acquire(&dir->i_op),
				struct ksu_susfs_iop, fake_iop);
	struct ksu_susfs_rule *rule;
	struct path visible_resolved;
	struct path backend_resolved;
	struct inode *inode;
	char visible_path[KSU_SUSFS_MAX_PATHNAME];
	char nomount_visible_path[KSU_SUSFS_MAX_PATHNAME];
	char backend_path[KSU_SUSFS_MAX_PATHNAME];
	u32 path_hash;
	int err;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	unsigned int nomount_type;
	unsigned long nomount_ino;
	struct inode *nomount_inode = NULL;
	int nomount_match;
#endif

	if (!wrapped || !wrapped->orig_iop) {
		return ERR_PTR(-EOPNOTSUPP);
	}

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	nomount_match = ksu_nomount_lookup_child(
		wrapped->parent->path, dentry->d_name.name, dentry->d_name.len,
		backend_path, sizeof(backend_path), &nomount_inode, &nomount_ino,
		&nomount_type);
	if (nomount_match == KSU_NOMOUNT_LOOKUP_WHITEOUT) {
		d_add(dentry, NULL);
		return NULL;
	}
	if (nomount_match == KSU_NOMOUNT_LOOKUP_REDIRECT) {
		if (nomount_type != DT_REG && nomount_type != DT_DIR &&
		    nomount_type != DT_LNK) {
			if (nomount_inode) {
				iput(nomount_inode);
			}
			goto fallback;
		}

		err = ksu_susfs_build_child_path(wrapped->parent->path,
						 &dentry->d_name,
						 nomount_visible_path,
						 sizeof(nomount_visible_path));
		if (err) {
			if (nomount_inode) {
				iput(nomount_inode);
			}
			goto fallback;
		}

		inode = nomount_inode;
		if (!inode || (!S_ISREG(inode->i_mode) &&
			       !S_ISDIR(inode->i_mode) &&
			       !S_ISLNK(inode->i_mode))) {
			if (nomount_inode) {
				iput(nomount_inode);
			}
			goto fallback;
		}

		inode = ksu_susfs_create_redirect_inode(
			dir->i_sb, inode, backend_path, nomount_visible_path,
			(u32)nomount_ino);
		iput(nomount_inode);
		if (!inode) {
			goto fallback;
		}

		return d_splice_alias(inode, dentry);
	}
#endif

	if (ksu_susfs_should_skip()) {
		goto fallback;
	}

	rcu_read_lock();
	rule = ksu_susfs_lookup_rule_rcu(wrapped->parent, dentry->d_name.name,
					 dentry->d_name.len);
	if (!rule) {
		rcu_read_unlock();
		goto fallback;
	}

	if (rule->type == KSU_SUSFS_RULE_HIDE &&
	    ksu_susfs_should_hide_current()) {
		rcu_read_unlock();
		d_add(dentry, NULL);
		return NULL;
	}

	if (rule->type != KSU_SUSFS_RULE_REDIRECT ||
	    !ksu_susfs_uid_scheme_matches(rule->uid_scheme)) {
		rcu_read_unlock();
		goto fallback;
	}

	path_hash = rule->path_hash;
	if (strscpy(visible_path, rule->visible_path,
		    sizeof(visible_path)) < 0 ||
	    strscpy(backend_path, rule->backend_path,
		    sizeof(backend_path)) < 0) {
		rcu_read_unlock();
		goto fallback;
	}
	rcu_read_unlock();

	err = ksu_susfs_resolve_path(visible_path, &visible_resolved);
	if (err) {
		goto fallback;
	}

	err = ksu_susfs_resolve_path(backend_path, &backend_resolved);
	if (err) {
		path_put(&visible_resolved);
		goto fallback;
	}

	inode = d_backing_inode(backend_resolved.dentry);
	if (!inode || (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode) &&
		       !S_ISLNK(inode->i_mode))) {
		path_put(&backend_resolved);
		path_put(&visible_resolved);
		goto fallback;
	}

	inode = ksu_susfs_create_redirect_inode(dir->i_sb, inode, backend_path,
						visible_path, path_hash);
	path_put(&backend_resolved);
	path_put(&visible_resolved);
	if (!inode) {
		goto fallback;
	}

	return d_splice_alias(inode, dentry);

fallback:
	if (wrapped->orig_iop->lookup) {
		return wrapped->orig_iop->lookup(dir, dentry, flags);
	}

	return ERR_PTR(-EOPNOTSUPP);
}

static void ksu_susfs_hijacked_destroy_inode(struct inode *inode)
{
	struct ksu_susfs_redirect_priv *priv;
	struct ksu_susfs_iop *wrapped_iop;
	struct ksu_susfs_fop *wrapped_fop;
	struct ksu_susfs_sop *wrapped_sop;

	if (inode->i_op == &ksu_susfs_file_iops ||
	    inode->i_op == &ksu_susfs_dir_iops ||
	    inode->i_op == &ksu_susfs_symlink_iops) {
		priv = ksu_susfs_backend_priv(inode);
		if (priv) {
			if (priv->backend_inode) {
				iput(priv->backend_inode);
			}
			kfree(priv);
			inode->i_private = NULL;
		}
	}

	wrapped_iop = __ksu_susfs_get(smp_load_acquire(&inode->i_op),
				      struct ksu_susfs_iop, fake_iop);
	if (wrapped_iop) {
		if (wrapped_iop->parent) {
			wrapped_iop->parent->dir_inode = NULL;
		}
		inode->i_op = wrapped_iop->orig_iop;
		if (!wrapped_iop->had_private_flag) {
			inode->i_flags &= ~S_PRIVATE;
		}
		kfree_rcu(wrapped_iop, rcu);
	}

	wrapped_fop = __ksu_susfs_get(smp_load_acquire(&inode->i_fop),
				      struct ksu_susfs_fop, fake_fop);
	if (wrapped_fop) {
		if (wrapped_fop->parent) {
			wrapped_fop->parent->dir_inode = NULL;
		}
		inode->i_fop = wrapped_fop->orig_fop;
		kfree_rcu(wrapped_fop, rcu);
	}

	wrapped_sop = __ksu_susfs_get(smp_load_acquire(&inode->i_sb->s_op),
				      struct ksu_susfs_sop, fake_sop);
	if (wrapped_sop && wrapped_sop->orig_sop &&
	    wrapped_sop->orig_sop->destroy_inode) {
		wrapped_sop->orig_sop->destroy_inode(inode);
	}
}

static void
ksu_susfs_free_fake_xattr(const struct xattr_handler **fake_xattr)
{
	int i = 0;

	if (!fake_xattr) {
		return;
	}

	while (fake_xattr[i]) {
		kfree(container_of(fake_xattr[i],
				   struct ksu_susfs_xattr_proxy, fake));
		i++;
	}
	kfree(fake_xattr);
}

static void ksu_susfs_hijacked_put_super(struct super_block *sb)
{
	struct ksu_susfs_sop *wrapped =
		__ksu_susfs_get(smp_load_acquire(&sb->s_op),
				struct ksu_susfs_sop, fake_sop);
	void (*orig_put_super)(struct super_block *);

	if (!wrapped) {
		return;
	}

	orig_put_super = wrapped->orig_sop->put_super;
	hash_del_rcu(&wrapped->node);
	smp_store_release(&sb->s_op, wrapped->orig_sop);

	if (wrapped->fake_xattr) {
		smp_store_release((const struct xattr_handler ***)&sb->s_xattr,
				  wrapped->orig_xattr);
		ksu_susfs_free_fake_xattr(wrapped->fake_xattr);
	}

	kfree_rcu(wrapped, rcu);

	if (orig_put_super) {
		orig_put_super(sb);
	}
}

static void ksu_susfs_restore_superblock_one(struct super_block *sb)
{
	struct ksu_susfs_sop *wrapped;

	if (!sb) {
		return;
	}

	wrapped = __ksu_susfs_get(smp_load_acquire(&sb->s_op),
				  struct ksu_susfs_sop, fake_sop);
	if (!wrapped) {
		return;
	}

	hash_del_rcu(&wrapped->node);
	smp_store_release(&sb->s_op, wrapped->orig_sop);

	if (wrapped->fake_xattr) {
		smp_store_release((const struct xattr_handler ***)&sb->s_xattr,
				  wrapped->orig_xattr);
		ksu_susfs_free_fake_xattr(wrapped->fake_xattr);
	}

	kfree_rcu(wrapped, rcu);
}

static int ksu_susfs_hijack_superblock(struct super_block *sb)
{
	struct ksu_susfs_sop *wrapped;
	const struct xattr_handler **new_array;
	int count = 0;
	int i;

	if (!sb || !sb->s_op) {
		return -EINVAL;
	}

	if (__ksu_susfs_get(smp_load_acquire(&sb->s_op),
			    struct ksu_susfs_sop, fake_sop)) {
		return 0;
	}

	wrapped = kzalloc(sizeof(*wrapped), GFP_KERNEL);
	if (!wrapped) {
		return -ENOMEM;
	}

	memcpy(&wrapped->fake_sop, sb->s_op, sizeof(struct super_operations));
	wrapped->orig_sop = sb->s_op;
	wrapped->signature = KSU_SUSFS_SIGNATURE;
	wrapped->sb = sb;
	wrapped->fake_sop.destroy_inode = ksu_susfs_hijacked_destroy_inode;
	wrapped->fake_sop.put_super = ksu_susfs_hijacked_put_super;

	if (sb->s_xattr && !wrapped->orig_xattr) {
		while (sb->s_xattr[count]) {
			count++;
		}

		new_array = kzalloc((count + 1) * sizeof(void *), GFP_KERNEL);
		if (new_array) {
			for (i = 0; i < count; i++) {
				struct ksu_susfs_xattr_proxy *proxy;

				proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
				if (!proxy) {
					ksu_susfs_free_fake_xattr(new_array);
					new_array = NULL;
					break;
				}

				proxy->orig = sb->s_xattr[i];
				proxy->fake.name = proxy->orig->name;
				proxy->fake.prefix = proxy->orig->prefix;
				proxy->fake.flags = proxy->orig->flags;
				proxy->fake.list = proxy->orig->list;
				if (proxy->orig->get) {
					proxy->fake.get = ksu_susfs_xattr_get;
				}
				if (proxy->orig->set) {
					proxy->fake.set = ksu_susfs_xattr_set;
				}
				new_array[i] = &proxy->fake;
			}

			if (new_array) {
				wrapped->orig_xattr =
					(const struct xattr_handler **)sb->s_xattr;
				wrapped->fake_xattr = new_array;
				smp_store_release(
					(const struct xattr_handler ***)&sb->s_xattr,
					new_array);
			}
		}
	}

	hash_add_rcu(ksu_susfs_sb_ht, &wrapped->node, (unsigned long)sb);
	smp_store_release(&sb->s_op, &wrapped->fake_sop);
	return 1;
}

static int ksu_susfs_hijack_parent_inode(struct ksu_susfs_parent *parent,
					 struct inode *inode)
{
	struct ksu_susfs_iop *wrapped_iop;
	struct ksu_susfs_fop *wrapped_fop;

	if (!inode->i_op || !inode->i_op->lookup) {
		return -EOPNOTSUPP;
	}

	if (!__ksu_susfs_get(smp_load_acquire(&inode->i_op),
			     struct ksu_susfs_iop, fake_iop)) {
		wrapped_iop = kzalloc(sizeof(*wrapped_iop), GFP_KERNEL);
		if (!wrapped_iop) {
			return -ENOMEM;
		}

		memcpy(&wrapped_iop->fake_iop, inode->i_op,
		       sizeof(struct inode_operations));
		wrapped_iop->orig_iop = inode->i_op;
		wrapped_iop->signature = KSU_SUSFS_SIGNATURE;
		wrapped_iop->parent = parent;
		wrapped_iop->had_private_flag =
			(inode->i_flags & S_PRIVATE) != 0;
		wrapped_iop->fake_iop.lookup = ksu_susfs_hijacked_lookup;
		smp_store_release(&inode->i_op, &wrapped_iop->fake_iop);
		inode->i_flags |= S_PRIVATE;
	}

	if (inode->i_fop &&
	    !__ksu_susfs_get(smp_load_acquire(&inode->i_fop),
			     struct ksu_susfs_fop, fake_fop)) {
		wrapped_fop = kzalloc(sizeof(*wrapped_fop), GFP_KERNEL);
		if (!wrapped_fop) {
			return -ENOMEM;
		}

		memcpy(&wrapped_fop->fake_fop, inode->i_fop,
		       sizeof(struct file_operations));
		wrapped_fop->orig_fop = inode->i_fop;
		wrapped_fop->signature = KSU_SUSFS_SIGNATURE;
		wrapped_fop->parent = parent;

#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
		if (wrapped_fop->fake_fop.iterate_shared) {
			wrapped_fop->fake_fop.iterate_shared =
				ksu_susfs_hijacked_iterate_shared;
		}
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
		else if (wrapped_fop->fake_fop.iterate) {
#else
		if (wrapped_fop->fake_fop.iterate) {
#endif
			wrapped_fop->fake_fop.iterate =
				ksu_susfs_hijacked_iterate;
		}
#endif
		smp_store_release(&inode->i_fop, &wrapped_fop->fake_fop);
	}

	return 0;
}

static void ksu_susfs_unhijack_parent_inode(struct ksu_susfs_parent *parent,
					    struct inode *inode)
{
	struct ksu_susfs_iop *wrapped_iop;
	struct ksu_susfs_fop *wrapped_fop;

	if (!inode) {
		parent->dir_inode = NULL;
		return;
	}

	spin_lock(&inode->i_lock);
	wrapped_iop = __ksu_susfs_get(smp_load_acquire(&inode->i_op),
				      struct ksu_susfs_iop, fake_iop);
	if (wrapped_iop && wrapped_iop->parent == parent) {
		smp_store_release(&inode->i_op, wrapped_iop->orig_iop);
		if (!wrapped_iop->had_private_flag) {
			inode->i_flags &= ~S_PRIVATE;
		}
		kfree_rcu(wrapped_iop, rcu);
	}

	wrapped_fop = __ksu_susfs_get(smp_load_acquire(&inode->i_fop),
				      struct ksu_susfs_fop, fake_fop);
	if (wrapped_fop && wrapped_fop->parent == parent) {
		smp_store_release(&inode->i_fop, wrapped_fop->orig_fop);
		kfree_rcu(wrapped_fop, rcu);
	}
	spin_unlock(&inode->i_lock);

	parent->dir_inode = NULL;
}

static void ksu_susfs_restore_parent(struct ksu_susfs_parent *parent)
{
	struct inode *inode = parent->dir_inode;
	struct dentry *alias;

	if (!inode) {
		return;
	}

	if (!igrab(inode)) {
		parent->dir_inode = NULL;
		return;
	}

	ksu_susfs_unhijack_parent_inode(parent, inode);

	alias = d_find_alias(inode);
	if (alias) {
		shrink_dcache_parent(alias);
		d_drop(alias);
		dput(alias);
	}

	iput(inode);
	parent->dir_inode = NULL;
}

static void ksu_susfs_restore_superblocks(void)
{
	struct ksu_susfs_sop *wrapped;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(ksu_susfs_sb_ht, bkt, tmp, wrapped, node) {
		ksu_susfs_restore_superblock_one(wrapped->sb);
	}
}

static int ksu_susfs_attach_parent_locked(struct ksu_susfs_parent *parent)
{
	struct path resolved;
	struct inode *inode;
	int sb_hijacked;
	int err;

	if (parent->dir_inode) {
		return 0;
	}

	err = ksu_susfs_resolve_path(parent->path, &resolved);
	if (err) {
		return err;
	}

	inode = d_backing_inode(resolved.dentry);
	if (!inode || !S_ISDIR(inode->i_mode)) {
		path_put(&resolved);
		return -ENOTDIR;
	}

	sb_hijacked = ksu_susfs_hijack_superblock(inode->i_sb);
	if (sb_hijacked < 0) {
		path_put(&resolved);
		return sb_hijacked;
	}

	err = ksu_susfs_hijack_parent_inode(parent, inode);
	if (err) {
		ksu_susfs_unhijack_parent_inode(parent, inode);
		if (sb_hijacked > 0) {
			ksu_susfs_restore_superblock_one(inode->i_sb);
		}
		path_put(&resolved);
		return err;
	}

	parent->dir_inode = inode;
	path_put(&resolved);
	return 0;
}

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
int ksu_susfs_attach_nomount_parent(const char *path)
{
	struct ksu_susfs_parent *parent;
	char *normalized;
	size_t len;
	bool new_parent = false;
	int err;

	if (!path || path[0] != '/') {
		return -EINVAL;
	}

	normalized = kstrdup(path, GFP_KERNEL);
	if (!normalized) {
		return -ENOMEM;
	}

	len = strlen(normalized);
	while (len > 1 && normalized[len - 1] == '/') {
		normalized[--len] = '\0';
	}

	mutex_lock(&ksu_susfs_lock);
	parent = ksu_susfs_find_parent_locked(normalized);
	if (!parent) {
		parent = kzalloc(sizeof(*parent), GFP_KERNEL);
		if (!parent) {
			err = -ENOMEM;
			goto out_unlock;
		}

		INIT_LIST_HEAD(&parent->all_list);
		INIT_LIST_HEAD(&parent->rules);
		if (strscpy(parent->path, normalized, sizeof(parent->path)) < 0) {
			kfree(parent);
			err = -ENAMETOOLONG;
			goto out_unlock;
		}

		hash_add(ksu_susfs_parents_ht, &parent->node,
			 ksu_susfs_hash_path(parent->path));
		list_add_tail(&parent->all_list, &ksu_susfs_parent_list);
		new_parent = true;
	}

	err = ksu_susfs_attach_parent_locked(parent);
	if (err && new_parent) {
		hash_del(&parent->node);
		list_del(&parent->all_list);
		kfree(parent);
	}

out_unlock:
	mutex_unlock(&ksu_susfs_lock);
	kfree(normalized);
	return err;
}
#endif

static int ksu_susfs_validate_redirect(const char *visible_path,
				       const char *backend_path)
{
	struct path visible;
	struct path backend;
	struct inode *visible_inode;
	struct inode *backend_inode;
	int err;

	err = ksu_susfs_resolve_path(visible_path, &visible);
	if (err) {
		return err;
	}

	err = ksu_susfs_resolve_path(backend_path, &backend);
	if (err) {
		path_put(&visible);
		return err;
	}

	visible_inode = d_backing_inode(visible.dentry);
	backend_inode = d_backing_inode(backend.dentry);

	if (!visible_inode || !backend_inode) {
		err = -ENOENT;
		goto out;
	}

	if ((!S_ISREG(visible_inode->i_mode) && !S_ISDIR(visible_inode->i_mode)) ||
	    (!S_ISREG(backend_inode->i_mode) && !S_ISDIR(backend_inode->i_mode))) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!!S_ISDIR(visible_inode->i_mode) != !!S_ISDIR(backend_inode->i_mode)) {
		err = -EINVAL;
		goto out;
	}

	err = 0;

out:
	path_put(&backend);
	path_put(&visible);
	return err;
}

static int ksu_susfs_add_rule(const char *visible_path, const char *backend_path,
			      int uid_scheme, bool allow_missing_target)
{
	struct ksu_susfs_parent *parent;
	struct ksu_susfs_rule *rule;
	char normalized_visible[KSU_SUSFS_MAX_PATHNAME];
	char normalized_backend[KSU_SUSFS_MAX_PATHNAME];
	char parent_path[KSU_SUSFS_MAX_PATHNAME];
	char name[KSU_SUSFS_MAX_PATHNAME];
	int err;
	bool new_parent = false;

	err = ksu_susfs_normalize_path(normalized_visible,
				       sizeof(normalized_visible), visible_path);
	if (err) {
		return err;
	}

	err = ksu_susfs_split_path(normalized_visible, parent_path,
				   sizeof(parent_path), name, sizeof(name));
	if (err) {
		return err;
	}

	if (!allow_missing_target) {
		struct path resolved;

		err = ksu_susfs_resolve_path(normalized_visible, &resolved);
		if (err) {
			return err;
		}
		path_put(&resolved);
	}

	if (!backend_path) {
		normalized_backend[0] = '\0';
	} else {
		err = ksu_susfs_normalize_path(normalized_backend,
					       sizeof(normalized_backend),
					       backend_path);
		if (err) {
			return err;
		}

		err = ksu_susfs_validate_redirect(normalized_visible,
						  normalized_backend);
		if (err) {
			return err;
		}
	}

	mutex_lock(&ksu_susfs_lock);

	if (ksu_susfs_find_rule_locked(normalized_visible)) {
		err = -EEXIST;
		goto out_unlock;
	}

	parent = ksu_susfs_find_parent_locked(parent_path);
	if (!parent) {
		parent = kzalloc(sizeof(*parent), GFP_KERNEL);
		if (!parent) {
			err = -ENOMEM;
			goto out_unlock;
		}

		INIT_LIST_HEAD(&parent->all_list);
		INIT_LIST_HEAD(&parent->rules);
		if (strscpy(parent->path, parent_path, sizeof(parent->path)) < 0) {
			kfree(parent);
			err = -ENAMETOOLONG;
			goto out_unlock;
		}

		hash_add(ksu_susfs_parents_ht, &parent->node,
			 ksu_susfs_hash_path(parent->path));
		list_add_tail(&parent->all_list, &ksu_susfs_parent_list);
		new_parent = true;
	}

	err = ksu_susfs_attach_parent_locked(parent);
	if (err) {
		if (new_parent) {
			hash_del(&parent->node);
			list_del(&parent->all_list);
			kfree(parent);
		}
		goto out_unlock;
	}

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		err = -ENOMEM;
		goto out_unwind_parent;
	}

	rule->path_hash = ksu_susfs_hash_path(normalized_visible);
	rule->uid_scheme = uid_scheme;
	rule->type = backend_path ? KSU_SUSFS_RULE_REDIRECT :
				    KSU_SUSFS_RULE_HIDE;
	INIT_LIST_HEAD(&rule->free_list);
	if (strscpy(rule->name, name, sizeof(rule->name)) < 0 ||
	    strscpy(rule->visible_path, normalized_visible,
		    sizeof(rule->visible_path)) < 0 ||
	    (backend_path &&
	     strscpy(rule->backend_path, normalized_backend,
		     sizeof(rule->backend_path)) < 0)) {
		kfree(rule);
		err = -ENAMETOOLONG;
		goto out_unwind_parent;
	}

	hash_add(ksu_susfs_rules_ht, &rule->path_node, rule->path_hash);
	list_add_tail_rcu(&rule->parent_list, &parent->rules);
	if (atomic_inc_return(&ksu_susfs_rule_count) == 1) {
		static_branch_enable(&ksu_susfs_active);
	}

	err = 0;

out_unwind_parent:
	if (err && new_parent) {
		ksu_susfs_restore_parent(parent);
		hash_del(&parent->node);
		list_del(&parent->all_list);
		kfree(parent);
	}

out_unlock:
	mutex_unlock(&ksu_susfs_lock);
	if (!err) {
		ksu_susfs_invalidate_path(normalized_visible, parent_path);
	}
	return err;
}

static void ksu_susfs_clear_all(void)
{
	struct ksu_susfs_rule *rule;
	struct ksu_susfs_rule *rule_tmp;
	struct hlist_node *rule_hnode_tmp;
	struct ksu_susfs_parent *parent, *parent_tmp;
	LIST_HEAD(free_rules);
	LIST_HEAD(free_parents);
	int bkt;

	mutex_lock(&ksu_susfs_lock);

	hash_for_each_safe(ksu_susfs_rules_ht, bkt, rule_hnode_tmp, rule,
			   path_node) {
		hash_del_rcu(&rule->path_node);
		list_del_rcu(&rule->parent_list);
		list_add_tail(&rule->free_list, &free_rules);
	}

	list_for_each_entry(parent, &ksu_susfs_parent_list, all_list) {
		ksu_susfs_restore_parent(parent);
	}
	ksu_susfs_restore_superblocks();

	list_for_each_entry_safe(parent, parent_tmp, &ksu_susfs_parent_list,
				 all_list) {
		hash_del(&parent->node);
		list_del(&parent->all_list);
		list_add_tail(&parent->all_list, &free_parents);
	}

	if (atomic_read(&ksu_susfs_rule_count) > 0) {
		atomic_set(&ksu_susfs_rule_count, 0);
		static_branch_disable(&ksu_susfs_active);
	}

	mutex_unlock(&ksu_susfs_lock);

	synchronize_rcu();

	list_for_each_entry_safe(rule, rule_tmp, &free_rules, free_list) {
		list_del(&rule->free_list);
		kfree(rule);
	}

	list_for_each_entry_safe(parent, parent_tmp, &free_parents, all_list) {
		list_del(&parent->all_list);
		kfree(parent);
	}
}

static bool ksu_susfs_compat_root_allowed(void)
{
	return current_uid().val == 0 || is_ksu_domain();
}

static bool ksu_susfs_handle_path_compat(void __user *arg, bool allow_missing)
{
	struct ksu_susfs_path_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	cmd.target_pathname[sizeof(cmd.target_pathname) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	cmd.err = ksu_susfs_add_rule(cmd.target_pathname, NULL, 0,
				     allow_missing);

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: path compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_redirect_compat(void __user *arg)
{
	struct ksu_susfs_open_redirect_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	cmd.target_pathname[sizeof(cmd.target_pathname) - 1] = '\0';
	cmd.redirected_pathname[sizeof(cmd.redirected_pathname) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	if (cmd.uid_scheme < KSU_SUSFS_UID_NON_APP_PROC ||
	    cmd.uid_scheme > KSU_SUSFS_UID_UMOUNTED_PROC) {
		cmd.err = -EINVAL;
		goto out;
	}

	cmd.err = ksu_susfs_add_rule(cmd.target_pathname,
				     cmd.redirected_pathname,
				     cmd.uid_scheme, false);

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: redirect compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_version_compat(void __user *arg)
{
	struct ksu_susfs_version_cmd cmd = { .err = 0 };

	strscpy(cmd.susfs_version, KSU_SUSFS_VERSION,
		sizeof(cmd.susfs_version));
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: version compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_variant_compat(void __user *arg)
{
	struct ksu_susfs_variant_cmd cmd = { .err = 0 };

	strscpy(cmd.susfs_variant, KSU_SUSFS_VARIANT, sizeof(cmd.susfs_variant));
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: variant compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_features_compat(void __user *arg)
{
	struct ksu_susfs_enabled_features_cmd *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		return true;
	}

	strscpy(cmd->enabled_features,
		"hookless_vfs\nhookless_procfs\nsus_path\nsus_path_loop\n"
		"open_redirect\nsus_mount\nsus_kstat\nsus_map\n"
		"spoof_cmdline_or_bootconfig\nspoof_uname\n"
		"avc_log_spoofing\nproc_maps_kstat\nproc_smaps_kstat\n"
		"proc_maps_hide\nproc_smaps_hide\n",
		sizeof(cmd->enabled_features));
	if (copy_to_user(arg, cmd, sizeof(*cmd))) {
		pr_err("susfs: feature compat copy_to_user failed\n");
	}
	kfree(cmd);
	return true;
}

static bool ksu_susfs_handle_log_compat(void __user *arg)
{
	struct ksu_susfs_log_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	cmd.err = 0;

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: log compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_compat(unsigned int cmd, void __user *arg)
{
	switch (cmd) {
	case KSU_SUSFS_CMD_ADD_SUS_PATH:
		return ksu_susfs_handle_path_compat(arg, false);
	case KSU_SUSFS_CMD_ADD_SUS_PATH_LOOP:
		return ksu_susfs_handle_path_compat(arg, true);
	case KSU_SUSFS_CMD_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
		return ksu_susfs_handle_mount_compat(arg);
	case KSU_SUSFS_CMD_ADD_SUS_KSTAT:
	case KSU_SUSFS_CMD_UPDATE_SUS_KSTAT:
	case KSU_SUSFS_CMD_ADD_SUS_KSTAT_STATICALLY:
		return ksu_susfs_handle_kstat_compat(cmd, arg);
	case KSU_SUSFS_CMD_ADD_SUS_MAP:
		return ksu_susfs_handle_sus_map_compat(arg);
	case KSU_SUSFS_CMD_ADD_OPEN_REDIRECT:
		return ksu_susfs_handle_redirect_compat(arg);
	case KSU_SUSFS_CMD_SET_UNAME:
		return ksu_susfs_handle_uname_compat(arg);
	case KSU_SUSFS_CMD_ENABLE_LOG:
		return ksu_susfs_handle_log_compat(arg);
	case KSU_SUSFS_CMD_SET_CMDLINE_OR_BOOTCONFIG:
		return ksu_susfs_handle_cmdline_compat(arg);
	case KSU_SUSFS_CMD_SHOW_VERSION:
		return ksu_susfs_handle_version_compat(arg);
	case KSU_SUSFS_CMD_SHOW_VARIANT:
		return ksu_susfs_handle_variant_compat(arg);
	case KSU_SUSFS_CMD_SHOW_ENABLED_FEATURES:
		return ksu_susfs_handle_features_compat(arg);
	case KSU_SUSFS_CMD_ENABLE_AVC_LOG_SPOOFING:
		return ksu_susfs_handle_avc_compat(arg);
	default:
		return false;
	}
}

void ksu_susfs_apply_default_rules(void)
{
	size_t i;
	int err;

	for (i = 0; i < ARRAY_SIZE(ksu_susfs_default_hide_paths); i++) {
		err = ksu_susfs_add_rule(ksu_susfs_default_hide_paths[i], NULL,
					 0, false);
		if (!err) {
			pr_info("susfs: default hide rule enabled for %s\n",
				ksu_susfs_default_hide_paths[i]);
			continue;
		}

		if (err == -ENOENT || err == -EEXIST) {
			continue;
		}

		pr_warn("susfs: failed to install default hide rule for %s: %d\n",
			ksu_susfs_default_hide_paths[i], err);
	}
}

void ksu_susfs_init(void)
{
	hash_init(ksu_susfs_rules_ht);
	hash_init(ksu_susfs_parents_ht);
	hash_init(ksu_susfs_sb_ht);
	atomic_set(&ksu_susfs_rule_count, 0);
	ksu_susfs_apply_default_rules();
	if (ksu_susfs_procfs_init()) {
		pr_warn("susfs: procfs runtime init returned non-zero\n");
	}
	if (ksu_susfs_kstat_init()) {
		pr_warn("susfs: kstat runtime init returned non-zero\n");
	}
	pr_info("susfs: hookless core initialized\n");
}

void ksu_susfs_exit(void)
{
	ksu_susfs_kstat_exit();
	ksu_susfs_procfs_exit();
	ksu_susfs_clear_all();
	pr_info("susfs: hookless core exited\n");
}
