#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
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
#include <linux/string.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "nomount/nomount.h"
#include "susfs/compat.h"

#define KSU_NOMOUNT_MAGIC_POS ((loff_t)0x7000000000000000LL)
#define KSU_NOMOUNT_COMPAT_MAGIC_POS ((loff_t)0x7E000000)
#define KSU_NOMOUNT_MAGIC_WINDOW 100000

struct ksu_nomount_child {
	u32 ino;
	u16 name_offset;
	u8 d_type;
	u8 flags;
};

struct ksu_nomount_child_array {
	atomic_t refcnt;
	u32 num_children;
	u32 heap_size;
	struct rcu_head rcu;
	struct ksu_nomount_child entries[];
};

struct ksu_nomount_parent {
	struct hlist_node node;
	struct list_head all_node;
	struct ksu_nomount_child_array __rcu *children;
	char path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_nomount_rule {
	struct hlist_node node;
	struct list_head gc_node;
	struct ksu_nomount_parent *parent;
	struct inode *backend_inode;
	u32 hash;
	u32 flags;
	unsigned long ino;
	unsigned int d_type;
	char virtual_path[KSU_SUSFS_MAX_PATHNAME];
	char real_path[KSU_SUSFS_MAX_PATHNAME];
	char parent_path[KSU_SUSFS_MAX_PATHNAME];
	char name[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_nomount_uid {
	struct hlist_node node;
	struct list_head gc_node;
	uid_t uid;
};

struct ksu_nomount_rule_scratch {
	char normalized_virtual[KSU_SUSFS_MAX_PATHNAME];
	char normalized_real[KSU_SUSFS_MAX_PATHNAME];
	char parent_path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_nomount_ancestor_scratch {
	char prefix[KSU_SUSFS_MAX_PATHNAME];
	char internal_real[KSU_SUSFS_MAX_PATHNAME];
	char last_created[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_nomount_prune_scratch {
	char cursor[KSU_SUSFS_MAX_PATHNAME];
	char parent_path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_nomount_invalidate_scratch {
	char prefix[KSU_SUSFS_MAX_PATHNAME];
	char parent_path[KSU_SUSFS_MAX_PATHNAME];
	char name[KSU_SUSFS_MAX_PATHNAME];
};

static DEFINE_HASHTABLE(ksu_nomount_rules, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_parents, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_uids, KSU_NOMOUNT_UID_HASH_BITS);
static LIST_HEAD(ksu_nomount_parent_list);
static DEFINE_MUTEX(ksu_nomount_lock);
static atomic_t ksu_nomount_rule_count = ATOMIC_INIT(0);
static atomic_t ksu_nomount_uid_count = ATOMIC_INIT(0);
static DEFINE_STATIC_KEY_FALSE(ksu_nomount_active_rules);
static DEFINE_STATIC_KEY_FALSE(ksu_nomount_active_uids);

static u32 ksu_nomount_hash_path(const char *path)
{
	return jhash(path, strlen(path), 0);
}

static const char *
ksu_nomount_child_name(const struct ksu_nomount_child_array *array,
		       const struct ksu_nomount_child *child)
{
	return (const char *)&array->entries[array->num_children] +
	       child->name_offset;
}

static u8 ksu_nomount_child_flags(u32 rule_flags)
{
	return rule_flags & (KSU_NOMOUNT_FLAG_IS_DIR |
			     KSU_NOMOUNT_FLAG_WHITEOUT);
}

static loff_t ksu_nomount_magic_pos(void)
{
#ifdef CONFIG_COMPAT
	if (in_compat_syscall())
		return KSU_NOMOUNT_COMPAT_MAGIC_POS;
#endif
	return KSU_NOMOUNT_MAGIC_POS;
}

bool ksu_nomount_pos_is_magic(loff_t pos)
{
	loff_t magic_pos = ksu_nomount_magic_pos();

	return pos >= magic_pos &&
	       pos < magic_pos + KSU_NOMOUNT_MAGIC_WINDOW;
}

static int ksu_nomount_normalize_path(char *dst, size_t dst_size,
				      const char *src)
{
	size_t len;

	if (!src || !*src || src[0] != '/')
		return -EINVAL;

	if (strscpy(dst, src, dst_size) < 0)
		return -ENAMETOOLONG;

	len = strlen(dst);
	while (len > 1 && dst[len - 1] == '/')
		dst[--len] = '\0';

	return 0;
}

static int ksu_nomount_split_path(const char *path, char *parent,
				  size_t parent_size, char *name,
				  size_t name_size)
{
	const char *slash;
	size_t parent_len;

	if (!path || path[0] != '/' || path[1] == '\0')
		return -EINVAL;

	slash = strrchr(path, '/');
	if (!slash || slash[1] == '\0')
		return -EINVAL;

	if (strscpy(name, slash + 1, name_size) < 0)
		return -ENAMETOOLONG;

	if (slash == path)
		return strscpy(parent, "/", parent_size) < 0 ? -ENAMETOOLONG : 0;

	parent_len = slash - path;
	if (parent_len >= parent_size)
		return -ENAMETOOLONG;

	memcpy(parent, path, parent_len);
	parent[parent_len] = '\0';
	return 0;
}

static int ksu_nomount_build_child_path(const char *parent, const char *name,
					size_t namelen, char *out,
					size_t out_size)
{
	size_t parent_len = strlen(parent);
	size_t total = parent_len + 1 + namelen + 1;

	if (parent_len == 1 && parent[0] == '/')
		total--;

	if (total > out_size)
		return -ENAMETOOLONG;

	if (parent_len == 1 && parent[0] == '/') {
		out[0] = '/';
		memcpy(out + 1, name, namelen);
		out[namelen + 1] = '\0';
		return 0;
	}

	memcpy(out, parent, parent_len);
	out[parent_len] = '/';
	memcpy(out + parent_len + 1, name, namelen);
	out[parent_len + 1 + namelen] = '\0';
	return 0;
}

static unsigned int ksu_nomount_count_components(const char *path)
{
	unsigned int count = 0;
	const char *p;

	if (!path || path[0] != '/')
		return 0;

	p = path + 1;
	while (*p) {
		const char *slash;

		count++;
		slash = strchr(p, '/');
		if (!slash)
			break;
		p = slash + 1;
	}

	return count;
}

static int ksu_nomount_prefix_components(const char *path, unsigned int count,
					 char *out, size_t out_size)
{
	const char *p;
	size_t len = 1;
	unsigned int seen = 0;

	if (!path || path[0] != '/' || !count)
		return strscpy(out, "/", out_size) < 0 ? -ENAMETOOLONG : 0;

	p = path + 1;
	while (*p && seen < count) {
		const char *slash = strchr(p, '/');
		size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);

		len = (p - path) + comp_len;
		seen++;
		if (!slash)
			break;
		p = slash + 1;
	}

	if (seen != count || len >= out_size)
		return -ENAMETOOLONG;

	memcpy(out, path, len);
	out[len] = '\0';
	return 0;
}

static int ksu_nomount_trim_components(const char *path, unsigned int count,
				       char *out, size_t out_size)
{
	int err;

	if (!path || path[0] != '/')
		return strscpy(out, "/", out_size) < 0 ? -ENAMETOOLONG : 0;

	err = ksu_nomount_normalize_path(out, out_size, path);
	if (err)
		return err;

	while (count-- && strcmp(out, "/")) {
		char *slash = strrchr(out, '/');

		if (!slash || slash == out) {
			out[1] = '\0';
			break;
		}
		*slash = '\0';
	}

	return 0;
}

static int ksu_nomount_resolve_path_flags(const char *path, unsigned int flags,
					  struct path *out)
{
	const struct cred *saved = NULL;
	int err;

	if (ksu_cred)
		saved = override_creds(ksu_cred);
	err = kern_path(path, flags, out);
	if (saved)
		revert_creds(saved);
	return err;
}

static int ksu_nomount_resolve_path(const char *path, struct path *out)
{
	return ksu_nomount_resolve_path_flags(path, 0, out);
}

static int ksu_nomount_real_dir_status(const char *path)
{
	struct path resolved;
	struct inode *inode;
	int err;

	err = ksu_nomount_resolve_path_flags(path, LOOKUP_FOLLOW, &resolved);
	if (err)
		return err;

	inode = d_backing_inode(resolved.dentry);
	if (!inode || !S_ISDIR(inode->i_mode)) {
		path_put(&resolved);
		return -ENOTDIR;
	}

	path_put(&resolved);
	return 0;
}

static void ksu_nomount_drop_cached_child(const char *path)
{
	struct ksu_nomount_invalidate_scratch *scratch;
	struct path parent_path;
	struct qstr qname;
	struct dentry *cached;
	int err;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return;

	err = ksu_nomount_split_path(path, scratch->parent_path,
				     sizeof(scratch->parent_path),
				     scratch->name, sizeof(scratch->name));
	if (err)
		goto out_free;

	err = ksu_nomount_resolve_path(scratch->parent_path, &parent_path);
	if (err)
		goto out_free;

	qname.name = scratch->name;
	qname.len = strlen(scratch->name);
	qname.hash = full_name_hash(parent_path.dentry, qname.name, qname.len);
	if ((parent_path.dentry->d_flags & DCACHE_OP_HASH) &&
	    parent_path.dentry->d_op && parent_path.dentry->d_op->d_hash)
		parent_path.dentry->d_op->d_hash(parent_path.dentry, &qname);

	cached = d_lookup(parent_path.dentry, &qname);
	if (cached) {
		shrink_dcache_parent(cached);
		d_drop(cached);
		dput(cached);
	}

	path_put(&parent_path);

out_free:
	kfree(scratch);
}

static void ksu_nomount_invalidate_path(const char *path, const char *parent)
{
	struct path resolved;

	if (!ksu_nomount_resolve_path(path, &resolved)) {
		shrink_dcache_parent(resolved.dentry);
		d_drop(resolved.dentry);
		path_put(&resolved);
		return;
	}

	ksu_nomount_drop_cached_child(path);

	if (parent && !ksu_nomount_resolve_path(parent, &resolved)) {
		shrink_dcache_parent(resolved.dentry);
		path_put(&resolved);
	}
}

static struct ksu_nomount_parent *
ksu_nomount_find_parent_locked(const char *path)
{
	struct ksu_nomount_parent *parent;
	u32 hash = ksu_nomount_hash_path(path);

	hash_for_each_possible(ksu_nomount_parents, parent, node, hash) {
		if (!strcmp(parent->path, path))
			return parent;
	}

	return NULL;
}

static struct ksu_nomount_parent *
ksu_nomount_find_parent_rcu(const char *path)
{
	struct ksu_nomount_parent *parent;
	u32 hash = ksu_nomount_hash_path(path);

	hash_for_each_possible_rcu(ksu_nomount_parents, parent, node, hash) {
		if (!strcmp(parent->path, path))
			return parent;
	}

	return NULL;
}

static struct ksu_nomount_rule *ksu_nomount_find_rule_locked(const char *path)
{
	struct ksu_nomount_rule *rule;
	u32 hash = ksu_nomount_hash_path(path);

	hash_for_each_possible(ksu_nomount_rules, rule, node, hash) {
		if (!strcmp(rule->virtual_path, path))
			return rule;
	}

	return NULL;
}

static bool ksu_nomount_path_has_children_locked(const char *path)
{
	struct ksu_nomount_child_array *array;
	struct ksu_nomount_parent *parent;

	parent = ksu_nomount_find_parent_locked(path);
	if (!parent)
		return false;

	array = rcu_dereference_protected(parent->children,
					  lockdep_is_held(&ksu_nomount_lock));
	return array && array->num_children > 0;
}

static int ksu_nomount_parent_dir_status_locked(const char *path)
{
	struct ksu_nomount_rule *rule;

	if (!strcmp(path, "/"))
		return ksu_nomount_real_dir_status(path);
	rule = ksu_nomount_find_rule_locked(path);
	if (rule)
		return rule->d_type == DT_DIR ? 0 : -ENOTDIR;

	return ksu_nomount_real_dir_status(path);
}

static int ksu_nomount_select_internal_real_path(const char *virtual_path,
						 const char *prefix_path,
						 const char *real_path,
						 bool whiteout, char *out,
						 size_t out_size)
{
	unsigned int virtual_depth;
	unsigned int prefix_depth;
	unsigned int trim;
	int err;

	if (whiteout || !real_path || !real_path[0])
		return strscpy(out, "/", out_size) < 0 ? -ENAMETOOLONG : 0;

	virtual_depth = ksu_nomount_count_components(virtual_path);
	prefix_depth = ksu_nomount_count_components(prefix_path);
	if (!virtual_depth || !prefix_depth || prefix_depth >= virtual_depth)
		return strscpy(out, "/", out_size) < 0 ? -ENAMETOOLONG : 0;

	trim = virtual_depth - prefix_depth;
	err = ksu_nomount_trim_components(real_path, trim, out, out_size);
	if (err)
		return err;

	if (ksu_nomount_real_dir_status(out))
		return strscpy(out, "/", out_size) < 0 ? -ENAMETOOLONG : 0;

	return 0;
}

static struct ksu_nomount_rule *ksu_nomount_find_rule_rcu(const char *path)
{
	struct ksu_nomount_rule *rule;
	u32 hash = ksu_nomount_hash_path(path);

	hash_for_each_possible_rcu(ksu_nomount_rules, rule, node, hash) {
		if (!strcmp(rule->virtual_path, path))
			return rule;
	}

	return NULL;
}

static bool ksu_nomount_uid_blocked(uid_t uid)
{
	struct ksu_nomount_uid *entry;

	if (!static_branch_unlikely(&ksu_nomount_active_uids))
		return false;

	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_nomount_uids, entry, node, uid) {
		if (entry->uid == uid) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static bool ksu_nomount_should_skip(void)
{
	if (!static_branch_unlikely(&ksu_nomount_active_rules))
		return true;
	if (unlikely(in_interrupt() || oops_in_progress))
		return true;
	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING)))
		return true;
	return ksu_nomount_uid_blocked(current_uid().val);
}

static void ksu_nomount_child_array_put(struct ksu_nomount_child_array *array)
{
	if (array && atomic_dec_and_test(&array->refcnt))
		kfree_rcu(array, rcu);
}

static struct ksu_nomount_child_array *
ksu_nomount_get_child_array(const char *parent_path)
{
	struct ksu_nomount_child_array *array = NULL;
	struct ksu_nomount_parent *parent;

	if (ksu_nomount_should_skip())
		return NULL;

	rcu_read_lock();
	parent = ksu_nomount_find_parent_rcu(parent_path);
	if (parent) {
		array = rcu_dereference(parent->children);
		if (array && !atomic_inc_not_zero(&array->refcnt))
			array = NULL;
	}
	rcu_read_unlock();

	return array;
}

static int
ksu_nomount_replace_child_array_locked(struct ksu_nomount_parent *parent,
				       const struct ksu_nomount_rule *rule)
{
	struct ksu_nomount_child_array *old_array;
	struct ksu_nomount_child_array *new_array;
	const char *old_heap = NULL;
	char *new_heap;
	u32 old_num = 0;
	u32 old_heap_size = 0;
	u32 new_heap_size;
	u32 new_num;
	int replace_idx = -1;
	size_t name_len = strlen(rule->name);
	size_t new_total_size;
	u32 i;

	old_array = rcu_dereference_protected(parent->children,
					      lockdep_is_held(&ksu_nomount_lock));
	if (old_array) {
		old_num = old_array->num_children;
		old_heap_size = old_array->heap_size;
		old_heap = (const char *)&old_array->entries[old_num];
		for (i = 0; i < old_num; i++) {
			const char *child =
				ksu_nomount_child_name(old_array,
						       &old_array->entries[i]);

			if (!strcmp(child, rule->name)) {
				replace_idx = i;
				break;
			}
		}
	}

	new_num = replace_idx >= 0 ? old_num : old_num + 1;
	new_heap_size = replace_idx >= 0 ? old_heap_size :
				 old_heap_size + name_len + 1;
	new_total_size = sizeof(*new_array) +
			 new_num * sizeof(struct ksu_nomount_child) +
			 new_heap_size;

	new_array = kmalloc(new_total_size, GFP_KERNEL);
	if (!new_array)
		return -ENOMEM;

	atomic_set(&new_array->refcnt, 1);
	new_array->num_children = new_num;
	new_array->heap_size = new_heap_size;
	new_heap = (char *)&new_array->entries[new_num];

	for (i = 0; i < old_num; i++)
		new_array->entries[i] = old_array->entries[i];
	if (old_heap_size)
		memcpy(new_heap, old_heap, old_heap_size);

	if (replace_idx >= 0) {
		new_array->entries[replace_idx].ino = rule->ino;
		new_array->entries[replace_idx].d_type = rule->d_type;
		new_array->entries[replace_idx].flags =
			ksu_nomount_child_flags(rule->flags);
	} else {
		new_array->entries[old_num].ino = rule->ino;
		new_array->entries[old_num].name_offset = old_heap_size;
		new_array->entries[old_num].d_type = rule->d_type;
		new_array->entries[old_num].flags =
			ksu_nomount_child_flags(rule->flags);
		memcpy(new_heap + old_heap_size, rule->name, name_len + 1);
	}

	rcu_assign_pointer(parent->children, new_array);
	ksu_nomount_child_array_put(old_array);
	return 0;
}

static int ksu_nomount_delete_child_locked(struct ksu_nomount_parent *parent,
					   const char *name)
{
	struct ksu_nomount_child_array *old_array;
	struct ksu_nomount_child_array *new_array;
	const char *old_heap;
	char *new_heap;
	int found = -1;
	u32 num;
	u32 new_heap_size = 0;
	u32 current_offset = 0;
	u32 src;
	u32 dst = 0;
	size_t len;
	size_t total;

	old_array = rcu_dereference_protected(parent->children,
					      lockdep_is_held(&ksu_nomount_lock));
	if (!old_array)
		return 0;

	num = old_array->num_children;
	for (src = 0; src < num; src++) {
		const char *child = ksu_nomount_child_name(old_array,
							   &old_array->entries[src]);

		if (!strcmp(child, name)) {
			found = src;
			continue;
		}
		new_heap_size += strlen(child) + 1;
	}

	if (found < 0)
		return 0;

	if (num == 1) {
		rcu_assign_pointer(parent->children, NULL);
		ksu_nomount_child_array_put(old_array);
		return 0;
	}

	total = sizeof(*new_array) + (num - 1) * sizeof(struct ksu_nomount_child) +
		new_heap_size;
	new_array = kmalloc(total, GFP_KERNEL);
	if (!new_array)
		return -ENOMEM;

	atomic_set(&new_array->refcnt, 1);
	new_array->num_children = num - 1;
	new_array->heap_size = new_heap_size;
	old_heap = (const char *)&old_array->entries[num];
	new_heap = (char *)&new_array->entries[num - 1];

	for (src = 0; src < num; src++) {
		if (src == found)
			continue;

		len = strlen(ksu_nomount_child_name(old_array,
						    &old_array->entries[src]));
		new_array->entries[dst] = old_array->entries[src];
		memcpy(new_heap + current_offset,
		       old_heap + old_array->entries[src].name_offset, len + 1);
		new_array->entries[dst].name_offset = current_offset;
		current_offset += len + 1;
		dst++;
	}

	rcu_assign_pointer(parent->children, new_array);
	ksu_nomount_child_array_put(old_array);
	return 0;
}

static void ksu_nomount_rule_free(struct ksu_nomount_rule *rule)
{
	if (rule->backend_inode)
		iput(rule->backend_inode);
	kfree(rule);
}

static void ksu_nomount_uid_free(struct ksu_nomount_uid *entry)
{
	kfree(entry);
}

static struct ksu_nomount_rule *
ksu_nomount_alloc_rule(const char *virtual_path, const char *real_path,
		       u32 flags, unsigned int d_type,
		       struct inode *backend_inode)
{
	struct ksu_nomount_rule *rule;
	int err;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rule->gc_node);
	err = ksu_nomount_split_path(virtual_path, rule->parent_path,
				     sizeof(rule->parent_path), rule->name,
				     sizeof(rule->name));
	if (err) {
		kfree(rule);
		return ERR_PTR(err);
	}

	rule->hash = ksu_nomount_hash_path(virtual_path);
	rule->flags = flags;
	if (!(flags & KSU_NOMOUNT_FLAG_WHITEOUT)) {
		if (!backend_inode) {
			kfree(rule);
			return ERR_PTR(-ENOENT);
		}

		rule->backend_inode = igrab(backend_inode);
		if (!rule->backend_inode) {
			kfree(rule);
			return ERR_PTR(-ENOENT);
		}
	}
	rule->ino = rule->hash;
	rule->d_type = d_type;
	if (d_type == DT_DIR)
		rule->flags |= KSU_NOMOUNT_FLAG_IS_DIR;
	else
		rule->flags &= ~KSU_NOMOUNT_FLAG_IS_DIR;

	if (strscpy(rule->virtual_path, virtual_path,
		    sizeof(rule->virtual_path)) < 0 ||
	    strscpy(rule->real_path, real_path ? real_path : "",
		    sizeof(rule->real_path)) < 0) {
		ksu_nomount_rule_free(rule);
		return ERR_PTR(-ENAMETOOLONG);
	}

	return rule;
}

static struct ksu_nomount_parent *
ksu_nomount_get_or_create_parent_locked(const char *path, bool *created)
{
	struct ksu_nomount_parent *parent;

	*created = false;
	parent = ksu_nomount_find_parent_locked(path);
	if (parent)
		return parent;

	parent = kzalloc(sizeof(*parent), GFP_KERNEL);
	if (!parent)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&parent->all_node);
	RCU_INIT_POINTER(parent->children, NULL);
	if (strscpy(parent->path, path, sizeof(parent->path)) < 0) {
		kfree(parent);
		return ERR_PTR(-ENAMETOOLONG);
	}

	hash_add_rcu(ksu_nomount_parents, &parent->node,
		     ksu_nomount_hash_path(parent->path));
	list_add_tail(&parent->all_node, &ksu_nomount_parent_list);
	*created = true;
	return parent;
}

static void
ksu_nomount_drop_empty_parent_locked(struct ksu_nomount_parent *parent,
				     struct list_head *parent_victims)
{
	struct ksu_nomount_child_array *children;

	if (!parent)
		return;

	children = rcu_dereference_protected(parent->children,
					     lockdep_is_held(&ksu_nomount_lock));
	if (children && children->num_children)
		return;

	hash_del_rcu(&parent->node);
	list_del(&parent->all_node);
	list_add_tail(&parent->all_node, parent_victims);
}

static int
ksu_nomount_prepare_parent_locked(const char *parent_path)
{
	struct ksu_nomount_rule *parent_rule;
	int err;

	parent_rule = strcmp(parent_path, "/") ?
			      ksu_nomount_find_rule_locked(parent_path) : NULL;
	if (parent_rule)
		return parent_rule->d_type == DT_DIR ? 0 : -ENOTDIR;

	err = ksu_nomount_parent_dir_status_locked(parent_path);
	if (err)
		return err;

	return ksu_susfs_attach_nomount_parent(parent_path);
}

static int
ksu_nomount_publish_rule_locked(struct ksu_nomount_rule *rule,
				struct list_head *rule_victims,
				struct list_head *parent_victims)
{
	struct ksu_nomount_parent *parent;
	struct ksu_nomount_rule *victim;
	bool new_parent;
	int err;

	err = ksu_nomount_prepare_parent_locked(rule->parent_path);
	if (err)
		return err;

	victim = ksu_nomount_find_rule_locked(rule->virtual_path);
	if (victim && ksu_nomount_path_has_children_locked(rule->virtual_path) &&
	    rule->d_type != DT_DIR)
		return -ENOTDIR;

	parent = ksu_nomount_get_or_create_parent_locked(rule->parent_path,
							 &new_parent);
	if (IS_ERR(parent))
		return PTR_ERR(parent);

	rule->parent = parent;
	err = ksu_nomount_replace_child_array_locked(parent, rule);
	if (err) {
		if (new_parent)
			ksu_nomount_drop_empty_parent_locked(parent,
							    parent_victims);
		return err;
	}

	if (victim) {
		hash_del_rcu(&victim->node);
		list_add_tail(&victim->gc_node, rule_victims);
	}

	hash_add_rcu(ksu_nomount_rules, &rule->node, rule->hash);
	if (!victim && atomic_inc_return(&ksu_nomount_rule_count) == 1)
		static_branch_enable(&ksu_nomount_active_rules);

	return 0;
}

static int
ksu_nomount_remove_rule_locked(struct ksu_nomount_rule *rule,
			       struct list_head *rule_victims,
			       struct list_head *parent_victims)
{
	struct ksu_nomount_parent *parent = rule->parent;
	int err;

	err = ksu_nomount_delete_child_locked(parent, rule->name);
	if (err)
		return err;

	hash_del_rcu(&rule->node);
	if (atomic_dec_return(&ksu_nomount_rule_count) == 0)
		static_branch_disable(&ksu_nomount_active_rules);
	list_add_tail(&rule->gc_node, rule_victims);
	ksu_nomount_drop_empty_parent_locked(parent, parent_victims);
	return 0;
}

static void
ksu_nomount_prune_internal_ancestors_locked(const char *start_path,
					    struct list_head *rule_victims,
					    struct list_head *parent_victims)
{
	struct ksu_nomount_prune_scratch *scratch;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return;

	if (strscpy(scratch->cursor, start_path, sizeof(scratch->cursor)) < 0)
		goto out;

	while (strcmp(scratch->cursor, "/")) {
		struct ksu_nomount_rule *rule;

		rule = ksu_nomount_find_rule_locked(scratch->cursor);
		if (!rule || !(rule->flags & KSU_NOMOUNT_FLAG_INTERNAL) ||
		    ksu_nomount_path_has_children_locked(scratch->cursor))
			break;

		if (strscpy(scratch->parent_path, rule->parent_path,
			    sizeof(scratch->parent_path)) < 0)
			break;

		if (ksu_nomount_remove_rule_locked(rule, rule_victims,
						   parent_victims))
			break;

		if (strscpy(scratch->cursor, scratch->parent_path,
			    sizeof(scratch->cursor)) < 0)
			break;
	}

out:
	kfree(scratch);
}

static int
ksu_nomount_create_missing_ancestors_locked(const char *virtual_path,
					    const char *real_path, bool whiteout,
					    struct list_head *rule_victims,
					    struct list_head *parent_victims)
{
	struct ksu_nomount_ancestor_scratch *scratch;
	unsigned int depth = ksu_nomount_count_components(virtual_path);
	unsigned int i;
	int err = 0;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	for (i = 1; i < depth; i++) {
		struct ksu_nomount_rule *rule;

		err = ksu_nomount_prefix_components(virtual_path, i,
						    scratch->prefix,
						    sizeof(scratch->prefix));
		if (err)
			goto out_prune;

		rule = ksu_nomount_find_rule_locked(scratch->prefix);
		if (rule) {
			if (rule->d_type != DT_DIR) {
				err = -ENOTDIR;
				goto out_prune;
			}
			continue;
		}

		err = ksu_nomount_real_dir_status(scratch->prefix);
		if (!err)
			continue;
		if (err != -ENOENT)
			goto out_prune;

		err = ksu_nomount_select_internal_real_path(
			virtual_path, scratch->prefix, real_path, whiteout,
			scratch->internal_real, sizeof(scratch->internal_real));
		if (err)
			goto out_prune;

		{
			struct path resolved;
			struct inode *inode;

			err = ksu_nomount_resolve_path_flags(
				scratch->internal_real, LOOKUP_FOLLOW, &resolved);
			if (err)
				goto out_prune;

			inode = d_backing_inode(resolved.dentry);
			if (!inode || !S_ISDIR(inode->i_mode)) {
				path_put(&resolved);
				err = -ENOTDIR;
				goto out_prune;
			}

			rule = ksu_nomount_alloc_rule(
				scratch->prefix, scratch->internal_real,
				KSU_NOMOUNT_FLAG_INTERNAL |
					KSU_NOMOUNT_FLAG_IS_DIR,
				DT_DIR, inode);
			path_put(&resolved);
		}
		if (IS_ERR(rule)) {
			err = PTR_ERR(rule);
			goto out_prune;
		}

		err = ksu_nomount_publish_rule_locked(rule, rule_victims,
						      parent_victims);
		if (err) {
			ksu_nomount_rule_free(rule);
			goto out_prune;
		}
		ksu_nomount_invalidate_path(scratch->prefix,
					    rule->parent_path);

		if (strscpy(scratch->last_created, scratch->prefix,
			    sizeof(scratch->last_created)) < 0) {
			err = -ENAMETOOLONG;
			goto out_prune;
		}
	}

	goto out_free;

out_prune:
	if (scratch->last_created[0])
		ksu_nomount_prune_internal_ancestors_locked(
			scratch->last_created, rule_victims, parent_victims);
out_free:
	kfree(scratch);
	return err;
}

static void ksu_nomount_release_victims(struct list_head *rule_victims,
					struct list_head *parent_victims)
{
	struct ksu_nomount_rule *rule;
	struct ksu_nomount_rule *rule_tmp;
	struct ksu_nomount_parent *parent;
	struct ksu_nomount_parent *parent_tmp;

	if (list_empty(rule_victims) && list_empty(parent_victims))
		return;

	synchronize_rcu();

	list_for_each_entry_safe(rule, rule_tmp, rule_victims, gc_node) {
		list_del(&rule->gc_node);
		ksu_nomount_invalidate_path(rule->virtual_path, rule->parent_path);
		ksu_nomount_rule_free(rule);
	}

	list_for_each_entry_safe(parent, parent_tmp, parent_victims, all_node) {
		list_del(&parent->all_node);
		kfree(parent);
	}
}

int ksu_nomount_add_rule(const char *virtual_path, const char *real_path,
			 u32 flags)
{
	struct ksu_nomount_rule *rule;
	struct ksu_nomount_rule_scratch *scratch;
	struct path resolved;
	struct inode *inode;
	struct inode *backend_inode = NULL;
	bool whiteout = (flags & KSU_NOMOUNT_FLAG_WHITEOUT) != 0;
	bool resolved_backend = false;
	unsigned int d_type = DT_REG;
	LIST_HEAD(rule_victims);
	LIST_HEAD(parent_victims);
	int err;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	flags &= ~KSU_NOMOUNT_FLAG_INTERNAL;
	err = ksu_nomount_normalize_path(scratch->normalized_virtual,
					 sizeof(scratch->normalized_virtual),
					 virtual_path);
	if (err)
		goto out_free_scratch;

	scratch->normalized_real[0] = '\0';
	if (!whiteout) {
		if (!real_path) {
			err = -EINVAL;
			goto out_free_scratch;
		}

		err = ksu_nomount_normalize_path(scratch->normalized_real,
						 sizeof(scratch->normalized_real),
						 real_path);
		if (err)
			goto out_free_scratch;

		err = ksu_nomount_resolve_path(scratch->normalized_real,
					       &resolved);
		if (err)
			goto out_free_scratch;
		resolved_backend = true;

		inode = d_backing_inode(resolved.dentry);
		if (!inode) {
			err = -ENOENT;
			goto out_put_backend;
		}
		if (S_ISDIR(inode->i_mode)) {
			flags |= KSU_NOMOUNT_FLAG_IS_DIR;
			d_type = DT_DIR;
		} else if (S_ISLNK(inode->i_mode)) {
			d_type = DT_LNK;
		} else if (!S_ISREG(inode->i_mode)) {
			err = -EOPNOTSUPP;
			goto out_put_backend;
		}
		backend_inode = inode;
	}

	rule = ksu_nomount_alloc_rule(scratch->normalized_virtual,
				      scratch->normalized_real, flags, d_type,
				      backend_inode);
	if (resolved_backend) {
		path_put(&resolved);
		resolved_backend = false;
	}
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto out_free_scratch;
	}
	if (strscpy(scratch->parent_path, rule->parent_path,
		    sizeof(scratch->parent_path)) < 0) {
		err = -ENAMETOOLONG;
		goto out_free_rule;
	}

	mutex_lock(&ksu_nomount_lock);
	err = ksu_nomount_create_missing_ancestors_locked(
		scratch->normalized_virtual, scratch->normalized_real, whiteout,
		&rule_victims, &parent_victims);
	if (err)
		goto out_unlock;
	err = ksu_nomount_publish_rule_locked(rule, &rule_victims,
					      &parent_victims);
	if (err)
		ksu_nomount_prune_internal_ancestors_locked(
			scratch->parent_path, &rule_victims, &parent_victims);

out_unlock:
	mutex_unlock(&ksu_nomount_lock);

	ksu_nomount_release_victims(&rule_victims, &parent_victims);

	if (err)
		goto out_free_rule;

	ksu_nomount_invalidate_path(scratch->normalized_virtual,
				    scratch->parent_path);
	kfree(scratch);
	return 0;

out_free_rule:
	ksu_nomount_rule_free(rule);
out_put_backend:
	if (resolved_backend)
		path_put(&resolved);
out_free_scratch:
	kfree(scratch);
	return err;
}

int ksu_nomount_del_rule(const char *virtual_path)
{
	struct ksu_nomount_rule *rule = NULL;
	struct ksu_nomount_rule_scratch *scratch;
	LIST_HEAD(rule_victims);
	LIST_HEAD(parent_victims);
	int err;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	err = ksu_nomount_normalize_path(scratch->normalized_virtual,
					 sizeof(scratch->normalized_virtual),
					 virtual_path);
	if (err)
		goto out_free_scratch;

	mutex_lock(&ksu_nomount_lock);
	rule = ksu_nomount_find_rule_locked(scratch->normalized_virtual);
	if (!rule) {
		mutex_unlock(&ksu_nomount_lock);
		err = -ENOENT;
		goto out_free_scratch;
	}

	if (rule->flags & KSU_NOMOUNT_FLAG_INTERNAL) {
		mutex_unlock(&ksu_nomount_lock);
		err = -ENOENT;
		goto out_free_scratch;
	}

	strscpy(scratch->parent_path, rule->parent_path,
		sizeof(scratch->parent_path));
	if (ksu_nomount_path_has_children_locked(scratch->normalized_virtual)) {
		if (rule->d_type != DT_DIR) {
			mutex_unlock(&ksu_nomount_lock);
			err = -ENOTDIR;
			goto out_free_scratch;
		}
		rule->flags |= KSU_NOMOUNT_FLAG_INTERNAL |
			       KSU_NOMOUNT_FLAG_IS_DIR;
		rule->d_type = DT_DIR;
		if (ksu_nomount_real_dir_status(rule->real_path)) {
			if (strscpy(rule->real_path, "/",
				    sizeof(rule->real_path)) < 0) {
				err = -ENAMETOOLONG;
				mutex_unlock(&ksu_nomount_lock);
				goto out_free_scratch;
			}
		}
		err = ksu_nomount_replace_child_array_locked(rule->parent, rule);
	} else {
		err = ksu_nomount_remove_rule_locked(rule, &rule_victims,
						     &parent_victims);
		if (!err)
			ksu_nomount_prune_internal_ancestors_locked(
				scratch->parent_path, &rule_victims,
				&parent_victims);
	}
	mutex_unlock(&ksu_nomount_lock);

	if (err) {
		ksu_nomount_release_victims(&rule_victims, &parent_victims);
		goto out_free_scratch;
	}

	ksu_nomount_release_victims(&rule_victims, &parent_victims);
	ksu_nomount_invalidate_path(scratch->normalized_virtual,
				    scratch->parent_path);
	kfree(scratch);
	return 0;

out_free_scratch:
	kfree(scratch);
	return err;
}

void ksu_nomount_clear_all(void)
{
	struct ksu_nomount_rule *rule;
	struct ksu_nomount_rule *rule_tmp;
	struct ksu_nomount_uid *uid;
	struct ksu_nomount_uid *uid_tmp;
	struct ksu_nomount_parent *parent;
	struct ksu_nomount_parent *parent_tmp;
	struct ksu_nomount_child_array *children;
	struct hlist_node *tmp;
	LIST_HEAD(rule_victims);
	LIST_HEAD(uid_victims);
	LIST_HEAD(parent_victims);
	int bkt;

	mutex_lock(&ksu_nomount_lock);

	hash_for_each_safe(ksu_nomount_rules, bkt, tmp, rule, node) {
		hash_del_rcu(&rule->node);
		list_add_tail(&rule->gc_node, &rule_victims);
	}

	hash_for_each_safe(ksu_nomount_uids, bkt, tmp, uid, node) {
		hash_del_rcu(&uid->node);
		list_add_tail(&uid->gc_node, &uid_victims);
	}

	list_for_each_entry_safe(parent, parent_tmp, &ksu_nomount_parent_list,
				 all_node) {
		list_del(&parent->all_node);
		hash_del_rcu(&parent->node);
		children = rcu_dereference_protected(
			parent->children, lockdep_is_held(&ksu_nomount_lock));
		rcu_assign_pointer(parent->children, NULL);
		ksu_nomount_child_array_put(children);
		list_add_tail(&parent->all_node, &parent_victims);
	}

	if (atomic_read(&ksu_nomount_rule_count) > 0)
		static_branch_disable(&ksu_nomount_active_rules);
	if (atomic_read(&ksu_nomount_uid_count) > 0)
		static_branch_disable(&ksu_nomount_active_uids);
	atomic_set(&ksu_nomount_rule_count, 0);
	atomic_set(&ksu_nomount_uid_count, 0);

	mutex_unlock(&ksu_nomount_lock);

	synchronize_rcu();

	list_for_each_entry_safe(rule, rule_tmp, &rule_victims, gc_node) {
		list_del(&rule->gc_node);
		ksu_nomount_invalidate_path(rule->virtual_path, rule->parent_path);
		ksu_nomount_rule_free(rule);
	}

	list_for_each_entry_safe(uid, uid_tmp, &uid_victims, gc_node) {
		list_del(&uid->gc_node);
		ksu_nomount_uid_free(uid);
	}

	list_for_each_entry_safe(parent, parent_tmp, &parent_victims, all_node) {
		list_del(&parent->all_node);
		kfree(parent);
	}
}

int ksu_nomount_add_uid(uid_t uid)
{
	struct ksu_nomount_uid *entry;
	struct ksu_nomount_uid *existing;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->gc_node);
	entry->uid = uid;

	mutex_lock(&ksu_nomount_lock);
	hash_for_each_possible(ksu_nomount_uids, existing, node, uid) {
		if (existing->uid == uid) {
			mutex_unlock(&ksu_nomount_lock);
			kfree(entry);
			return -EEXIST;
		}
	}

	hash_add_rcu(ksu_nomount_uids, &entry->node, uid);
	if (atomic_inc_return(&ksu_nomount_uid_count) == 1)
		static_branch_enable(&ksu_nomount_active_uids);
	mutex_unlock(&ksu_nomount_lock);
	return 0;
}

int ksu_nomount_del_uid(uid_t uid)
{
	struct ksu_nomount_uid *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&ksu_nomount_lock);
	hash_for_each_safe(ksu_nomount_uids, bkt, tmp, entry, node) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->node);
			if (atomic_dec_return(&ksu_nomount_uid_count) == 0)
				static_branch_disable(&ksu_nomount_active_uids);
			mutex_unlock(&ksu_nomount_lock);
			synchronize_rcu();
			ksu_nomount_uid_free(entry);
			return 0;
		}
	}
	mutex_unlock(&ksu_nomount_lock);
	return -ENOENT;
}

int ksu_nomount_get_dump_rule(struct ksu_nomount_dump_state *state,
			      char *virtual_path, size_t virtual_size,
			      char *real_path, size_t real_size, u32 *flags)
{
	struct ksu_nomount_rule *rule;
	int start = state->index;
	int idx = 0;
	int bkt;
	int ret = -ENOENT;

	rcu_read_lock();
	hash_for_each_rcu(ksu_nomount_rules, bkt, rule, node) {
		if (rule->flags & KSU_NOMOUNT_FLAG_INTERNAL)
			continue;

		if (idx++ < start)
			continue;

		if (strscpy(virtual_path, rule->virtual_path, virtual_size) < 0 ||
		    strscpy(real_path, rule->real_path, real_size) < 0) {
			ret = -ENAMETOOLONG;
		} else {
			*flags = rule->flags & ~KSU_NOMOUNT_FLAG_INTERNAL;
			state->index = idx;
			ret = 0;
		}
		break;
	}
	rcu_read_unlock();
	return ret;
}

bool ksu_nomount_parent_active(const char *parent_path)
{
	struct ksu_nomount_child_array *array;

	array = ksu_nomount_get_child_array(parent_path);
	if (!array)
		return false;
	ksu_nomount_child_array_put(array);
	return true;
}

bool ksu_nomount_dir_is_internal(const char *path)
{
	struct ksu_nomount_rule *rule;
	bool internal = false;

	if (!static_branch_unlikely(&ksu_nomount_active_rules))
		return false;

	rcu_read_lock();
	rule = ksu_nomount_find_rule_rcu(path);
	if (rule && rule->d_type == DT_DIR &&
	    (rule->flags & KSU_NOMOUNT_FLAG_INTERNAL))
		internal = true;
	rcu_read_unlock();
	return internal;
}

bool ksu_nomount_filter_child(const char *parent_path, const char *name,
			      size_t namelen)
{
	struct ksu_nomount_child_array *array;
	bool found = false;
	u32 i;

	array = ksu_nomount_get_child_array(parent_path);
	if (!array)
		return false;

	for (i = 0; i < array->num_children; i++) {
		const char *child =
			ksu_nomount_child_name(array, &array->entries[i]);

		if (child[namelen] == '\0' && !memcmp(child, name, namelen)) {
			found = true;
			break;
		}
	}

	ksu_nomount_child_array_put(array);
	return found;
}

void ksu_nomount_emit_children(const char *parent_path, struct dir_context *ctx)
{
	struct ksu_nomount_child_array *array;
	loff_t magic_pos = ksu_nomount_magic_pos();
	unsigned long start = 0;
	u32 i;

	array = ksu_nomount_get_child_array(parent_path);
	if (!array)
		return;

	if (ctx->pos >= magic_pos &&
	    ctx->pos < magic_pos + KSU_NOMOUNT_MAGIC_WINDOW) {
		start = (unsigned long)(ctx->pos - magic_pos);
	} else {
		ctx->pos = magic_pos;
	}

	for (i = start; i < array->num_children; i++) {
		const struct ksu_nomount_child *child = &array->entries[i];
		const char *name = ksu_nomount_child_name(array, child);

		if (child->flags & KSU_NOMOUNT_FLAG_WHITEOUT) {
			ctx->pos = magic_pos + i + 1;
			continue;
		}

		if (!dir_emit(ctx, name, strlen(name), child->ino, child->d_type))
			break;
		ctx->pos = magic_pos + i + 1;
	}

	ksu_nomount_child_array_put(array);
}

int ksu_nomount_lookup_child(const char *parent_path, const char *name,
			     size_t namelen, char *real_path,
			     size_t real_size, struct inode **backend_inode,
			     unsigned long *ino, unsigned int *d_type)
{
	struct ksu_nomount_rule *rule;
	char *virtual_path;
	int ret = KSU_NOMOUNT_LOOKUP_NONE;

	if (ksu_nomount_should_skip())
		return KSU_NOMOUNT_LOOKUP_NONE;

	virtual_path = kmalloc(KSU_SUSFS_MAX_PATHNAME, GFP_ATOMIC);
	if (!virtual_path)
		return KSU_NOMOUNT_LOOKUP_NONE;

	if (ksu_nomount_build_child_path(parent_path, name, namelen,
					 virtual_path, KSU_SUSFS_MAX_PATHNAME))
		goto out_free;

	rcu_read_lock();
	rule = ksu_nomount_find_rule_rcu(virtual_path);
	if (!rule)
		goto out;

	if (rule->flags & KSU_NOMOUNT_FLAG_WHITEOUT) {
		ret = KSU_NOMOUNT_LOOKUP_WHITEOUT;
		goto out;
	}

	if (strscpy(real_path, rule->real_path, real_size) < 0) {
		ret = KSU_NOMOUNT_LOOKUP_NONE;
		goto out;
	}

	if (backend_inode) {
		*backend_inode = rule->backend_inode ?
					 igrab(rule->backend_inode) : NULL;
		if (!*backend_inode) {
			ret = KSU_NOMOUNT_LOOKUP_NONE;
			goto out;
		}
	}

	*ino = rule->ino;
	*d_type = rule->d_type;
	ret = KSU_NOMOUNT_LOOKUP_REDIRECT;

out:
	rcu_read_unlock();
out_free:
	kfree(virtual_path);
	return ret;
}

void ksu_nomount_init(void)
{
	int err;

	hash_init(ksu_nomount_rules);
	hash_init(ksu_nomount_parents);
	hash_init(ksu_nomount_uids);
	atomic_set(&ksu_nomount_rule_count, 0);
	atomic_set(&ksu_nomount_uid_count, 0);

	err = ksu_nomount_netlink_init();
	if (err) {
		pr_warn("NoMount: failed to register Generic Netlink family: %d\n",
			err);
		return;
	}

	pr_info("NoMount: hookless bridge initialized\n");
}

void ksu_nomount_exit(void)
{
	ksu_nomount_netlink_exit();
	ksu_nomount_clear_all();
	pr_info("NoMount: hookless bridge exited\n");
}
