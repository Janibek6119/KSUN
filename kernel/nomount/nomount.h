#ifndef __KSU_NOMOUNT_H
#define __KSU_NOMOUNT_H

#include <linux/fs.h>
#include <linux/types.h>

#include "susfs/susfs.h"

#define KSU_NOMOUNT_VERSION 13
#define KSU_NOMOUNT_GENL_NAME "nomount"
#define KSU_NOMOUNT_GENL_VERSION 1

#define KSU_NOMOUNT_HASH_BITS 8
#define KSU_NOMOUNT_UID_HASH_BITS 4

#define KSU_NOMOUNT_FLAG_IS_DIR (1U << 1)
#define KSU_NOMOUNT_FLAG_WHITEOUT (1U << 2)
#define KSU_NOMOUNT_FLAG_INTERNAL (1U << 31)

enum ksu_nomount_cmd {
	KSU_NOMOUNT_CMD_UNSPEC = 0,
	KSU_NOMOUNT_CMD_GET_VERSION,
	KSU_NOMOUNT_CMD_ADD_RULE,
	KSU_NOMOUNT_CMD_DEL_RULE,
	KSU_NOMOUNT_CMD_CLEAR_ALL,
	KSU_NOMOUNT_CMD_ADD_UID,
	KSU_NOMOUNT_CMD_DEL_UID,
	KSU_NOMOUNT_CMD_GET_LIST,
	__KSU_NOMOUNT_CMD_MAX,
};
#define KSU_NOMOUNT_CMD_MAX (__KSU_NOMOUNT_CMD_MAX - 1)

enum ksu_nomount_attr {
	KSU_NOMOUNT_ATTR_UNSPEC = 0,
	KSU_NOMOUNT_ATTR_VIRTUAL_PATH,
	KSU_NOMOUNT_ATTR_REAL_PATH,
	KSU_NOMOUNT_ATTR_FLAGS,
	KSU_NOMOUNT_ATTR_UID,
	KSU_NOMOUNT_ATTR_VERSION,
	KSU_NOMOUNT_ATTR_PAYLOAD,
	__KSU_NOMOUNT_ATTR_MAX,
};
#define KSU_NOMOUNT_ATTR_MAX (__KSU_NOMOUNT_ATTR_MAX - 1)

enum ksu_nomount_lookup_result {
	KSU_NOMOUNT_LOOKUP_NONE = 0,
	KSU_NOMOUNT_LOOKUP_WHITEOUT,
	KSU_NOMOUNT_LOOKUP_REDIRECT,
};

struct ksu_nomount_dump_state {
	int bucket;
	int index;
};

void ksu_nomount_init(void);
void ksu_nomount_exit(void);

int ksu_nomount_add_rule(const char *virtual_path, const char *real_path,
			 u32 flags);
int ksu_nomount_del_rule(const char *virtual_path);
void ksu_nomount_clear_all(void);
int ksu_nomount_add_uid(uid_t uid);
int ksu_nomount_del_uid(uid_t uid);
int ksu_nomount_get_dump_rule(struct ksu_nomount_dump_state *state,
			      char *virtual_path, size_t virtual_size,
			      char *real_path, size_t real_size, u32 *flags);

bool ksu_nomount_parent_active(const char *parent_path);
bool ksu_nomount_dir_is_internal(const char *path);
bool ksu_nomount_pos_is_magic(loff_t pos);
bool ksu_nomount_filter_child(const char *parent_path, const char *name,
				      size_t namelen);
void ksu_nomount_emit_children(const char *parent_path, struct dir_context *ctx);
int ksu_nomount_lookup_child(const char *parent_path, const char *name,
			     size_t namelen, char *real_path,
			     size_t real_size, struct inode **backend_inode,
			     unsigned long *ino, unsigned int *d_type);

int ksu_nomount_netlink_init(void);
void ksu_nomount_netlink_exit(void);

#endif /* __KSU_NOMOUNT_H */
