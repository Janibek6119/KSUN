#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <net/genetlink.h>
#include <net/netlink.h>

#include "klog.h" // IWYU pragma: keep
#include "nomount/nomount.h"

#ifdef KSU_NOMOUNT_GENL_FAMILY_HAS_POLICY
#define KSU_NOMOUNT_FAMILY_POLICY .policy = ksu_nomount_genl_policy,
#else
#define KSU_NOMOUNT_FAMILY_POLICY
#endif

#ifdef KSU_NOMOUNT_GENL_OPS_HAS_POLICY
#define KSU_NOMOUNT_OPS_POLICY .policy = ksu_nomount_genl_policy,
#else
#define KSU_NOMOUNT_OPS_POLICY
#endif

#ifdef KSU_NOMOUNT_GENL_FAMILY_HAS_NETNSOK
#define KSU_NOMOUNT_FAMILY_NETNSOK .netnsok = true,
#else
#define KSU_NOMOUNT_FAMILY_NETNSOK
#endif

#ifdef KSU_NOMOUNT_GENL_FAMILY_HAS_MODULE
#define KSU_NOMOUNT_FAMILY_MODULE .module = THIS_MODULE,
#else
#define KSU_NOMOUNT_FAMILY_MODULE
#endif

#ifdef KSU_NOMOUNT_GENL_FAMILY_HAS_OPS
#define KSU_NOMOUNT_FAMILY_OPS \
	.ops = ksu_nomount_genl_ops, \
	.n_ops = ARRAY_SIZE(ksu_nomount_genl_ops),
#else
#define KSU_NOMOUNT_FAMILY_OPS
#endif

static struct genl_family ksu_nomount_genl_family;
static bool ksu_nomount_genl_registered;

struct ksu_nomount_dump_scratch {
	char virtual_path[KSU_NOMOUNT_MAX_PATH];
	char real_path[KSU_NOMOUNT_MAX_PATH];
};

static int ksu_nomount_copy_payload_path(const char *data, int len,
					 char **out)
{
	if (len <= 0)
		return -EINVAL;
	if (len >= KSU_NOMOUNT_MAX_PATH)
		return -ENAMETOOLONG;
	if (memchr(data, '\0', len))
		return -EINVAL;

	*out = kstrndup(data, len, GFP_KERNEL);
	return *out ? 0 : -ENOMEM;
}

static int ksu_nomount_validate_add_payload(const char *data, int len)
{
	int pos = 0;

	if (len <= 0)
		return -EINVAL;
	while (pos < len) {
		u32 flags;
		u16 virtual_len, real_len;

		if (len - pos < 8)
			return -EINVAL;
		flags = get_unaligned((const u32 *)(data + pos));
		virtual_len = get_unaligned((const u16 *)(data + pos + 4));
		real_len = get_unaligned((const u16 *)(data + pos + 6));
		pos += 8;

		if (!virtual_len || virtual_len >= KSU_NOMOUNT_MAX_PATH ||
		    real_len >= KSU_NOMOUNT_MAX_PATH ||
		    (!(flags & KSU_NOMOUNT_FLAG_WHITEOUT) && !real_len) ||
		    virtual_len > len - pos ||
		    real_len > len - pos - virtual_len)
			return -EINVAL;
		if (memchr(data + pos, '\0', virtual_len) ||
		    (real_len &&
		     memchr(data + pos + virtual_len, '\0', real_len)))
			return -EINVAL;
		pos += virtual_len + real_len;
	}
	return 0;
}

static int ksu_nomount_validate_del_payload(const char *data, int len)
{
	int pos = 0;

	if (len <= 0)
		return -EINVAL;
	while (pos < len) {
		u16 virtual_len;

		if (len - pos < 2)
			return -EINVAL;
		virtual_len = get_unaligned((const u16 *)(data + pos));
		pos += 2;
		if (!virtual_len || virtual_len >= KSU_NOMOUNT_MAX_PATH ||
		    virtual_len > len - pos ||
		    memchr(data + pos, '\0', virtual_len))
			return -EINVAL;
		pos += virtual_len;
	}
	return 0;
}

static int ksu_nomount_count_del_payload(const char *data, int len)
{
	int pos = 0;
	int count = 0;

	while (pos < len) {
		u16 virtual_len;

		virtual_len = get_unaligned((const u16 *)(data + pos));
		pos += 2 + virtual_len;
		count++;
	}
	return count;
}

static void ksu_nomount_free_path_array(char **paths, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		kfree(paths[i]);
	kfree(paths);
}

static int ksu_nomount_genl_add_rule(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct nlattr *payload = info->attrs[KSU_NOMOUNT_ATTR_PAYLOAD];
	int first_err = 0;

	if (payload) {
		const char *data = nla_data(payload);
		int len = nla_len(payload);
		int pos = 0;
		int validate_err;

		validate_err = ksu_nomount_validate_add_payload(data, len);
		if (validate_err)
			return validate_err;

		while (pos + 8 <= len) {
			char *virtual_path = NULL;
			char *real_path = NULL;
			u32 flags;
			u16 virtual_len;
			u16 real_len;
			int err;

			flags = get_unaligned((const u32 *)(data + pos));
			virtual_len = get_unaligned((const u16 *)(data + pos + 4));
			real_len = get_unaligned((const u16 *)(data + pos + 6));
			pos += 8;

			if (virtual_len == 0 || pos + virtual_len + real_len > len)
				return first_err ?: -EINVAL;

			err = ksu_nomount_copy_payload_path(data + pos, virtual_len,
							    &virtual_path);
			pos += virtual_len;
			if (!err && real_len) {
				err = ksu_nomount_copy_payload_path(data + pos,
								    real_len,
								    &real_path);
			}
			pos += real_len;

			if (!err)
				err = ksu_nomount_add_rule(virtual_path, real_path,
							   flags);
			if (err && !first_err)
				first_err = err;

			kfree(virtual_path);
			kfree(real_path);
		}

		if (pos != len)
			return first_err ?: -EINVAL;

		return first_err ?: 0;
	}

	if (info->attrs[KSU_NOMOUNT_ATTR_VIRTUAL_PATH]) {
		const char *virtual_path =
			nla_data(info->attrs[KSU_NOMOUNT_ATTR_VIRTUAL_PATH]);
		const char *real_path = NULL;
		u32 flags = 0;

		if (info->attrs[KSU_NOMOUNT_ATTR_FLAGS])
			flags = nla_get_u32(info->attrs[KSU_NOMOUNT_ATTR_FLAGS]);
		if (info->attrs[KSU_NOMOUNT_ATTR_REAL_PATH])
			real_path =
				nla_data(info->attrs[KSU_NOMOUNT_ATTR_REAL_PATH]);
		else if (!(flags & KSU_NOMOUNT_FLAG_WHITEOUT))
			return -EINVAL;

		return ksu_nomount_add_rule(virtual_path, real_path, flags);
	}

	return -EINVAL;
}

static int ksu_nomount_genl_del_rule(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct nlattr *payload = info->attrs[KSU_NOMOUNT_ATTR_PAYLOAD];
	int first_err = 0;

	if (payload) {
		const char *data = nla_data(payload);
		int len = nla_len(payload);
		int pos = 0;
		int validate_err;
		char **paths;
		int path_count;
		unsigned int idx = 0;

		validate_err = ksu_nomount_validate_del_payload(data, len);
		if (validate_err)
			return validate_err;
		path_count = ksu_nomount_count_del_payload(data, len);
		if (path_count <= 0)
			return -EINVAL;
		paths = kcalloc(path_count, sizeof(*paths), GFP_KERNEL);
		if (!paths)
			return -ENOMEM;

		while (pos + 2 <= len) {
			char *virtual_path = NULL;
			u16 virtual_len;
			int err;

			virtual_len = get_unaligned((const u16 *)(data + pos));
			pos += 2;
			if (pos + virtual_len > len)
				return first_err ?: -EINVAL;

			err = ksu_nomount_copy_payload_path(data + pos, virtual_len,
							    &virtual_path);
			pos += virtual_len;
			if (!err) {
				paths[idx++] = virtual_path;
				virtual_path = NULL;
			}
			if (err && !first_err)
				first_err = err;
			kfree(virtual_path);
			if (err)
				break;
		}
		if (!first_err && pos != len)
			first_err = -EINVAL;
		if (idx) {
			int err = ksu_nomount_del_rules(paths, idx);

			if (err && !first_err)
				first_err = err;
		}
		ksu_nomount_free_path_array(paths, idx);

		return first_err ?: 0;
	}

	if (info->attrs[KSU_NOMOUNT_ATTR_VIRTUAL_PATH])
		return ksu_nomount_del_rule(
			nla_data(info->attrs[KSU_NOMOUNT_ATTR_VIRTUAL_PATH]));

	return -EINVAL;
}

static int ksu_nomount_genl_clear_rules(struct sk_buff *skb,
					struct genl_info *info)
{
	ksu_nomount_clear_all();
	return 0;
}

static int ksu_nomount_genl_add_uid(struct sk_buff *skb,
				    struct genl_info *info)
{
	if (!info->attrs[KSU_NOMOUNT_ATTR_UID])
		return -EINVAL;

	return ksu_nomount_add_uid(nla_get_u32(info->attrs[KSU_NOMOUNT_ATTR_UID]));
}

static int ksu_nomount_genl_del_uid(struct sk_buff *skb,
				    struct genl_info *info)
{
	if (!info->attrs[KSU_NOMOUNT_ATTR_UID])
		return -EINVAL;

	return ksu_nomount_del_uid(nla_get_u32(info->attrs[KSU_NOMOUNT_ATTR_UID]));
}

static int ksu_nomount_genl_get_version(struct sk_buff *skb,
					struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &ksu_nomount_genl_family, 0,
				info->genlhdr->cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	ret = nla_put_u32(msg, KSU_NOMOUNT_ATTR_VERSION, KSU_NOMOUNT_VERSION);
	if (ret) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

static int ksu_nomount_genl_dump_rules(struct sk_buff *skb,
				       struct netlink_callback *cb)
{
	struct ksu_nomount_dump_state state = {
		.bucket = cb->args[0],
		.index = cb->args[1],
	};
	struct ksu_nomount_dump_scratch *scratch;
	u32 flags;
	int ret;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	for (;;) {
		struct ksu_nomount_dump_state next = state;
		void *hdr;
		int err;

		err = ksu_nomount_get_dump_rule(&next, scratch->virtual_path,
						sizeof(scratch->virtual_path),
						scratch->real_path,
						sizeof(scratch->real_path),
						&flags);
		if (err == -ENOENT)
			break;
		if (err) {
			kfree(scratch);
			return err;
		}

		hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
				  cb->nlh->nlmsg_seq, &ksu_nomount_genl_family,
				  NLM_F_MULTI, KSU_NOMOUNT_CMD_GET_LIST);
		if (!hdr)
			break;

		if (nla_put_string(skb, KSU_NOMOUNT_ATTR_VIRTUAL_PATH,
				   scratch->virtual_path) ||
		    nla_put_string(skb, KSU_NOMOUNT_ATTR_REAL_PATH,
				   scratch->real_path) ||
		    nla_put_u32(skb, KSU_NOMOUNT_ATTR_FLAGS, flags)) {
			genlmsg_cancel(skb, hdr);
			break;
		}

		genlmsg_end(skb, hdr);
		state = next;
		cb->args[0] = state.bucket;
		cb->args[1] = state.index;
	}

	ret = skb->len;
	kfree(scratch);
	return ret;
}

static const struct nla_policy
	ksu_nomount_genl_policy[KSU_NOMOUNT_ATTR_MAX + 1] = {
		[KSU_NOMOUNT_ATTR_VIRTUAL_PATH] = {
			.type = NLA_NUL_STRING,
			.len = KSU_NOMOUNT_MAX_PATH,
		},
		[KSU_NOMOUNT_ATTR_REAL_PATH] = {
			.type = NLA_NUL_STRING,
			.len = KSU_NOMOUNT_MAX_PATH,
		},
		[KSU_NOMOUNT_ATTR_FLAGS] = { .type = NLA_U32 },
		[KSU_NOMOUNT_ATTR_UID] = { .type = NLA_U32 },
		[KSU_NOMOUNT_ATTR_VERSION] = { .type = NLA_U32 },
		[KSU_NOMOUNT_ATTR_PAYLOAD] = { .type = NLA_BINARY },
	};

static const struct genl_ops ksu_nomount_genl_ops[] = {
	{
		.cmd = KSU_NOMOUNT_CMD_ADD_RULE,
		.flags = GENL_ADMIN_PERM,
		.doit = ksu_nomount_genl_add_rule,
		KSU_NOMOUNT_OPS_POLICY
	},
	{
		.cmd = KSU_NOMOUNT_CMD_DEL_RULE,
		.flags = GENL_ADMIN_PERM,
		.doit = ksu_nomount_genl_del_rule,
		KSU_NOMOUNT_OPS_POLICY
	},
	{
		.cmd = KSU_NOMOUNT_CMD_CLEAR_ALL,
		.flags = GENL_ADMIN_PERM,
		.doit = ksu_nomount_genl_clear_rules,
		KSU_NOMOUNT_OPS_POLICY
	},
	{
		.cmd = KSU_NOMOUNT_CMD_ADD_UID,
		.flags = GENL_ADMIN_PERM,
		.doit = ksu_nomount_genl_add_uid,
		KSU_NOMOUNT_OPS_POLICY
	},
	{
		.cmd = KSU_NOMOUNT_CMD_DEL_UID,
		.flags = GENL_ADMIN_PERM,
		.doit = ksu_nomount_genl_del_uid,
		KSU_NOMOUNT_OPS_POLICY
	},
	{
		.cmd = KSU_NOMOUNT_CMD_GET_LIST,
		.flags = GENL_ADMIN_PERM,
		.dumpit = ksu_nomount_genl_dump_rules,
		KSU_NOMOUNT_OPS_POLICY
	},
	{
		.cmd = KSU_NOMOUNT_CMD_GET_VERSION,
		.flags = GENL_ADMIN_PERM,
		.doit = ksu_nomount_genl_get_version,
		KSU_NOMOUNT_OPS_POLICY
	},
};

static struct genl_family ksu_nomount_genl_family = {
	.name = KSU_NOMOUNT_GENL_NAME,
	.version = KSU_NOMOUNT_GENL_VERSION,
	.maxattr = KSU_NOMOUNT_ATTR_MAX,
	KSU_NOMOUNT_FAMILY_POLICY
	KSU_NOMOUNT_FAMILY_NETNSOK
	KSU_NOMOUNT_FAMILY_MODULE
	KSU_NOMOUNT_FAMILY_OPS
};

int ksu_nomount_netlink_init(void)
{
	int err;

#ifdef KSU_NOMOUNT_GENL_FAMILY_HAS_OPS
	err = genl_register_family(&ksu_nomount_genl_family);
#elif defined(KSU_NOMOUNT_HAS_GENL_REGISTER_FAMILY_WITH_OPS)
	err = genl_register_family_with_ops(
		&ksu_nomount_genl_family,
		(struct genl_ops *)ksu_nomount_genl_ops,
		ARRAY_SIZE(ksu_nomount_genl_ops));
#else
	err = -EOPNOTSUPP;
#endif
	if (!err)
		ksu_nomount_genl_registered = true;
	return err;
}

void ksu_nomount_netlink_exit(void)
{
	if (!ksu_nomount_genl_registered)
		return;

	genl_unregister_family(&ksu_nomount_genl_family);
	ksu_nomount_genl_registered = false;
}
