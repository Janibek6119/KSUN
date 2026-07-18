# KernelSU Hookless NoMount

This branch adds a KernelSU-Next-hosted NoMount compatibility layer on top of
the hookless SUSFS runtime. It is inspired by NoMount's hookless branch at
`https://github.com/maxsteeel/nomount/tree/experimental/hookless`, the
branch-link hook work in `https://github.com/backslashxx/KernelSU`, and the
operation-table shadowing ideas in `https://github.com/Anatdx/Kasumi`, but it
does not copy NoMount's kernel integration model.

## Goals

- Keep all NoMount integration inside `KernelSU-Next/kernel/`.
- Avoid adding `fs/nomount.c` or editing the main kernel `fs/Kconfig` /
  `fs/Makefile`.
- Preserve NoMount's Generic Netlink ABI so the existing `nm` userspace binary
  can continue to talk to the kernel family named `nomount`.
- Reuse the SUSFS VFS shadow engine instead of stacking a second set of
  `inode_operations`, `file_operations`, and `super_operations` wrappers.
- Depend on `KSU_KPROBES_HOOK` through `KSU_KPROBES_SUSFS`.

## Kconfig

Enable:

```text
CONFIG_KSU_KPROBES_HOOK=y
CONFIG_KSU_KPROBES_SUSFS=y
CONFIG_KSU_KPROBES_NOMOUNT=y
```

`KSU_KPROBES_NOMOUNT` requires `NET`. The implementation uses the Generic
Netlink API when it is available, but it does not depend on the
`GENERIC_NETLINK` Kconfig symbol because some Android kernels expose the
headers and helpers without that symbol.

## Architecture

NoMount owns only policy state:

- exact virtual path rules
- parent directory child arrays used for `readdir`
- UID block rules
- Generic Netlink command handling

SUSFS owns the VFS interception:

- parent directory lookup wrapping
- parent directory iteration wrapping
- redirect inode creation
- superblock lifetime cleanup

When `nm add <virtual> <real>` is received, the NoMount layer normalizes the
paths, validates the real path, asks SUSFS to attach the virtual parent
directory, then publishes a child entry through an RCU-protected child array.
Lookup copies the rule data under RCU and lets SUSFS create the transient
redirect inode.

When `nm w <virtual>` is received, the child is marked as a whiteout. Directory
iteration filters the original child and lookup returns a negative dentry.

When `nm block <uid>` is received, that UID sees the original filesystem. This
matches upstream NoMount's isolation model and is separate from KernelSU's
app umount allowlist.

## Netlink ABI

The Generic Netlink family remains:

- family name: `nomount`
- family version: `1`
- module ABI version: `13`

Supported commands:

- `GET_VERSION`
- `ADD_RULE`
- `DEL_RULE`
- `CLEAR_ALL`
- `ADD_UID`
- `DEL_UID`
- `GET_LIST`

Both the string attributes and NoMount's packed batch payloads are supported.
The Kbuild probes place the netlink policy on `struct genl_ops` for older
headers and on `struct genl_family` for newer headers. They also select
between embedded family ops and legacy `genl_register_family_with_ops()`
registration, which is the main NoMount hookless compatibility risk on older
Android kernels.

## Current Scope

Implemented:

- injection into existing parent directories
- replacement of existing children
- whiteout of existing or future children
- synthetic intermediate virtual directories when the virtual parent path does
  not exist
- symlink redirect inodes
- UID block/unblock
- rule listing and clear
- 32-bit compat `readdir` position range

Synthetic ancestors are created as internal NoMount directory rules and are not
returned by `GET_LIST`. SUSFS uses their visible path for follow-up
lookup/readdir on nested virtual directories, while the backing path is only a
staging anchor used to instantiate redirect inodes. Internal synthetic
directories only expose NoMount children, so fallback anchors like `/` do not
leak unrelated backend entries into the virtual tree.

Still intentionally avoided:

- NoMount's separate standalone inode/superblock wrapper stack
- kernel-tree changes under the main `fs/` directories

This keeps NoMount and SUSFS sharing one VFS interception layer instead of
competing over the same operation tables.

## Legacy Kernel Notes

The primary target is Android ARM64 4.19/5.4 through heavily backported 5.4
trees. The implementation avoids version-only assumptions where the Generic
Netlink structure layout is known to vary. Kernels older than 4.19 are not a
current target because KernelSU's hookless path already needs modern kprobes,
syscall tracepoints, and Android VFS/procfs surfaces.
