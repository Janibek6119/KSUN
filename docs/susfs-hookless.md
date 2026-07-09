# SUSFS Hookless

## Overview

`susfs-hookless` moves SUSFS integration out of main-kernel source patches and
into `KernelSU-Next` only.

The target configuration is:

- `CONFIG_KSU_KPROBES_HOOK=y`
- `CONFIG_KSU_KPROBES_SUSFS=y`

On the Lisa kernel tree, `drivers/kernelsu` resolves to
`KernelSU-Next/kernel`, so the hookless SUSFS layer is consumed through the
existing KernelSU build path without adding new `fs/` or `include/` files to
the main kernel tree.

## Goal

The goal is not "zero hooks anywhere".

The goal is:

- no manual source patching across generic kernel files such as `fs/*`,
  `mm/*`, `kernel/sys.c`, or `security/selinux/*`
- all SUSFS maintenance kept inside `KernelSU-Next`
- runtime behavior that stays close to upstream SUSFS where it matters for
  userspace compatibility

## Design Model

Hookless SUSFS uses a hybrid model.

Path-facing features follow the same general idea as NoMount:

- store policy inside a KSU-owned rule engine
- hijack only affected per-object operation tables at runtime
- avoid global VFS edits

Global proc/mm surfaces use small KSU-owned runtime instrumentation:

- kprobes and kretprobes
- runtime procfs file-operation replacement
- runtime `seq_operations` replacement
- existing KSU hooks where they are already available

This keeps the maintenance boundary narrow while still covering SUSFS features
that cannot be expressed as a pure VFS overlay.

## Source Layout

The hookless implementation lives under `KernelSU-Next/kernel/`:

- `kernel/susfs/`
- `kernel/hook/`
- `kernel/infra/`
- `kernel/supercall/`

There is no dependency on the old `susfs4ksu/kernel_patches/50_add_*` main
kernel patch path.

## Runtime Architecture

### Path and redirect layer

`sus_path` and `open_redirect` are implemented as a local runtime overlay:

- rules are stored inside `KernelSU-Next`
- affected parent directories have their `i_op.lookup` replaced
- affected parent directories have their `i_fop.iterate*` replaced
- redirected entries are fronted by synthetic inodes backed by real objects

This removes the need for main-kernel edits in generic pathname resolution and
directory iteration code.

### Metadata spoofing

`sus_kstat` is split into two cases:

- virtual or redirected entries use the synthetic front-end path
- standalone files use a KSU-owned compatibility layer

The standalone compatibility layer currently uses:

- a `vfs_getattr_nosec()` kretprobe
- runtime replacement of proc `maps` and `smaps` `seq_operations.show`

### Mount hiding

Mount hiding is implemented from inside KernelSU by rewriting procfs mount
views at runtime instead of patching procfs source files.

The current layer covers:

- `/proc/*/mounts`
- `/proc/*/mountinfo`
- `/proc/*/mountstats`
- `/proc/*/fdinfo/*`

The rewritten view is intentionally scoped to the same SUSFS-targeted app and
isolated UIDs. Root and zygote-side readers stay on the stock kernel path.

### Mount namespace normalization

Helper and isolated app processes can start in a different mount namespace even
when they belong to the same package. To keep SUSFS mount hiding coherent, the
hookless layer normalizes package-local helpers onto the package's visible main
namespace.

The current flow is:

1. SUSFS receives the KSU setuid callback.
2. Work is deferred through task work so the logic does not run in atomic
   kprobe context.
3. The main package process is cached as a package anchor.
4. Same-package helpers such as `:tools` or isolated children try to join the
   anchor's mount namespace.
5. `ksu_join_task_mount_ns()` duplicates `current->fs` with
   `unshare_fs_struct()` when needed so `setns(CLONE_NEWNS)` satisfies the
   5.4 kernel `mntns_install()` requirement.

Namespace identity readback is normalized separately through the KSU-owned
`mntns_get()` kretprobe so `/proc/*/ns/mnt`, `readlink()`, and namespace-fd
identity stay aligned with the visible namespace.

### Proc/mm hiding

`sus_map` is implemented through runtime proc/mm compatibility hooks rather than
through main-kernel patches.

Today the live hookless coverage is intentionally limited to:

- `/proc/*/maps`
- `/proc/*/smaps`

This is the stable subset that was validated without the earlier BRENE crash
path.

### Cmdline, uname, AVC, and property hygiene

Other SUSFS-adjacent behaviors are handled inside KernelSU:

- `/proc/cmdline` spoofing swaps the KSU-visible `saved_command_line` pointer
  instead of patching proc entry source
- `uname` spoofing reuses a KSU syscall hook instead of patching
  `kernel/sys.c`
- AVC spoofing reuses the existing KSU AVC path
- delayed property hygiene restores BRENE-style resetprop coherence from a
  kernel-owned post-boot retry window

## Feature Coverage

### Implemented

The current branch covers the following SUSFS-facing operations inside
`KernelSU-Next`:

- `add_sus_path`
- `add_sus_path_loop`
- `add_open_redirect`
- `hide_sus_mnts_for_non_su_procs`
- `add_sus_kstat`
- `update_sus_kstat`
- `add_sus_kstat_statically`
- `add_sus_map`
- `set_cmdline_or_bootconfig`
- `set_uname`
- `enable_avc_log_spoofing`
- compat reporting for `show_version`, `show_variant`, and
  `show_enabled_features`
- delayed property hygiene for BRENE-style resetprop cleanup

There is also a built-in default hide for
`/product/overlay/LineageSDKOverlaySM8350.apk`, seeded from inside SUSFS init
and retried again from the boot-complete path so late-mounted overlays are
still covered.

### Partial or intentionally narrow

- `sus_map` currently targets `maps` and `smaps` only
- `/proc/bootconfig` is not implemented on this Lisa 5.4 target because the
  kernel exposes `/proc/cmdline` but not `/proc/bootconfig`
- procfs rewriting is scoped to app and isolated readers that are already under
  KSU's umount policy

### Not part of this branch

- `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS`

That knob is symbol-hardening work, not required for the hookless migration.

## Safety Rules

The hookless layer is intentionally conservative in a few places:

- root and zygote-side readers keep the stock procfs path
- SUSFS compat work is deferred out of atomic kprobe context
- package-helper namespace joins only apply to app or isolated processes that
  are already eligible for the KSU mount-hide view

This is important for keeping ReZygisk, TreatWheel, manager state persistence,
and module-side behavior stable.

## Verified Status

The current live-device validation on Lisa confirms:

- TNG helper mount drift is fixed
- the package main process and `:tools` helper now converge on the same mount
  namespace
- the kernel-side path no longer relies on main-kernel manual hooks
- the earlier BRENE `sus_map` atomic-context crash path is fixed by deferring
  compat work through task work

One concrete live replay after the `unshare_fs_struct()` fix showed:

- main process `my.com.tngdigital.ewallet` in `mnt:[4026534906]`
- helper process `my.com.tngdigital.ewallet:tools` also in
  `mnt:[4026534906]`

That replay replaced the earlier failing behavior where the helper stayed in a
different namespace and `setns(CLONE_NEWNS)` returned `-EINVAL` because the
process still shared its `fs_struct`.

## Configuration

Enable SUSFS hookless with:

- `CONFIG_KSU_KPROBES_HOOK=y`
- `CONFIG_KSU_KPROBES_SUSFS=y`

The hookless path is designed to work with kernel-side changes only. It does
not require a separate manager-side migration to function.

## Summary

`susfs-hookless` keeps SUSFS inside `KernelSU-Next`, replaces the old broad
main-kernel patch set with a mix of:

- NoMount-style per-object VFS hijacking for path features
- KSU-owned runtime instrumentation for proc/mm and namespace surfaces

This is the intended long-term maintenance model for the Lisa target:

- no generic-kernel manual hooks
- no SUSFS files spread through the main tree
- all feature work isolated inside `KernelSU-Next`
