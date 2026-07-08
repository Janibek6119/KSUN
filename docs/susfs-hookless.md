# SUSFS Hookless Design Notes

## Goal

Move SUSFS away from patching core kernel source files like `fs/namei.c`,
`fs/readdir.c`, `fs/stat.c`, `fs/statfs.c`, `fs/proc/*`, `mm/*`, and
`security/selinux/*`.

The target environment is `KernelSU-Next` with `CONFIG_KSU_KPROBES_HOOK=y`.
Modifying `KernelSU-Next` is allowed. Patching the main kernel tree should be
avoided.

## Why NoMount Is "Hookless"

The `origin/experimental/hookless` branch of NoMount does not patch generic VFS
entry points anymore. Its kernel integration patch only adds:

- `fs/Kconfig`
- `fs/Makefile`

The actual interception is done at runtime by hijacking per-object operation
tables:

- `inode->i_op`
- `inode->i_fop`
- `sb->s_op`
- `sb->s_xattr`

It then:

1. Builds a virtual topology for affected parent directories.
2. Swaps lookup and iterate callbacks only on those directories.
3. Creates synthetic front-facing inodes for virtual or redirected entries.
4. Delegates real IO to backend inodes while keeping the VFS surface local to
   the affected objects.

This is why NoMount no longer needs per-kernel patches in `namei.c`,
`readdir.c`, `stat.c`, `statfs.c`, `task_mmu.c`, or `d_path.c`.

## Why SUSFS Is Harder

Current SUSFS is split into two parts:

1. State and rule storage in `fs/susfs.c`.
2. A wide patch set that injects SUSFS checks into generic kernel paths.

The current patch set touches many files because SUSFS covers several different
problem classes:

- `sus_path`: pathname hiding
- `open_redirect`: pathname redirection
- `sus_kstat`: metadata spoofing
- `sus_map`: proc/mm mapping hiding
- `sus_mount`: mountinfo and mount namespace hiding
- `spoof_uname`
- `spoof_cmdline_or_bootconfig`
- `avc_log_spoofing`

Not all of these can be solved with the same NoMount-style VFS object hijack.

## Important Observation For This Tree

In this kernel, `drivers/kernelsu` is a symlink to
`KernelSU-Next/kernel`. That means SUSFS can live inside `KernelSU-Next` and be
linked into the kernel as part of the existing KernelSU object set.

That gives us a much better route than `susfs4ksu` uses today:

- no `fs/Makefile` patch for `susfs.o`
- no `include/linux/susfs*.h` patch into the main tree
- no direct source edits to generic kernel code

Instead, SUSFS can become an internal KernelSU subsystem.

## Proposed Architecture

### 1. Build A KSU-Hosted SUSFS Core

Add a new SUSFS subsystem under `KernelSU-Next/kernel/`, for example:

- `kernel/susfs/core.c`
- `kernel/susfs/path.c`
- `kernel/susfs/redirect.c`
- `kernel/susfs/proc.c`
- `kernel/susfs/mount.c`
- `kernel/susfs/policy.c`

And add corresponding `Kconfig` and `Kbuild` entries inside `KernelSU-Next`.

### 2. Replace Per-Inode Flag Hiding With Rule-Based Virtual Topology

Current `sus_path` depends on:

- setting custom bits in `inode->i_mapping->flags`
- checking those bits from patched `namei.c` and `readdir.c`

That model is the main reason kernel patching is required.

Instead, `sus_path` should move to the same model used by NoMount:

- hash rules by virtual path
- keep parent directory nodes
- keep child arrays per affected parent
- hijack only the affected parent `i_op.lookup`
- hijack only the affected parent `i_fop.iterate*`

This turns `sus_path` from a global lookup filter into a local virtual-filesystem
overlay.

### 3. Merge `open_redirect` Into The Same Front-End

`open_redirect` does not need a global `open.c` path rewrite if lookup returns a
synthetic inode for the virtual target.

That synthetic inode can carry:

- visible virtual path identity
- backend real inode or backend real file
- spoofed metadata profile
- access policy

This lets one front-end cover:

- `sus_path`
- `open_redirect`
- most of `sus_kstat`

### 4. Prefer Synthetic Inodes Over Global Getattr Hooks

For redirected or hidden entries, metadata spoofing should be served by custom
inode operations on the synthetic inode instead of patched:

- `generic_fillattr`
- `vfs_getattr`
- `show_map_vma`

This works well for normal stat-style metadata. It also reduces the need for
global stat hooks, though standalone `sus_kstat` still benefits from a small
runtime compat layer for plain files that are not fronted by synthetic inodes.

### 5. Keep KernelSU Integration Minimal

SUSFS still needs policy about who should see the stock view and who should see
the SUSFS view.

This should stay inside `KernelSU-Next`, but the integration should be much
smaller than the current patch set:

- reuse KernelSU allowlist or app profile state
- reuse current KSU process / uid policy
- optionally keep a lightweight per-task "stock view" marker if still needed
- keep the userspace control plane in KernelSU supercall or move to generic
  netlink

## Features That Can Become Mostly Hookless

### Good Candidates

- `sus_path`
- `open_redirect`
- `sus_kstat` for redirected or virtual entries

These fit the NoMount pattern well because they are VFS object problems.

### Partial Candidates

- `sus_mount`
- `spoof_cmdline_or_bootconfig`
- `sus_kstat` for plain non-redirected files

These may be moved away from kernel source patching by runtime hijacking procfs
entry operations, `seq_operations`, or small post-VFS runtime hooks, but they
are not as clean as VFS directory/file interception.

### Poor Candidates For Full Hookless Conversion

- `avc_log_spoofing`

These touch global SELinux or proc/mm surfaces. They likely still need one of:

- KSU runtime hooks
- kprobes / kretprobes
- tracepoints
- function-table patching like KSU's LSM hook support

`sus_map` was implemented on this branch through a KSU-owned proc/mm
compatibility layer rather than through NoMount-style VFS virtualization. That
is the intended model for the remaining global surfaces too: keep them small,
localized, and owned by `KernelSU-Next`.

## Practical End State

The clean target is a hybrid model:

1. NoMount-style object hijacking for path-facing SUSFS features.
2. Small KSU runtime hooks only for the remaining global surfaces.

That gives us:

- no main-kernel source patching
- far less kernel-version churn
- most maintenance isolated inside `KernelSU-Next`

## Suggested Migration Order

### Phase 1

Implement a KSU-hosted rule engine and NoMount-style parent directory hijacking
for:

- `sus_path`
- `open_redirect`

### Phase 2

Fold `sus_kstat` into synthetic inode metadata for those same virtual entries.

### Phase 3

Add optional runtime hook helpers for:

- proc maps
- mountinfo / mountstat
- uname
- cmdline / bootconfig
- AVC spoofing

### Phase 4

Delete the old `susfs4ksu/kernel_patches/50_add_*` style integration path once
feature parity is good enough.

## Key Tradeoff

If we copy NoMount exactly, we will reduce maintenance fast, but we will also
lose some of the current SUSFS global spoof surfaces unless we reintroduce them
through a small runtime-hook layer inside `KernelSU-Next`.

So the realistic goal is not "zero hooks anywhere".

The realistic goal is:

- zero main-kernel source patches
- NoMount-style VFS hijack for path features
- minimal KSU-owned runtime hooks for global proc/mm/SELinux surfaces

## Current Branch Status

The current `susfs-hookless` branch implements the KSU-hosted hookless layer
inside `KernelSU-Next` only:

- `add_sus_path`
- `add_sus_path_loop`
- `add_open_redirect`
- `hide_sus_mnts_for_non_su_procs`
  Note: the procfs mount/fdinfo compatibility view is now scoped to the same
  umounted app/isolation UIDs as the rest of SUSFS. Root and zygote-side
  readers keep the stock procfs implementation so ReZygisk, TreatWheel, and
  similar tooling do not parse a rewritten mount view.
  Mount-namespace identity is normalized separately through a KSU-owned
  `mntns_get()` kretprobe so `/proc/*/ns/mnt`, `readlink()`, and namespace-fd
  identity stay aligned with the visible main namespace for SUSFS-hidden app
  readers.
- `add_sus_kstat`
- `update_sus_kstat`
- `add_sus_kstat_statically`
  Note: standalone `sus_kstat` is implemented with a `vfs_getattr_nosec()`
  kretprobe plus runtime patches on the proc `maps` and `smaps`
  `seq_operations.show` slots.
  The patched show handlers only spoof output for the same umounted
  app/isolation readers SUSFS is targeting; root and zygote-side readers fall
  back to the kernel's original procfs logic.
- `add_sus_map`
  Note: standalone `sus_map` is implemented with KSU-owned runtime patches on
  the proc `maps` and `smaps` `seq_operations.show` slots.
  The broader hookless proc/mm wrappers for `/proc/*/smaps_rollup`,
  `/proc/*/pagemap`, `map_files`, and `/proc/*/mem` are deliberately kept on
  the stock kernel path for now, but the original BRENE-triggered
  `add_sus_map` panic path has been fixed: current live-device replay of the
  BRENE module's `sus_map` batch no longer reproduces the
  `scheduling while atomic` crash.
- `set_cmdline_or_bootconfig`
  Note: this 5.4 target exposes `/proc/cmdline` but does not have
  `/proc/bootconfig`, so the compat command maps to cmdline spoofing only.
  The hookless implementation now swaps the kernel's `saved_command_line`
  pointer from inside KernelSU-Next instead of patching the proc entry's
  `single_show` callback at runtime.
- `set_uname`
- `enable_avc_log_spoofing`
- compat reporting for `show_version`, `show_variant`, and
  `show_enabled_features`
- delayed property hygiene for BRENE-style resetprop cleanup
  Note: the kernel-owned KSU init-rc injection now captures a pre-module
  baseline for
  `ro.build.version.known_codenames` and
  `ro.product.ab_ota_partitions`. The matching restore path is no longer
  embedded in the appended init rc; instead `on_boot_completed()` schedules a
  kernel-owned usermode helper retry window that deletes `ro.modversion`,
  restores the tracked coherence props, and rebuilds the property areas after
  asynchronous module scripts finish.
  This keeps the flow kernel-side without requiring a manager refresh while
  avoiding the init-rc parser regressions caused by embedding complex shell
  parameter expansion directly into the appended rc blob.

The implementation is intentionally scoped to built-in
`CONFIG_KSU_KPROBES_SUSFS` on top of `CONFIG_KSU_KPROBES_HOOK` and works by:

- storing SUSFS rules inside `KernelSU-Next`
- hijacking only affected parent-directory `i_op.lookup`
- hijacking only affected parent-directory `i_fop.iterate*`
- proxying selected superblock operations for synthetic redirected inodes
- patching procfs file-operation entry points at runtime for mount and fdinfo
  views
- using a `mntns_get()` kretprobe so mount-namespace symlink, path-follow, and
  namespace-fd identity all converge on the same visible namespace for
  SUSFS-hidden app readers
- patching procfs `maps` and `smaps` `seq_operations.show` slots at runtime
  for standalone `sus_kstat` dev:ino spoofing and `sus_map` hiding
- replacing `/proc/cmdline` from inside KSU instead of patching proc source
- using a KSU syscall hook for `uname` instead of patching `kernel/sys.c`
- reusing the existing KSU AVC spoof feature instead of duplicating SELinux
  patch logic
- capturing the BRENE-oriented property baseline from KSU's injected init rc
  and restoring it from a delayed kernel-owned usermode helper retry window
  after `boot-completed`, so it stays kernel-side without depending on manager
  updates
- deferring SUSFS compat commands onto task work when running through
  `CONFIG_KSU_KPROBES_HOOK`, so path resolution, mutexes, and user buffer
  copies do not execute from the reboot kprobe's atomic pre-handler context

For the proc/mm compatibility layer, the current implementation also assumes
the target kernel exposes the needed procfs symbols through kallsyms. On this
`lisa_kernel` tree that is a reasonable assumption because the arm64 defconfig
already enables `CONFIG_KALLSYMS_ALL=y`.

At this point the old SUSFS feature set from the main kernel patch path is
mostly covered from inside `KernelSU-Next`, with the remaining complexity
concentrated in the proc/mm compatibility layer instead of spread across
multiple core kernel files. The one deliberate gap right now is the broader
`sus_map` proc/mm surface, which is narrowed to `maps` and `smaps` until the
live-device lockup on LSPosed preload mappings is fully root-caused.

One live-device panic has now been root-caused: under
`CONFIG_KSU_KPROBES_HOOK`, SUSFS compat commands originally ran directly from
the `sys_reboot` kprobe pre-handler. Replaying BRENE's `add_sus_map` batch
triggered `BUG: scheduling while atomic` from `ksu_susfs_handle_sus_map_compat`
in that atomic context. The current branch fixes that by deferring SUSFS
compat work to task work before returning to userspace.

For compatibility, the procfs runtime layer is intentionally narrower than the
old global kernel patch path. The hookless implementation only rewrites procfs
views for the umounted app/isolation processes SUSFS is targeting, while
zygote/root readers continue through the stock kernel code path.

One legacy option is intentionally not ported as part of the hookless layer:

- `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS`

That knob is about symbol visibility hardening rather than SUSFS feature
coverage, so it is treated as separate future work instead of a blocker for the
hookless migration.
