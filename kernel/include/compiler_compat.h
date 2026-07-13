/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_COMPILER_COMPAT_H
#define __KSU_COMPILER_COMPAT_H

/* Upstream legacy kernels predate Android's Clang CFI annotation. */
#ifndef __nocfi
#define __nocfi
#endif

#endif /* __KSU_COMPILER_COMPAT_H */
