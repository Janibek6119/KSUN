#ifndef __KSU_H_UTIL
#define __KSU_H_UTIL

#include "linux/fdtable.h" // IWYU pragma: keep
#include <linux/version.h>
#include <linux/syscalls.h>

#ifdef KSU_HAS_CLOSE_FD
#define ksu_close_fd close_fd
#elif defined(KSU_HAS_KSYS_CLOSE)
#define ksu_close_fd ksys_close
#else
#define ksu_close_fd sys_close
#endif

#endif
