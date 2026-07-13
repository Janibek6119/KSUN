/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_SUSFS_COMPAT_H
#define __KSU_SUSFS_COMPAT_H

#include <linux/hugetlb.h>
#include <linux/jump_label.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/radix-tree.h>
#include <linux/rwsem.h>
#include <linux/seq_file.h>

#ifdef KSU_SUSFS_HAS_SCHED_MM
#include <linux/sched/mm.h>
#else
#include <linux/sched.h>
#endif

#ifdef KSU_SUSFS_HAS_PAGE_IDLE
#include <linux/page_idle.h>
#endif

#ifdef KSU_SUSFS_HAS_PGSIZE_MIGRATION
#include <linux/pgsize_migration.h>
#endif

#ifndef PTRACE_MODE_READ_FSCREDS
#define PTRACE_MODE_READ_FSCREDS PTRACE_MODE_READ
#endif

#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

/* The typed static-branch API landed after the original static-key API. */
#ifndef DEFINE_STATIC_KEY_FALSE
#define DEFINE_STATIC_KEY_FALSE(name) \
	struct static_key name = STATIC_KEY_INIT_FALSE
#endif

#ifndef static_branch_unlikely
#define static_branch_unlikely(key) static_key_false(key)
#endif

#ifndef static_branch_enable
#define static_branch_enable(key) static_key_slow_inc(key)
#endif

#ifndef static_branch_disable
#define static_branch_disable(key) static_key_slow_dec(key)
#endif

static inline bool ksu_susfs_mmget_not_zero(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MMGET_NOT_ZERO
	return mmget_not_zero(mm);
#else
	return atomic_inc_not_zero(&mm->mm_users);
#endif
}

static inline int ksu_susfs_mmap_read_lock_killable(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MMAP_LOCK
	return mmap_read_lock_killable(mm);
#elif defined(KSU_SUSFS_HAS_DOWN_READ_KILLABLE)
	return down_read_killable(&mm->mmap_sem);
#else
	down_read(&mm->mmap_sem);
	return 0;
#endif
}

static inline void ksu_susfs_mmap_read_unlock(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MMAP_LOCK
	mmap_read_unlock(mm);
#else
	up_read(&mm->mmap_sem);
#endif
}

static inline struct vm_area_struct *
ksu_susfs_first_vma(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MM_MT
	unsigned long index = 0;

	return mt_find(&mm->mm_mt, &index, ULONG_MAX);
#else
	return mm->mmap;
#endif
}

static inline struct vm_area_struct *
ksu_susfs_next_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
#ifdef KSU_SUSFS_HAS_MM_MT
	unsigned long index = vma->vm_end;

	return mt_find(&mm->mm_mt, &index, ULONG_MAX);
#else
	(void)mm;
	return vma->vm_next;
#endif
}

static inline int ksu_susfs_compound_nr(struct page *page)
{
#ifdef KSU_SUSFS_HAS_COMPOUND_NR
	return compound_nr(page);
#else
	return 1 << compound_order(page);
#endif
}

static inline bool ksu_susfs_page_is_young(struct page *page)
{
#ifdef KSU_SUSFS_HAS_PAGE_IDLE
	return page_is_young(page);
#else
	(void)page;
	return false;
#endif
}

static inline bool ksu_susfs_pagecache_is_value(const void *entry)
{
#ifdef KSU_SUSFS_HAS_XA_IS_VALUE
	return xa_is_value(entry);
#else
	return radix_tree_exceptional_entry((void *)entry);
#endif
}

static inline void ksu_susfs_seq_put_hex_ll(struct seq_file *m,
					     const char *delimiter,
					     unsigned long long value,
					     unsigned int width)
{
#ifdef KSU_SUSFS_HAS_SEQ_PUT_HEX_LL
	seq_put_hex_ll(m, delimiter, value, width);
#else
	if (delimiter)
		seq_puts(m, delimiter);
	seq_printf(m, "%0*llx", (int)width, value);
#endif
}

static inline void
ksu_susfs_seq_put_decimal_ull_width(struct seq_file *m,
				    const char *delimiter,
				    unsigned long long value,
				    unsigned int width)
{
#ifdef KSU_SUSFS_HAS_SEQ_PUT_DECIMAL_ULL_WIDTH
	seq_put_decimal_ull_width(m, delimiter, value, width);
#else
	if (delimiter)
		seq_puts(m, delimiter);
	seq_printf(m, "%*llu", (int)width, value);
#endif
}

static inline bool ksu_susfs_hugetlb_pmd_shared(pte_t *pte)
{
#ifdef KSU_SUSFS_HAS_HUGETLB_PMD_SHARED
	return hugetlb_pmd_shared(pte);
#else
	(void)pte;
	return false;
#endif
}

static inline unsigned long
ksu_susfs_vma_pad_start(struct vm_area_struct *vma)
{
#ifdef KSU_SUSFS_HAS_PGSIZE_MIGRATION
	return VMA_PAD_START(vma);
#else
	return vma->vm_end;
#endif
}

static inline void ksu_susfs_show_map_pad_vma(struct vm_area_struct *vma,
					       struct seq_file *m, void *show,
					       bool smaps)
{
#ifdef KSU_SUSFS_HAS_PGSIZE_MIGRATION
	show_map_pad_vma(vma, m, show, smaps);
#else
	(void)vma;
	(void)m;
	(void)show;
	(void)smaps;
#endif
}

#endif /* __KSU_SUSFS_COMPAT_H */
