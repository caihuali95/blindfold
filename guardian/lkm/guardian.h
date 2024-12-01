#ifndef __GUARDIAN_H__
#define __GUARDIAN_H__

#include <linux/blindfold.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <asm/memory.h>

#define GUARDIAN_AARCH64
#ifdef GUARDIAN_AARCH64
#include "guardian_aarch64.h"
#else
#endif

#define ORDER_2MB   9
#define ORDER_1GB   18

void flush_all_tlb(void);
void enable_interrupt(void);
void disable_interrupt(void);
void flush_dcache_va(unsigned long vaddr);
void arch_initialize(unsigned long k_ptbr);
void arch_check_2mb_page(unsigned long k_ptbr, unsigned long vaddr_2mb);
void switch_k_ptbr(unsigned long k_ptbr);
unsigned long get_k_ptbr(void);
unsigned long get_sp(void);

extern void printStr(char *);
extern void printHex(unsigned long);
extern void printlnHex(unsigned long);
extern void printlnStrHex(char *, unsigned long);

#endif