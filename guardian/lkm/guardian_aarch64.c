#include "guardian.h"

const unsigned long OA_MASK = 0xfffffffff000;
const unsigned long UART_VADDR = 0xffffff80fe201000;
const unsigned long UART_GADDR = 0xffffffa0fe201000;

__init void flush_all_tlb(void)     { asm volatile("tlbi vmalle1\nisb\n"); }
__init void enable_interrupt(void)  { asm volatile("msr daifclr, #0x3\n"); }
__init void disable_interrupt(void) { asm volatile("msr daifset, #0x3\n"); }
__init void flush_dcache_va(unsigned long vaddr) {
    asm volatile("dc cvac, %0\n" :: "r" (vaddr) : "memory");
}
__init void switch_k_ptbr(unsigned long k_ptbr) {
    unsigned long ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr1_el1));
    printlnStrHex("old ttbr_el1 = 0x\0", ttbr1_el1);
    ttbr1_el1 = (ttbr1_el1 & ~OA_MASK) | (k_ptbr & OA_MASK);
    printlnStrHex("new ttbr_el1 = 0x\0", ttbr1_el1);                // Guardian's PT is still active here
    asm volatile("msr ttbr1_el1, %0\n  isb\n" :: "r" (ttbr1_el1));  // Be careful after switching page table
    asm volatile("dsb ishst\n tlbi vmalle1\n dsb ish\n isb\n");
}
unsigned long get_k_ptbr(void) {
    unsigned long k_ptbr;
    asm volatile("mrs %0, ttbr1_el1" : "=r" (k_ptbr));
    return k_ptbr & OA_MASK;
}
unsigned long get_sp(void) {
    unsigned long sp;
    asm volatile("mov %0, sp\n" : "=r" (sp));
    return sp;
}
void arch_initialize(unsigned long k_ptbr) {    // for printing debug messages when kernel PT is active
    unsigned long i, j, uart, *pudt, *pmdt, *pt, idx, mair_el1;
    for (i = 0; i < 1; ++i) {                   // initialize only UART_VADDR but not UART_GADDR
        uart = (i == 0)? UART_VADDR : UART_GADDR;
        pr_info("arch_initialize: uart = 0x%lx\n", uart);
        pudt = (unsigned long *)__va(k_ptbr);
        idx = (uart >> 30) & 0x1ff;
        if ((pudt[idx] & 0x3) != 0x3) {
            pmdt = (unsigned long *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
            if ((pudt[idx] & 0x3) == 0x1) {     // split 1GB huge page
                pr_info("arch_initialize: warning, pud = 0x%lx\n", pudt[idx]);
                for (j = 0; j < PTRS_PER_PTE; ++j) pmdt[j] = pudt[idx] + j * PAGE_SIZE * (1 << ORDER_2MB);
            }
            pudt[idx] = (unsigned long)__pa(pmdt) | 0x3;
        }
        pmdt = (unsigned long *)__va(pudt[idx] & OA_MASK);
        idx = (uart >> 21) & 0x1ff;
        if ((pmdt[idx] & 0x3) != 0x3) {
            pt = (unsigned long *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
            if ((pmdt[idx] & 0x3) == 0x1) {     // split 2MB huge page
                pr_info("arch_initialize: warning, pmd = 0x%lx\n", pmdt[idx]);
                for (j = 0; j < PTRS_PER_PTE; ++j) pt[j] = (pmdt[idx] + j * PAGE_SIZE) | 0x2;
            }
            pmdt[idx] = (unsigned long)__pa(pt) | 0x3;
        }
        pt = (unsigned long *)__va(pmdt[idx] & OA_MASK);
        idx = (uart >> 12) & 0x1ff;
        asm volatile("mrs %0, mair_el1" : "=r" (mair_el1));
        pr_info("arch_initialize: mair_el1 = 0x%lx\n", mair_el1);   // change 0xc as mair_el1 changes
        pt[idx] = (__pa(uart) & OA_MASK) | 0x403 | 0xc;             // map uart as device memory
        pr_info("arch_initialize: updated pte = 0x%lx\n", pt[idx]);
    }
}
void arch_check_2mb_page(unsigned long k_ptbr, unsigned long vaddr_2mb) {
    unsigned long *pudt, *pmdt, idx;
    pudt = (unsigned long *)__va(k_ptbr);
    idx = (vaddr_2mb >> 30) & 0x1ff;
    if ((pudt[idx] & 0x3) != 0x3) {
        bf_printlnStrHex("arch_check_2mb_page: error, pud = 0x\0", pudt[idx]);
        return;
    }
    pmdt = (unsigned long *)__va(pudt[idx] & OA_MASK);
    idx = (vaddr_2mb >> 21) & 0x1ff;
    if ((pmdt[idx] & 0x3) != 0x3)
        bf_printlnStrHex("arch_check_2mb_page: error, pmd = 0x\0", pmdt[idx]);
}