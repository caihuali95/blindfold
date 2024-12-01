#include "guardian.h"

extern void asm_print_str(char *);          // These are used when Guardian's PT is active. Their counterparts
extern void asm_print_hex(unsigned long);   // "bf_XXX" in blindfold.c are used when kernel PT is active. Both
                                            // sets of functions can be used only after UART mapping is set up
void printStr(char *s) {
    asm volatile("mov x4, %0\n"
                 "bl asm_print_str\n" :: "r" (s) : "x0", "x1", "x2", "x3", "x4", "x30");
}
void printHex(unsigned long x) {
    const char *n = " ";
    asm volatile("mov x4, %0\n"
                 "bl asm_print_hex\n"
                 "mov x4, %1\n"
                 "bl asm_print_str\n" :: "r" (x), "r" (n) : "x0", "x1", "x2", "x3", "x4", "x5", "x30");
}
void printlnHex(unsigned long x) {
    const char *n = "\n";
    asm volatile("mov x4, %0\n"
                 "bl asm_print_hex\n"
                 "mov x4, %1\n"
                 "bl asm_print_str\n" :: "r" (x), "r" (n) : "x0", "x1", "x2", "x3", "x4", "x5", "x30");
}
void printlnStrHex(char *s, unsigned long x) {
    const char *n = "\n";
    asm volatile("mov x4, %0\n"
                 "bl asm_print_str\n"
                 "mov x4, %1\n"
                 "bl asm_print_hex\n"
                 "mov x4, %2\n"
                 "bl asm_print_str\n" :: "r" (s), "r" (x), "r" (n) : "x0", "x1", "x2", "x3", "x4", "x5", "x30");
}

extern void rsG_secboot(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

DEFINE_SPINLOCK(ipi_lock);
volatile unsigned int ipi_wait = 0x0;
static __init void ipi_handler(void *_empty) {
    disable_interrupt();
    spin_lock(&ipi_lock);
    ipi_wait += 1;
    bf_printlnStrHex("enqueued, ipi_wait = 0x\0", ipi_wait);
    spin_unlock(&ipi_lock);
    while (ipi_wait < HW_N_CORE) { }    // wait for the primary core to finish initialization
    flush_all_tlb();
    spin_lock(&ipi_lock);
    bf_printlnHex(ipi_wait);            // don't print string as it is in the hidden core's rodata
    spin_unlock(&ipi_lock);
    enable_interrupt();
}
static __init void blindfold_init(rsG_func entry) {
    spin_lock(&ipi_lock);   // printing string triggers page fault as it is in the hidden core's rodata
    if (rsG_call) bf_printlnStrHex("blindfold_init: error, rsG_call = 0x\0", (unsigned long)rsG_call);
    rsG_call = entry;
    rsG_debug = 0x007f30ff;
    flush_dcache_va((unsigned long)&rsG_call);
    flush_dcache_va((unsigned long)&rsG_debug);
    ipi_wait += 1;
    spin_unlock(&ipi_lock);
}
static __init unsigned long get_checked_2mb_page(unsigned long k_ptbr) {
    unsigned long vaddr_2mb;
    vaddr_2mb = __get_free_pages(GFP_KERNEL | __GFP_ZERO, ORDER_2MB);
    if (vaddr_2mb & 0x1fffff) {
        bf_printlnStrHex("get_checked_2mb_page: error, vaddr_2mb = 0x\0", vaddr_2mb); 
        return 0;
    }
    arch_check_2mb_page(k_ptbr, vaddr_2mb);
    return vaddr_2mb;
}
extern unsigned long empty_zero_page[];
static __init int guardian_init(void) {
    struct cpumask mask;
    unsigned int cpu_id, i;
    unsigned long k_ptbr, vaddr_2mb, *frame, mod_segs[MOD_MEM_NUM_TYPES + 1][2];

    disable_interrupt();
    k_ptbr = get_k_ptbr();
    arch_initialize(k_ptbr);                // start using bf_printXXX after this point
    cpumask_clear(&mask);
    cpu_id = smp_processor_id();
    for (i = 0; i < HW_N_CORE; ++i)
        if (i != cpu_id) cpumask_set_cpu(i, &mask);
    on_each_cpu_mask(&mask, ipi_handler, NULL, 0);
    while (ipi_wait < HW_N_CORE - 1) { }    // wait for all other cores to enqueue
    vaddr_2mb = get_checked_2mb_page(k_ptbr);
    frame = (unsigned long *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    for (i = 0; i <= HW_N_GB * 2; ++i) { frame[i] = get_checked_2mb_page(k_ptbr); }
    for (i = 0; i < MOD_MEM_NUM_TYPES; ++i) {
        mod_segs[i][0] = (unsigned long)THIS_MODULE->mem[i].base;
        mod_segs[i][1] = (unsigned long)THIS_MODULE->mem[i].base + THIS_MODULE->mem[i].size;
        bf_printlnStrHex("start\t = 0x\0", mod_segs[i][0]);
        bf_printlnStrHex("end\t = 0x\0", mod_segs[i][1]);
    }
    mod_segs[MOD_MEM_NUM_TYPES][1] = (get_sp() & ~0xfff) + PAGE_SIZE;
    mod_segs[MOD_MEM_NUM_TYPES][0] = mod_segs[MOD_MEM_NUM_TYPES][1] - THREAD_SIZE;
    rsG_secboot(vaddr_2mb, k_ptbr, (unsigned long)frame, (unsigned long)mod_segs, __pa_symbol(empty_zero_page));
    switch_k_ptbr(k_ptbr);                              // Call kernel functions only after switch to kernel PT
    blindfold_init((rsG_func)((void *)frame + 0x800));  // Touching hidden Guardian's pages will trigger faults
    // Lazy to do: erase msr instructions that involves sensitive control register updates in kernel code
    enable_interrupt();
    return 0;
}

static __exit void guardian_exit(void) {        // This should fail since Guardian's pages are hidden from
    bf_printStr("Shutting down Guardian\n");    // the kernel and refuse to be unloaded after secure boot
}

module_init(guardian_init);
module_exit(guardian_exit);

MODULE_AUTHOR("Caihua Li <caihua.li@yale.edu>");
MODULE_DESCRIPTION("Blindfold's Guardian");
MODULE_LICENSE("GPL");