#include <linux/blindfold.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/printk.h>

#define __BF_ARCH_AARCH64

rsG_func rsG_call = NULL;
EXPORT_SYMBOL(rsG_call);

unsigned long rsG_debug = 0x00000f00;
EXPORT_SYMBOL(rsG_debug);

unsigned long is_current_sensitive(void) {
    unsigned long tmp;
    if (!rsG_call) return 0x0;
    asm volatile("mrs %0, tcr_el1\n" : "=r" (tmp));
    return tmp & 0x80;
//    asm volatile("mrs %0, ttbr0_el1\n" : "=r" (tmp));
//    return tmp >> 63;
}
EXPORT_SYMBOL(is_current_sensitive);

unsigned long bf_fixup_uaccess(struct pt_regs *regs) {
    if (!rsG_call || regs->pc != ((unsigned long)rsG_call) - 0x4) { return 0; }
    if (regs->regs[0] < GCALL_UACCESS_S || GCALL_UACCESS_E < regs->regs[0]) { return 0; }
    if (regs->regs[0] == GCALL_GET_U || regs->regs[0] == GCALL_PUT_U) { *((int*)regs->regs[5]) = -EFAULT; } else
    if (regs->regs[0] == GCALL_STL_U || regs->regs[0] == GCALL_STC_U) { *((long*)regs->regs[5]) = regs->regs[1] + 1; }
    regs->pc = regs->regs[8];
    return 1;
}

static void nano_init(void *empty) {
#ifdef __BF_ARCH_AARCH64
       asm volatile("mov x0, 0xf\n"                       // ER | CR | SW | EN
                    "msr PMUSERENR_EL0, x0\n"
                    "mov x0, 0xc7\n"                      // LP | LC | C | P | E
                    "mrs x1, PMCR_EL0\n"
                    "bfi x1, x0, #0, #10\n"
                    "msr PMCR_EL0, x1\n"
                    "mov x0, 0x08000000\n"                // NSH                  EL0 & EL1 & EL2 & EL3
                    "msr PMCCFILTR_EL0, x0\n"
//                  "mov x0, 0x08000000\n"                // NSH                  EL0 & EL1 & EL2 & EL3
//                  "mov x0, 0xCC000000\n"                // P | U | NSH | M      EL2 & EL3
                    "mov x0, 0x04000000\n"                // M                    EL0 & EL1
//                  "mov x0, 0x44000000\n"                // U | M                EL1
//                  "mov x0, 0x80000000\n"                // P                    EL0
                    "mov x1, #0x2\n"                      // L1 I TLB refill
                    "orr x1, x1, x0\n"
                    "msr PMEVTYPER0_EL0, x1\n"
                    "mov x1, #0x1\n"                      // L1 I cache refill
                    "orr x1, x1, x0\n"
                    "msr PMEVTYPER1_EL0, x1\n"
                    "mov x1, #0x5\n"                      // L1 D TLB refill
                    "orr x1, x1, x0\n"
                    "msr PMEVTYPER2_EL0, x1\n"
                    "mov x1, #0x3\n"                      // L1 D cache refill
                    "orr x1, x1, x0\n"
                    "msr PMEVTYPER3_EL0, x1\n"
                    "mov x1, #0x13\n"                     // Data memory access
                    "orr x1, x1, x0\n"
                    "msr PMEVTYPER4_EL0, x1\n"
                    "mov x1, #0x9\n"                      // Exception taken
                    "orr x1, x1, x0\n"
                    "msr PMEVTYPER5_EL0, x1\n"
                    "mov x0, 0x3f\n"                      // enable C | P0-5
                    "orr x0, x0, #0x80000000\n"           // P0-5 setup is for hikey960
                    "msr PMCNTENSET_EL0, x0\n"            // they are not used in RPI4
                    "isb\n"
                    "smc #0xdb0\n"
                    "isb\n"
                    ::: "x0", "x1");
#endif
}

SYSCALL_DEFINE6(blindfold, unsigned long, cmd, unsigned long, a1, unsigned long, a2, unsigned long, a3, unsigned long, a4, unsigned long, a5) {
    unsigned long i, cost_1_3, cost_3_1, t0, t1, t2, t3;
    switch (cmd) {
        case 0x0:
            pr_crit("blindfold: error, cmd == 0x0 is reserved for nano benchmark\n");
            break;
        #ifdef __BF_ARCH_AARCH64
		case 0xdb0:                     // BF: for nano benchmark
			pr_crit("blindfold: initialize PMU counters and HCR_EL2\n");
			on_each_cpu(nano_init, NULL, 1);
			break;
		case 0xdbc:                     // BF: for nano benchmark
			pr_crit("blindfold: nano benchmark: EL1 -> EL3 -> EL1\n");
			cost_1_3 = cost_3_1 = 0;
			for (i = 0; i < 10000; ++i) {
				asm volatile ("mrs x1, pmccntr_el0\n"
							  "smc #0xdbc\n"
							  "mrs x0, pmccntr_el0\n"
							  "mov %0, x1\n"
							  "mov %1, x2\n"
							  "mov %2, x3\n"
							  "mov %3, x0\n"
							: "=r" (t0), "=r" (t1), "=r" (t2), "=r" (t3) :
							: "x0", "x1", "x2", "x3");
				cost_1_3 += t1 - t0;	// after smc - before smc
				cost_3_1 += t3 - t2;	// after eret - before eret
			}
			pr_crit("EL1 -> EL3: %ld\n", cost_1_3 / 10000);
			pr_crit("EL3 -> EL1: %ld\n", cost_3_1 / 10000);
			break;
        #endif
		default:
			pr_crit("blindfold: unknown cmd 0x%lx\n", cmd);
	}
    return 0;
}

extern void bf_asm_print_str(char *);           // these can not be used until init_uart_mapping is called
extern void bf_asm_print_hex(unsigned long);

DEFINE_SPINLOCK(print_lock);
void bf_printStr(char *s) {
    spin_lock(&print_lock);
    asm volatile("mov x4, %0\n"
                 "bl bf_asm_print_str\n" :: "r" (s) : "x0", "x1", "x2", "x3", "x4", "x30");
    spin_unlock(&print_lock);
}
void bf_printHex(unsigned long x) {
    const char *n = " ";
    spin_lock(&print_lock);
    asm volatile("mov x4, %0\n"
                 "bl bf_asm_print_hex\n"
                 "mov x4, %1\n"
                 "bl bf_asm_print_str\n" :: "r" (x), "r" (n) : "x0", "x1", "x2", "x3", "x4", "x5", "x30");
    spin_unlock(&print_lock);
}
void bf_printlnHex(unsigned long x) {
    const char *n = "\n";
    spin_lock(&print_lock);
    asm volatile("mov x4, %0\n"
                 "bl bf_asm_print_hex\n"
                 "mov x4, %1\n"
                 "bl bf_asm_print_str\n" :: "r" (x), "r" (n) : "x0", "x1", "x2", "x3", "x4", "x5", "x30");
    spin_unlock(&print_lock);
}
void bf_printlnStrHex(char *s, unsigned long x) {
    const char *n = "\n";
    spin_lock(&print_lock);
    asm volatile("mov x4, %0\n"
                 "bl bf_asm_print_str\n"
                 "mov x4, %1\n"
                 "bl bf_asm_print_hex\n"
                 "mov x4, %2\n"
                 "bl bf_asm_print_str\n" :: "r" (s), "r" (x), "r" (n) : "x0", "x1", "x2", "x3", "x4", "x5", "x30");
    spin_unlock(&print_lock);
}
EXPORT_SYMBOL(bf_printStr);
EXPORT_SYMBOL(bf_printHex);
EXPORT_SYMBOL(bf_printlnHex);
EXPORT_SYMBOL(bf_printlnStrHex);
