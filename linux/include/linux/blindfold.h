#ifndef BLINDFOLD_H
#define BLINDFOLD_H

#include <asm/ptrace.h>

#define DEPTH_PGD       0
#define DEPTH_PUD       1
#define DEPTH_PMD       2
#define DEPTH_PGT       3
#define DEPTH_TOP       DEPTH_PUD

#define MAX_N_VMA       64
                                    // rsG_debug
#define GCALL_SET_PT    0xCA0       // 0x00000fff
#define GCALL_SET_PTBR  0xCA1       // 0x00001000
#define GCALL_FREE_PGD  0xCA2       // 0x00002000
#define GCALL_CREATE_P  0xCA3
#define GCALL_FORKED_P  0xCA4
#define GCALL_RESUME_P  0xCA5
#define GCALL_INTRPT_P  0xCA6
#define GCALL_UACCESS_S 0xCA7
#define GCALL_PUT_U     0xCA7       // 0x00010000
#define GCALL_CLR_U     0xCA8       // 0x00020000
#define GCALL_STL_U     0xCA9       // 0x00040000
#define GCALL_GET_U     0xCAA       // 0x00080000
#define GCALL_CFM_U     0xCAB       // 0x00100000
#define GCALL_CTO_U     0xCAC       // 0x00200000
#define GCALL_STC_U     0xCAD       // 0x00400000
#define GCALL_UACCESS_E 0xCAD

typedef void (*rsG_func)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
extern rsG_func rsG_call;

extern unsigned long rsG_debug;
extern unsigned long is_current_sensitive(void);
extern unsigned long bf_fixup_uaccess(struct pt_regs *regs);

extern void bf_printStr(char *);
extern void bf_printHex(unsigned long);
extern void bf_printlnHex(unsigned long);
extern void bf_printlnStrHex(char *, unsigned long);

#endif
