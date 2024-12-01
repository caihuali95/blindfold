use crate::*;

pub const HW_N_GB       : usize = 8;
pub const HW_N_CORE     : usize = 4;
pub const SIZE_DRAM     : u64 = SIZE_1GB * HW_N_GB as u64;
pub const OA_MASK       : u64 = 0x0000_007f_ffff_f000;
pub const K_PAGE_OFFSET : u64 = 0xffff_ff80_0000_0000;
pub const G_PAGE_OFFSET : u64 = 0xffff_ffa0_0000_0000;
pub const UART_GADDR    : u64 = 0xffff_ffa0_fe20_1000;
pub const DEPTH_TOP     : u64 = DEPTH_PUD;

#[inline(always)]pub fn get_ptbr_asid(ptbr: u64) -> u64 { (ptbr >> 48) & 0xffff }
#[inline(always)]pub fn is_valid_entry(entry: u64) -> bool { entry & 0x1 == 0x1 }
#[inline(always)]pub fn is_block_entry(entry: u64) -> bool { entry & 0x3 == 0x1 }
#[inline(always)]pub fn is_valid_pte(entry: u64) -> bool { entry & 0x3 == 0x3 }
#[inline(always)]fn flush_tlb_va(vaddr: u64, last_level: bool) {
    let tag = ((if vaddr & K_PAGE_OFFSET != 0x0 { K_PAGE_OFFSET } else { 0x0 } | vaddr) / PAGE_SIZE) & ((1 << 44) - 1);
    if last_level { unsafe { asm!("tlbi vaale1is, {0}\n dsb ish\n isb\n", in(reg) tag); } }
    else { unsafe { asm!("tlbi vaae1is, {0}\n dsb ish\n isb\n", in(reg) tag); } }
}
#[inline]pub fn set_table_exec(pud: &mut u64, pmd: &mut u64, pte: &mut u64, vaddr: u64) {
    *pud &= !(1 << 59);
    *pmd &= !(1 << 59);
    *pte = *pte & !((1 << 53) | (1 << 51) | 0x800) | 0x80; // W^X & Global: unset PXN & DBM & nG, set AP[2]
    flush_tlb_va(vaddr, false);
}
#[inline]pub fn set_pte_op(pte: &mut u64, op: usize, vaddr: u64) {
    match op {
        OP_INVA => *pte &= !0x1,
        OP_VALI => *pte |=  0x1,
        OP_ROLY => *pte |=  0x80,
        OP_RDWR => *pte &= !0x80,
        _ => log_str(L_ERROR, "set_entry_op: unknown op\n\0")
    }
    flush_tlb_va(vaddr, true);
}
#[inline]pub fn set_entry(entry: &mut u64, val: u64, vaddr: u64, last_level: bool) {
    *entry = val;
    flush_tlb_va(vaddr, last_level);
}
#[inline(always)]pub fn set_entry_noflush(entry: &mut u64, val: u64) { *entry = val; }
#[inline(always)]pub fn atomic_inc_i16(ptr: *mut i16) -> i16 {
    let cnt: i16;
    unsafe { asm!("0:   ldaxrh  {0:w}, [{1}]",
                  "     add     {0:w}, {0:w}, #1",
                  "     stlxrh  {2:w}, {0:w}, [{1}]",
                  "     cbnz    {2:w}, 0b", out(reg) cnt, in(reg) ptr, out(reg) _); }
    cnt
}
#[inline(always)]pub fn atomic_dec_i16(ptr: *mut i16) -> i16 {
    let cnt: i16;
    unsafe { asm!("0:   ldaxrh  {0:w}, [{1}]",
                  "     sub     {0:w}, {0:w}, #1",
                  "     stlxrh  {2:w}, {0:w}, [{1}]",
                  "     cbnz    {2:w}, 0b", out(reg) cnt, in(reg) ptr, out(reg) _); }
    cnt
}
#[inline(always)]pub fn switch_vbar(is_secure: u64) {
    unsafe { asm!("msr vbar_el1, {0}\n isb\n", in(reg) if is_secure == SECURE { S_IT_VADDR } else { N_IT_VADDR }); }
}
#[inline(always)]pub fn set_ptbr(ptbr0: u64, ptbr1: u64, bp: u64) {
    unsafe { asm!("msr ttbr0_el1, {0}\n isb\n", in(reg) ptbr0); }
    set_base_idx(bp, BP_PT, ptbr1);
}
#[inline(always)]pub fn set_epd0() {
    unsafe { asm!("mrs {0}, tcr_el1\n",
                  "orr {0}, {0}, #0x80\n",
                  "msr tcr_el1, {0}\n isb\n", out(reg) _); }
//    let ttbr0_el1: u64;
//    unsafe { asm!("mrs {0}, ttbr0_el1\n", out(reg) ttbr0_el1); }
//    unsafe { asm!("msr ttbr0_el1, {0}\n isb\n", in(reg) ttbr0_el1 | (0x1 << 63)); }
}
#[inline(always)]pub fn unset_epd0() {
    unsafe { asm!("mrs {0}, tcr_el1\n",
                  "bic {0}, {0}, #0x80\n",
                  "msr tcr_el1, {0}\n isb\n", out(reg) _); }
//    let ttbr0_el1: u64;
//    unsafe { asm!("mrs {0}, ttbr0_el1\n", out(reg) ttbr0_el1); }
//    unsafe { asm!("msr ttbr0_el1, {0}\n isb\n", in(reg) ttbr0_el1 & !(0x1 << 63)); }
}
#[inline(always)]pub fn get_pid() -> u64 {
    let ttbr0_el1: u64;
    unsafe { asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0_el1); }
    return ttbr0_el1 & OA_MASK;
}
#[inline(always)]pub fn get_cid() -> u64 {
    let ttbr0_el1: u64;
    unsafe { asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0_el1); }
    return (ttbr0_el1 >> 48) & 0x7fff;
}
#[inline(always)]pub fn set_cid(ctxt: *mut Context) {
    let ttbr0_el1: u64;
    unsafe { asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0_el1); }
    let cid = if ctxt as u64 == 0x0 { 0x0 } else { unsafe { (ctxt as u64 - CTXT_GADDR) / (CONTEXT_N_REG as u64 * 8) } };
    unsafe { asm!("msr ttbr0_el1, {0}", in(reg) entry_wr_baddr((cid & 0x7fff) << 48, ttbr0_el1)); }
}
#[inline(always)]pub fn get_cpuid() -> usize {
    let mpidr_el1: usize;
    unsafe { asm!("mrs {0}, mpidr_el1", out(reg) mpidr_el1); }
    return mpidr_el1 & 0x3;
}
#[inline(always)]pub fn memset(addr: u64, n_byte: u64) {
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0x0, n_byte as usize); }
}
#[inline(always)]pub fn memcpy(dst: u64, src: u64, n_byte: u64) {
    unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, n_byte as usize); }
}
#[inline(always)]pub fn ith_IT_entry(ith: u64) -> u64 { unsafe { N_IT_VADDR + ith * 0x80 } }
#[inline(always)]pub fn dispatch_page_fault(uvaddr: u64, is_write: bool, bp: u64) {
    let daif = get_base_idx(bp, BP_IF);
    set_base_idx(bp, BP_IF, daif | 0x3c0);
    set_base_idx(bp, BP_LR, ith_IT_entry(4));
    unsafe { asm!("msr elr_el1, {0}\n msr spsr_el1, {1}\n",
                  "msr esr_el1, {2}\n msr far_el1,  {3}\n", in(reg) S_IT_VADDR + 0x800 - 0x4, in(reg) daif | 0x005u64,
                  in(reg) if is_write { 0x96000047u64 } else { 0x96000007u64 }, in(reg) uvaddr); }
}
#[inline]pub fn analyze_exception(ctxt: *mut Context, idx: u64) -> u64 {
    if idx & 0x3 != 0x0 { return EXP_ASYNC; }
    let esr_el1: u64;
    unsafe { asm!("mrs {0}, esr_el1", out(reg) esr_el1); }
    match (esr_el1 >> 26) & 0x3f {
        0x0 => {
            let elr_el1 = get_ctxt_idx(ctxt, CT_ELR);
            let inst = get_base_idx_u32(elr_el1, 0x0);
            if inst & !0x1f == 0xd5380000 {
                let midr_el1: u64;
                unsafe { asm!("mrs {0}, midr_el1", out(reg) midr_el1); }
                set_ctxt_idx(ctxt, (inst & 0x1f) as usize, midr_el1);
                set_ctxt_idx(ctxt, CT_ELR, elr_el1 + 4);
                EXP_EMULATE
            } else { EXP_SYNC }
        },
        0x15 => match get_ctxt_idx(ctxt, CT_SYSCALL) {
            0x86 => EXP_SYSSIGACT,
            0x8b => EXP_SYSSIGRET,
            0x5d | 0x5e => EXP_SYSEXIT,
            0xdd => EXP_SYSEXEC,
            0xdc => {
                let flags = get_ctxt_idx(ctxt, CT_A0);
                if flags & CLONE_VM == 0x0 { EXP_SYSFORK }
                else if flags & CLONE_VFORK == 0x0 { EXP_SYSCLONE }
                else {
                    let new_sp = get_ctxt_idx(ctxt, CT_A1);
                    if new_sp != 0x0 && new_sp != get_ctxt_idx(ctxt, CT_SP) { EXP_SYSCLONE } else { EXP_SYSVFORK }
                }
            }
            0xd6 => EXP_SYSBRK,
            0xde => EXP_SYSMMAP,
            0xd7 => EXP_SYSMUNMAP,
            0xe2 => EXP_SYSMPROT,
            0x60 => EXP_SYSTID,
            0x63 => EXP_SYSROBUST,
            0x125 => EXP_SYSRSEQ,
            sid @ (0xc2 | 0xc3 | 0xc4 | 0xc5 | 0xd8) => { log_strHex(L_ERROR, "analyze_exception: 0x\0", sid); EXP_SYSERROR },
            _ => EXP_SYSCALL,
        },
        0x20 | 0x24 => {
            let far_el1: u64;
            unsafe { asm!("mrs {0}, far_el1", out(reg) far_el1); }
            log_strHex(L_DEBUG, "analyze_exception: far_el1 = 0x\0", far_el1);
            log_strHex(L_DEBUG, "analyze_exception: sp = 0x\0", get_ctxt_idx(ctxt, CT_SP));
            EXP_FAULT
        },
        _ => EXP_SYNC,
    }
}
//--------------------------------------------------------------------------------------------------------------------------------
// The following code is super dangerous and should be handled with care. It's used to initialize the interrupt table.
// We should migrate this code to assembly but it is not done yet because we are lazy...
//--------------------------------------------------------------------------------------------------------------------------------
fn mov_imm64(gate: &mut [u32], pc: &mut usize, rd: u32, imm: u64) {
    gate[*pc] = 0xD2800000 | (( imm        & 0xffff) << 5) as u32 | rd; *pc += 1;  // movz rd, imm, lsl #0
    gate[*pc] = 0xF2A00000 | (((imm >> 16) & 0xffff) << 5) as u32 | rd; *pc += 1;  // movk rd, imm, lsl #16
    gate[*pc] = 0xF2C00000 | (((imm >> 32) & 0xffff) << 5) as u32 | rd; *pc += 1;  // movk rd, imm, lsl #32
    gate[*pc] = 0xF2E00000 | (((imm >> 48) & 0xffff) << 5) as u32 | rd; *pc += 1;  // movk rd, imm, lsl #48
}
// When entering an interrupt or exception, DAIF must be 0x0 as sensitive process runs. Guardian's stack and PT are
// already in places, so it's safe to save registers to the stack and no need to switch PT before calling Guardian
// In a Guardian call from kernel, switch PT and stack before and after Guardian's handling. Take care of LR & DAIF
pub fn init_interrupt_table(gate_vaddr: u64) {
    set_4kb_frame_flag(vaddr_to_pfn(gate_vaddr), RDONLY | ITPAGE);
    unsafe {
        S_IT_VADDR = gate_vaddr;
        asm!("mrs {0}, vbar_el1\n", out(reg) N_IT_VADDR);
        bf_log_strHex(L_DEBUG, "secure IT = 0x\0", S_IT_VADDR);
        bf_log_strHex(L_DEBUG, "normal IT = 0x\0", N_IT_VADDR);
    }
//--------------------------------------------------------------------------------------------------------------------------------
    let gate = addr_to_slice::<u32>(gate_vaddr, PAGE_SIZE / 4);
    let mut pc = 0x0;               // 16 entries in secure IT (0x0~0x200) where each has up to 0x20 instructions
    gate[pc] = 0xD50343DF; pc += 1; // msr DAIFset, #0x3            // no need to save DAIF as it must be 0x0
    gate[pc] = 0xD50041BF; pc += 1; // msr spsel, #1                // switch to use sp_el1, which is Guardian's stack
    gate[pc] = 0xD5033FDF; pc += 1; // isb                          // Guardian's stack and PT are already in places
    gate[pc] = 0xA9BF37EC; pc += 1; // stp x12, x13, [sp, #-0x10]!  // safe to save registers to Guardian's stack
    mov_imm64(gate, &mut pc, 12, unsafe { CTXT_GADDR });            // mov x12, CTXT_GADDR
    gate[pc] = 0xD538200D; pc += 1; // mrs x13, ttbr0_el1
    gate[pc] = 0xD370FDAD; pc += 1; // lsr x13, x13, #48
    gate[pc] = 0x924039AD; pc += 1; // and x13, x13, #0x7fff        // get context id in x13
    gate[pc] = 0x8B0D258C; pc += 1; // add x12, x12, x13, lsl #9    // logical shift: 9 = log2(CONTEXT_N_REG * 8)
let IT_ENTRY_N_STATIC_INST = pc;
//    gate[pc] = 0x; pc += 1; // movz x13, #idx                     // set x29 to entry index [0, 16) (<IT_N_ENTRY)
//    gate[pc] = 0x; pc += 1; // b label_IT_common                  // jump to common entrance
let IT_ENTRY_N_DYNAMIC_INST = 2;
    if pc + IT_ENTRY_N_DYNAMIC_INST >= 0x20 { bf_log_str(L_ERROR, "interrupt table entry overflow\n\0"); }
//--------------------------------------------------------------------------------------------------------------------------------
    pc = 0x200;                     // the only gate (0x200~0x300) for kernel to call Guardian
    gate[pc - 1] = 0xAA0803FE;      // mov x30, x8
    gate[pc] = 0xD53B4229; pc += 1; // mrs x9, DAIF                 // save DAIF to x9 temporarily
    gate[pc] = 0xD50343DF; pc += 1; // msr DAIFset, #0x3            // disable interrupts
    gate[pc] = 0xD50041BF; pc += 1; // msr spsel, #1                // switch to use sp_el1, which is kernel's stack
    gate[pc] = 0xD5033FDF; pc += 1; // isb                          // Guardian's stack and PT are not in places yet
    gate[pc] = 0x910003EA; pc += 1; // mov x10, sp                  // save kernel's SP to x10 temporarily
    gate[pc] = 0xD538202B; pc += 1; // mrs x11, ttbr1_el1           // kernel's PT in x11 while Guardian's in x12
    gate[pc] = 0xF132981F; pc += 1; // cmp x0, #0xCA6
let relocate_skip_a1 = pc;
    gate[pc] = 0x00000000; pc += 1; // b.le label_skip_a
    gate[pc] = 0xAA0503EF; pc += 1; // mov x15, x5
    gate[pc] = 0xAA1F03ED; pc += 1; // mov x13, xzr
    gate[pc] = 0xD5087825; pc += 1; // at s1e1w, x5
    gate[pc] = 0xD5387405; pc += 1; // mrs x5, par_el1
    gate[pc] = 0x924000AC; pc += 1; // and x12, x5, #0x1
let relocate_skip_b = pc;
    gate[pc] = 0x00000000; pc += 1; // cbnz x12, label_skip_b
    gate[pc] = 0xD34CBCAD; pc += 1; // ubfm x13, x5,  #12, #47
    gate[pc] = 0xD374CDAD; pc += 1; // lsl  x13, x13, #12
    gate[pc] = 0xD3402DEC; pc += 1; // ubfm x12, x15, #0,  #11
    gate[pc] = 0xAA0C01AD; pc += 1; // orr  x13, x13, x12
let label_skip_b = pc;
    gate[relocate_skip_b] = 0xB500000C | ((label_skip_b - relocate_skip_b) << 5) as u32;   // cbnz x12, label_skip_b
    gate[pc] = 0xAA0D03E5; pc += 1; // mov x5, x13
    gate[pc] = 0xAA1F03E6; pc += 1; // mov x6, xzr
    gate[pc] = 0xF132A41F; pc += 1; // cmp x0, #0xCA9
let relocate_skip_a2 = pc;
    gate[pc] = 0x00000000; pc += 1; // b.le label_skip_a
    gate[pc] = 0xD5087803; pc += 1; // at s1e1r, x3
    gate[pc] = 0xD538740D; pc += 1; // mrs x13, par_el1
    gate[pc] = 0x924001AC; pc += 1; // and x12, x13, #0x1
let relocate_skip_a3 = pc;
    gate[pc] = 0x00000000; pc += 1; // cbnz x12, label_skip_a
    gate[pc] = 0xD34CBDA6; pc += 1; // ubfm x6,  x13, #12, #47
    gate[pc] = 0xD374CCC6; pc += 1; // lsl  x6,  x6,  #12
    gate[pc] = 0xD3402C6C; pc += 1; // ubfm x12, x3,  #0,  #11
    gate[pc] = 0xAA0C00C6; pc += 1; // orr  x6,  x6,  x12
let label_skip_a = pc;
    gate[relocate_skip_a1] = 0x5400000D | ((label_skip_a - relocate_skip_a1) << 5) as u32;   // b.le label_skip_a
    gate[relocate_skip_a2] = 0x5400000D | ((label_skip_a - relocate_skip_a2) << 5) as u32;   // b.le label_skip_a
    gate[relocate_skip_a3] = 0xB500000C | ((label_skip_a - relocate_skip_a3) << 5) as u32;   // cbnz x12, label_skip_a
    mov_imm64(gate, &mut pc, 12, vaddr_to_paddr(unsafe { G_PT.as_ptr() as u64 }));    // mov x12, paddr of G_PT
    gate[pc] = 0xD518202C; pc += 1; // msr ttbr1_el1, x12           // switch to use Guardian's PT
    gate[pc] = 0xD5033FDF; pc += 1; // isb
    gate[pc] = 0xD53800AD; pc += 1; // mrs x13, mpidr_el1           // prepare for switching to Guardian's stack
    gate[pc] = 0x924005AD; pc += 1; // and x13, x13, #0x3           // get core id in x13, specific to Cortex A72
    mov_imm64(gate, &mut pc, 12, unsafe { STACK_GADDR });           // mov x12, STACK_GADDR
    gate[pc] = 0x8B0D3D8C; pc += 1; // add x12, x12, x13, lsl #15   // logical shift: 15 = log2(STACK_N_PAGE * PAGE_SIZE)
    gate[pc] = 0x9100019f; pc += 1; // mov sp, x12                  // switch to use Guardian's stack
    gate[pc] = 0xD5033FDF; pc += 1; // isb                          // Guardian's stack and PT are in places now
    gate[pc] = 0xA9BF2FEA; pc += 1; // stp x10, x11, [sp, #-0x10]!  // save kernel's SP and PT to Guardian's stack
    gate[pc] = 0xA9BF27FE; pc += 1; // stp x30, x9,  [sp, #-0x10]!  // save kernel's LR and DAIF to Guardian's stack
    gate[pc] = 0xF132981F; pc += 1; // cmp x0, #0xCA6
let relocate_skip_c = pc;
    gate[pc] = 0x00000000; pc += 1; // b.le label_skip_c
    mov_imm64(gate, &mut pc, 12, unsafe { CTXT_GADDR });            // mov x12, CTXT_GADDR
    gate[pc] = 0x8B0D4D8C; pc += 1; // add x12, x12, x13, lsl #19   // logical shift: 19 = log2(SLOT_N_PAGE * PAGE_SIZE)
    gate[pc] = 0xA9000580; pc += 1; // stp x0,  x1,  [x12, #0x00]   // save x0,  x1  to context slot
    gate[pc] = 0xA9010D82; pc += 1; // stp x2,  x3,  [x12, #0x10]   // save x2,  x3  to context slot
    gate[pc] = 0xA9023D84; pc += 1; // stp x4,  x15, [x12, #0x20]   // save x4,  x5  to context slot
    gate[pc] = 0xF900199E; pc += 1; // str x30,      [x12, #0x30]   // save x30      to context slot
let label_skip_c = pc;
    gate[relocate_skip_c] = 0x5400000D | ((label_skip_c - relocate_skip_c) << 5) as u32;   // b.le label_skip_c
    mov_imm64(gate, &mut pc, 30, gate_vaddr + 0xC00);               // mov x30, address of return gate
    gate[pc] = 0x910003E7; pc += 1; // mov x7, sp                   // set x7 to current Guardian's stack pointer
    mov_imm64(gate, &mut pc, 12, rsG_entry as *const () as u64);    // mov x12, address of rsG_entry
    gate[pc] = 0xD61F0180; pc += 1; // br x12                       // jump to Guardian's entry and do not return
let label_IT_common = pc;
    gate[pc] = 0xA9000580; pc += 1; // stp x0,  x1,  [x12, #0x00]   // save x0,  x1  to context slot
    gate[pc] = 0xA9010D82; pc += 1; // stp x2,  x3,  [x12, #0x10]   // save x2,  x3  to context slot
    gate[pc] = 0xA9021584; pc += 1; // stp x4,  x5,  [x12, #0x20]   // save x4,  x5  to context slot
    gate[pc] = 0xD5384100; pc += 1; // mrs x0,  sp_el0              // get user's stack pointer in x0
    gate[pc] = 0xA8C10BE1; pc += 1; // ldp x1,  x2,  [sp], #0x10    // restore x12, x13 from Guardian's stack
    gate[pc] = 0xA9030188; pc += 1; // stp x8,  x0,  [x12, #0x30]   // save x8,  sp_el0 to context slot
    gate[pc] = 0xA9041D86; pc += 1; // stp x6,  x7,  [x12, #0x40]   // save x6,  x7  to context slot
    gate[pc] = 0xA9052989; pc += 1; // stp x9,  x10, [x12, #0x50]   // save x9,  x10 to context slot
    gate[pc] = 0xA906058B; pc += 1; // stp x11, x1,  [x12, #0x60]   // save x11, x12 to context slot
    gate[pc] = 0xA9073982; pc += 1; // stp x2,  x14, [x12, #0x70]   // save x13, x14 to context slot
    gate[pc] = 0xA908418F; pc += 1; // stp x15, x16, [x12, #0x80]   // save x15, x16 to context slot
    gate[pc] = 0xA9094991; pc += 1; // stp x17, x18, [x12, #0x90]   // save x17, x18 to context slot
    gate[pc] = 0xA90A5193; pc += 1; // stp x19, x20, [x12, #0xa0]   // save x19, x20 to context slot
    gate[pc] = 0xA90B5995; pc += 1; // stp x21, x22, [x12, #0xb0]   // save x21, x22 to context slot
    gate[pc] = 0xA90C6197; pc += 1; // stp x23, x24, [x12, #0xc0]   // save x23, x24 to context slot
    gate[pc] = 0xA90D6999; pc += 1; // stp x25, x26, [x12, #0xd0]   // save x25, x26 to context slot
    gate[pc] = 0xA90E719B; pc += 1; // stp x27, x28, [x12, #0xe0]   // save x27, x28 to context slot
    gate[pc] = 0xA90F799D; pc += 1; // stp x29, x30, [x12, #0xf0]   // save x29, x30 to context slot
    gate[pc] = 0xD5384023; pc += 1; // mrs x3, elr_el1
    gate[pc] = 0xD5384004; pc += 1; // mrs x4, spsr_el1
    gate[pc] = 0xA9101183; pc += 1; // stp x3,  x4,  [x12, #0x100]  // save elr_el1, spsr_el1 to context slot
    gate[pc] = 0xAD090580; pc += 1; // stp q0,  q1,  [x12, #0x120]  // save q0,  q1  to context slot
    gate[pc] = 0xAD0A0D82; pc += 1; // stp q2,  q3,  [x12, #0x140]  // save q2,  q3  to context slot
    gate[pc] = 0xAD0B1584; pc += 1; // stp q4,  q5,  [x12, #0x160]  // save q4,  q5  to context slot
    gate[pc] = 0xAD0C1D86; pc += 1; // stp q6,  q7,  [x12, #0x180]  // save q6,  q7  to context slot
    gate[pc] = 0xAD0D2588; pc += 1; // stp q8,  q9,  [x12, #0x1a0]  // save q8,  q9  to context slot
    gate[pc] = 0xAD0E2D8A; pc += 1; // stp q10, q11, [x12, #0x1c0]  // save q10, q11 to context slot
    gate[pc] = 0xAD0F358C; pc += 1; // stp q12, q13, [x12, #0x1e0]  // save q12, q13 to context slot
//    gate[pc] = 0xAD103D8E; pc += 1; // stp q14, q15, [x12, #0x200]  // save q14, q15 to context slot
//    gate[pc] = 0xAD114590; pc += 1; // stp q16, q17, [x12, #0x220]  // save q16, q17 to context slot
//    gate[pc] = 0xAD124D92; pc += 1; // stp q18, q19, [x12, #0x240]  // save q18, q19 to context slot
//    gate[pc] = 0xAD135594; pc += 1; // stp q20, q21, [x12, #0x260]  // save q20, q21 to context slot
//    gate[pc] = 0xAD145D96; pc += 1; // stp q22, q23, [x12, #0x280]  // save q22, q23 to context slot
//    gate[pc] = 0xAD156598; pc += 1; // stp q24, q25, [x12, #0x2a0]  // save q24, q25 to context slot
//    gate[pc] = 0xAD166D9A; pc += 1; // stp q26, q27, [x12, #0x2c0]  // save q26, q27 to context slot
//    gate[pc] = 0xAD17759C; pc += 1; // stp q28, q29, [x12, #0x2e0]  // save q28, q29 to context slot
//    gate[pc] = 0xAD187D9E; pc += 1; // stp q30, q31, [x12, #0x300]  // save q30, q31 to context slot
    mov_imm64(gate, &mut pc, 30, gate_vaddr + 0xC00);               // mov x30, address of return gate
    gate[pc] = 0xD28194C0; pc += 1; // mov x0, #0xCA6               // set x0 to GCALL_INTRPT_P
    gate[pc] = 0xAA0C03E1; pc += 1; // mov x1, x12                  // set x1 to address of context slot
    gate[pc] = 0xAA0D03E6; pc += 1; // mov x6, x13                  // set x6 to entry index in [0, 16)
    gate[pc] = 0x910003E7; pc += 1; // mov x7, sp                   // set x7 to current Guardian's stack pointer
    mov_imm64(gate, &mut pc, 12, rsG_entry as *const () as u64);    // mov x12, address of rsG_entry
    gate[pc] = 0xD61F0180; pc += 1; // br x12                       // jump to Guardian's entry and do not return
    if pc > 0x300 { bf_log_str(L_ERROR, "entrance gate overflow\n\0"); }
//--------------------------------------------------------------------------------------------------------------------------------
    pc = 0x300;                     // the only gate (0x300~0x400) for returning to kernel or sensitive process
let relocate_to_ker = pc;           // x0=0x0: exit to kernel; x0=0x8: exit to kernel for syscall; default: exit to user
    gate[pc] = 0x00000000; pc += 1; // cbz x0, label_exit_to_ker    // return value in x0 decides where & how to go
    mov_imm64(gate, &mut pc, 12, unsafe { CTXT_GADDR });            // mov x12, CTXT_GADDR
    gate[pc] = 0xF100201F; pc += 1; // cmp x0, #0x8                 // x0 == 0x0/0x8: exit to kernel w/o or w/ syscall
let relocate_to_usr = pc;
    gate[pc] = 0x00000000; pc += 1; // b.ne label_exit_to_usr       // x0 != 0x0/0x8: exit to user (sensitive process)
    gate[pc] = 0xD53800AD; pc += 1; // mrs x13, mpidr_el1
    gate[pc] = 0x924005AD; pc += 1; // and x13, x13, #0x3           // get core id in x13, specific to Cortex A72
    gate[pc] = 0x8B0D4D8C; pc += 1; // add x12, x12, x13, lsl #19   // logical shift: 19 = log2(SLOT_N_PAGE * PAGE_SIZE)
    gate[pc] = 0xA9400580; pc += 1; // ldp x0,  x1,  [x12, #0x00]   // restore x0,  x1  from context slot
    gate[pc] = 0xA9410D82; pc += 1; // ldp x2,  x3,  [x12, #0x10]   // restore x2,  x3  from context slot
    gate[pc] = 0xA9421584; pc += 1; // ldp x4,  x5,  [x12, #0x20]   // restore x4,  x5  from context slot
    gate[pc] = 0xF9401988; pc += 1; // ldr x8,       [x12, #0x30]   // restore x8 / x30 from context slot
let label_exit_to_ker = pc;                                         // Lazy to do: clear sensitive context
    gate[pc] = 0xA8C127FE; pc += 1; // ldp x30, x9,  [sp], #0x10    // x30 is address of kernel's Guardian call
    gate[pc] = 0xA8C12FEA; pc += 1; // ldp x10, x11, [sp], #0x10    // x10 and x11 are kernel's stack and PT
    gate[pc] = 0x9100015F; pc += 1; // mov sp, x10                  // for interrupted process, x30 is normal IT entry
    gate[pc] = 0xD518202B; pc += 1; // msr ttbr1_el1, x11           // x9, x10 and x11 are stored in resume_process call
    gate[pc] = 0xD5033FDF; pc += 1; // isb
    gate[pc] = 0xD51B4229; pc += 1; // msr DAIF, x9
    gate[pc] = 0xD65F03C0; pc += 1; // ret
let label_exit_to_usr = pc;                                         // do not restore sp_el0
    gate[pc] = 0xD538200D; pc += 1; // mrs x13, ttbr0_el1
    gate[pc] = 0xD370FDAD; pc += 1; // lsr x13, x13, #48
    gate[pc] = 0x924039AD; pc += 1; // and x13, x13, #0x7fff        // get context id in x13
    gate[pc] = 0x8B0D258C; pc += 1; // add x12, x12, x13, lsl #9    // logical shift: 9 = log2(CONTEXT_N_REG * 8)
    gate[pc] = 0xA9400580; pc += 1; // ldp x0,  x1,  [x12, #0x00]   // restore x0,  x1  from context slot
    gate[pc] = 0xA9410D82; pc += 1; // ldp x2,  x3,  [x12, #0x10]   // restore x2,  x3  from context slot
    gate[pc] = 0xA9421584; pc += 1; // ldp x4,  x5,  [x12, #0x20]   // restore x4,  x5  from context slot
    gate[pc] = 0xF9401988; pc += 1; // ldr x8,       [x12, #0x30]   // restore x8       from context slot
    gate[pc] = 0xA9441D86; pc += 1; // ldp x6,  x7,  [x12, #0x40]   // restore x6,  x7  from context slot
    gate[pc] = 0xA9452989; pc += 1; // ldp x9,  x10, [x12, #0x50]   // restore x9,  x10 from context slot
    gate[pc] = 0xA948418F; pc += 1; // ldp x15, x16, [x12, #0x80]   // restore X15, x16 from context slot
    gate[pc] = 0xA9494991; pc += 1; // ldp x17, x18, [x12, #0x90]   // restore x17, x18 from context slot
    gate[pc] = 0xA94A5193; pc += 1; // ldp x19, x20, [x12, #0xa0]   // restore x19, x20 from context slot
    gate[pc] = 0xA94B5995; pc += 1; // ldp x21, x22, [x12, #0xb0]   // restore x21, x22 from context slot
    gate[pc] = 0xA94C6197; pc += 1; // ldp x23, x24, [x12, #0xc0]   // restore x23, x24 from context slot
    gate[pc] = 0xA94D6999; pc += 1; // ldp x25, x26, [x12, #0xd0]   // restore x25, x26 from context slot
    gate[pc] = 0xA94E719B; pc += 1; // ldp x27, x28, [x12, #0xe0]   // restore x27, x28 from context slot
    gate[pc] = 0xA94F799D; pc += 1; // ldp x29, x30, [x12, #0xf0]   // restore x29, x30 from context slot
    gate[pc] = 0xA950398D; pc += 1; // ldp x13, x14, [x12, #0x100]  // restore elr_el1, spsr_el1 from context slot
    gate[pc] = 0xD518402D; pc += 1; // msr elr_el1, x13             // restore elr_el1
    gate[pc] = 0xD518400E; pc += 1; // msr spsr_el1, x14            // restore spsr_el1
    gate[pc] = 0xA947398D; pc += 1; // ldp x13, x14, [x12, #0x70]   // restore x13, x14 from context slot
    gate[pc] = 0xAD490580; pc += 1; // ldp q0,  q1,  [x12, #0x120]  // restore q0,  q1  from context slot
    gate[pc] = 0xAD4A0D82; pc += 1; // ldp q2,  q3,  [x12, #0x140]  // restore q2,  q3  from context slot
    gate[pc] = 0xAD4B1584; pc += 1; // ldp q4,  q5,  [x12, #0x160]  // restore q4,  q5  from context slot
    gate[pc] = 0xAD4C1D86; pc += 1; // ldp q6,  q7,  [x12, #0x180]  // restore q6,  q7  from context slot
    gate[pc] = 0xAD4D2588; pc += 1; // ldp q8,  q9,  [x12, #0x1a0]  // restore q8,  q9  from context slot
    gate[pc] = 0xAD4E2D8A; pc += 1; // ldp q10, q11, [x12, #0x1c0]  // restore q10, q11 from context slot
    gate[pc] = 0xAD4F358C; pc += 1; // ldp q12, q13, [x12, #0x1e0]  // restore q12, q13 from context slot
//    gate[pc] = 0xAD503D8E; pc += 1; // ldp q14, q15, [x12, #0x200]  // restore q14, q15 from context slot
//    gate[pc] = 0xAD514590; pc += 1; // ldp q16, q17, [x12, #0x220]  // restore q16, q17 from context slot
//    gate[pc] = 0xAD524D92; pc += 1; // ldp q18, q19, [x12, #0x240]  // restore q18, q19 from context slot
//    gate[pc] = 0xAD535594; pc += 1; // ldp q20, q21, [x12, #0x260]  // restore q20, q21 from context slot
//    gate[pc] = 0xAD545D96; pc += 1; // ldp q22, q23, [x12, #0x280]  // restore q22, q23 from context slot
//    gate[pc] = 0xAD556598; pc += 1; // ldp q24, q25, [x12, #0x2a0]  // restore q24, q25 from context slot
//    gate[pc] = 0xAD566D9A; pc += 1; // ldp q26, q27, [x12, #0x2c0]  // restore q26, q27 from context slot
//    gate[pc] = 0xAD57759C; pc += 1; // ldp q28, q29, [x12, #0x2e0]  // restore q28, q29 from context slot
//    gate[pc] = 0xAD587D9E; pc += 1; // ldp q30, q31, [x12, #0x300]  // restore q30, q31 from context slot
    gate[pc] = 0xA946318B; pc += 1; // ldp x11, x12, [x12, #0x60]   // restore x11, x12 from context slot
    gate[pc] = 0xD69F03E0; pc += 1; // eret                         // return to user
    if pc > 0x400 { bf_log_str(L_ERROR, "exit gate overflow\n\0"); }
    gate[relocate_to_ker] = 0xB4000000 | ((label_exit_to_ker - relocate_to_ker) << 5) as u32;   // cbz   x0, label_exit_to_ker
    gate[relocate_to_usr] = 0x54000001 | ((label_exit_to_usr - relocate_to_usr) << 5) as u32;   // b.ne      label_exit_to_usr
//--------------------------------------------------------------------------------------------------------------------------------
    const IT_N_ENTRY: usize = 16;
    for idx in 0..IT_N_ENTRY {
        let mut pc = idx * 0x20;
        if idx > 0 { for i in 0..IT_ENTRY_N_STATIC_INST { gate[pc + i] = gate[i]; } }
        pc += IT_ENTRY_N_STATIC_INST;
        gate[pc + 0] = 0xD2800000 | (idx << 5) as u32 | 13;                 // movz x13, #idx
        gate[pc + 1] = 0x14000000 | (label_IT_common - (pc + 1)) as u32;    // b label_IT_common
    }
}
pub fn switch_g_ptbr() {
    let old_ttbr1_el1;
    unsafe { asm!("mrs {0}, ttbr1_el1", out(reg) old_ttbr1_el1); }
    bf_log_strHex(L_DEBUG, "old ttbr_el1 = 0x\0", old_ttbr1_el1);
    let new_ttbr1_el1 = entry_wr_baddr(old_ttbr1_el1, unsafe { G_PT.as_ptr() } as u64);
    bf_log_strHex(L_DEBUG, "new ttbr_el1 = 0x\0", new_ttbr1_el1);
    unsafe { asm!("msr ttbr1_el1, {0}\n isb\n", in(reg) new_ttbr1_el1); }
    unsafe { asm!("dsb ishst\n tlbi vmalle1\n dsb ish\n isb\n"); }
}