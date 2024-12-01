use crate::*;

pub const BP_LR:    usize = 0;
pub const BP_IF:    usize = 1;
pub const BP_SP:    usize = 2;
pub const BP_PT:    usize = 3;
#[inline(always)]pub fn set_base_idx(base: u64, idx: usize, data: u64) {
    unsafe { *(base as *mut u64).offset(idx as isize) = data }
}
#[inline(always)]pub fn get_base_idx(base: u64, idx: usize) -> u64 {
    unsafe { *(base as *const u64).offset(idx as isize) }
}
#[inline(always)]pub fn get_base_idx_u32(base: u64, idx: usize) -> u32 {
    unsafe { *(base as *const u32).offset(idx as isize) }
}

pub const CT_A0:            usize = 0;      // x0
pub const CT_A1:            usize = 1;      // x1
pub const CT_A2:            usize = 2;      // x2
pub const CT_A3:            usize = 3;      // x3
pub const CT_A4:            usize = 4;      // x4
pub const CT_SYSCALL:       usize = 6;      // x8
pub const SYSCALL_N_REG:    usize = 7;      // x0-5, x8
pub const CT_SP:            usize = 7;
pub const CT_ELR:           usize = 32;
pub const CT_SPSR:          usize = 33;
pub const CT_CMD:           usize = 34;
pub const CT_CAP:           usize = 35;
pub const CT_TMP:           usize = 35;
pub const GENERAL_N_REG:    usize = 36;
pub const ARMNEON_N_REG:    usize = 28;
pub const CONTEXT_N_REG:    usize = GENERAL_N_REG + ARMNEON_N_REG;
pub type Context = [u64; CONTEXT_N_REG];
pub static mut SLOTS: [u64; HW_N_CORE] = [0x0; HW_N_CORE];
#[inline(always)]pub fn get_cpu_ctxt() -> *mut Context {
    unsafe { (CTXT_GADDR + SLOT_N_PAGE * PAGE_SIZE * get_cpuid() as u64) as *mut Context }
}
#[inline(always)]pub fn get_ctxt_from_cid(cid: u64) -> *mut Context {
    unsafe { (CTXT_GADDR + CONTEXT_N_REG as u64 * 8 * cid) as *mut Context }
}
#[inline(always)]pub fn alloc_ctxt() -> *mut Context {
    let cpuid = get_cpuid();
    unsafe {
        if SLOTS[cpuid] == 0x0 { log_str(L_ERROR, "alloc_ctxt: run out of slots\n\0"); loop { } }
        else { let ctxt = SLOTS[cpuid] as *mut Context; SLOTS[cpuid] = (*ctxt)[0]; ctxt }
    }
}
#[inline(always)]pub fn dealloc_ctxt(ctxt: &mut *mut Context) {
    if *ctxt as u64 == 0x0 { return; }
    let cpuid = get_cpuid();
    unsafe {
        (**ctxt)[0] = SLOTS[cpuid];
        SLOTS[cpuid] = *ctxt as u64;
    }
    *ctxt = 0x0 as *mut Context;
}
#[inline(always)]pub fn get_ctxt_idx(ctxt: *const Context, idx: usize) -> u64 {
    unsafe { (*ctxt)[idx] }
}
#[inline(always)]pub fn set_ctxt_idx(ctxt: *mut Context, idx: usize, data: u64) {
    unsafe { (*ctxt)[idx] = data }
}
#[inline(always)]pub fn read_ctxt(ctxt: *mut Context, ctxt_addr: u64, cmd: u64) {
    if ctxt as u64 == 0 || ctxt_addr == 0 { log_str(L_ERROR, "read_ctxt: error\n\0"); }
    memset(ctxt as u64 + GENERAL_N_REG as u64 * 8, ARMNEON_N_REG as u64 * 8);
    memcpy(ctxt as u64 + 0  * 8, ctxt_addr + 0  * 8, 6  * 8);  // x0-5
    memcpy(ctxt as u64 + 6  * 8, ctxt_addr + 8  * 8, 1  * 8);  // x8
    memcpy(ctxt as u64 + 7  * 8, ctxt_addr + 31 * 8, 1  * 8);  // sp
    memcpy(ctxt as u64 + 8  * 8, ctxt_addr + 6  * 8, 2  * 8);  // x6-7
    memcpy(ctxt as u64 + 10 * 8, ctxt_addr + 9  * 8, 22 * 8);  // x9-30
    memcpy(ctxt as u64 + 32 * 8, ctxt_addr + 32 * 8, 2  * 8);  // elr, spsr
    set_ctxt_idx(ctxt, CT_CMD, cmd);
    set_ctxt_idx(ctxt, CT_CAP, 0x0);
}
#[inline(always)]pub fn copy_ctxt(dst: *mut Context, src: *const Context, n_reg: usize) {
    memcpy(dst as u64, src as u64, n_reg as u64 * 8);
}

pub const EXP_EMULATE:          u64 = 0x0;
pub const EXP_ASYNC:            u64 = 0x1;
pub const EXP_SYNC:             u64 = 0x2;
pub const EXP_FAULT:            u64 = 0x3;
pub const EXP_SIGNAL:           u64 = 0x4;
pub const EXP_SYSCALL:          u64 = 0x5;
pub const EXP_SYSERROR:         u64 = 0x6;
pub const EXP_SYSSIGACT:        u64 = 0x7;
pub const EXP_SYSSIGRET:        u64 = 0x8;
pub const EXP_SYSEXIT:          u64 = 0x9;
pub const EXP_SYSEXEC:          u64 = 0xA;
pub const EXP_SYSFORK:          u64 = 0xB;
pub const EXP_SYSVFORK:         u64 = 0xC;
pub const EXP_SYSCLONE:         u64 = 0xD;
pub const EXP_SYSBRK:           u64 = 0xE;
pub const EXP_SYSMMAP:          u64 = 0xF;
pub const EXP_SYSMUNMAP:        u64 = 0x10;
pub const EXP_SYSMPROT:         u64 = 0x11;
pub const EXP_SYSTID:           u64 = 0x12;
pub const EXP_SYSRSEQ:          u64 = 0x13;
pub const EXP_SYSROBUST:        u64 = 0x14;
pub const CLONE_VM:             u64 = 0x100;
pub const CLONE_VFORK:          u64 = 0x4000;
pub const CLONE_SIGHAND:        u64 = 0x800;
pub const CLONE_CLEAR_SIGHAND:  u64 = 0x100000000;
#[inline(always)]pub fn exp_is_syscall(cmd: u64) -> bool { EXP_SYSCALL  <= cmd }
#[inline(always)]pub fn exp_have_lcap (cmd: u64) -> bool { EXP_SYSTID   <= cmd }
#[inline(always)]pub fn exp_interrupt (cmd: u64) -> bool { EXP_SYSCLONE <= cmd && cmd <= EXP_SYSMUNMAP || EXP_SYSSIGACT <= cmd && cmd <= EXP_SYSEXIT }
#[inline(always)]pub fn exp_resume    (cmd: u64) -> bool { EXP_SYSBRK   <= cmd || cmd == EXP_SYSVFORK }

pub const CAP_TID:              usize = 0x0;
pub const CAP_RSEQ:             usize = 0x1;
pub const CAP_ROBUST:           usize = 0x2;
pub static mut ECAPS: [u64; HW_N_CORE] = [0x0; HW_N_CORE];
pub fn add_ecap(ctxt: *mut Context, node: &(u64, u64, u64, u64)) {
    let cpuid = get_cpuid();
    let ecap = unsafe {
        if ECAPS[cpuid] == 0x0 { log_str(L_ERROR, "add_ecap: run out of slots\n\0"); loop { } }
        let tmp = ECAPS[cpuid]; ECAPS[cpuid] = get_base_idx(tmp, 3); &mut *(tmp as *mut (u64, u64, u64, u64))
    };
    *ecap = *node; ecap.3 = get_ctxt_idx(ctxt, CT_CAP);
    set_ctxt_idx(ctxt, CT_CAP, ecap as *const (u64, u64, u64, u64) as u64);
}
pub fn recycle_ecap(ptr: u64) {
    if ptr == 0x0 { return; }
    let (mut last, cpuid) = (ptr, get_cpuid());
    let mut next = get_base_idx(last, 3);
    while next != 0x0 { last = next; next = get_base_idx(last, 3); }
    unsafe { set_base_idx(last, 3, ECAPS[cpuid]); ECAPS[cpuid] = ptr; }
}

pub const VM_READ:              u64 = 0x1;
pub const VM_WRITE:             u64 = 0x2;
pub const VM_EXEC:              u64 = 0x4;
pub const VM_RWX:               u64 = VM_READ | VM_WRITE | VM_EXEC;
pub const VM_SHARED:            u64 = 0x8;
pub const VM_STACK:             u64 = 0x100;
pub const VM_HEAP:              u64 = 0x1 << 63;
pub const TEXT_VMA_IDX:         usize = 0;
#[inline(always)]pub fn is_shared(flags: u64) -> bool { flags & VM_SHARED == VM_SHARED }