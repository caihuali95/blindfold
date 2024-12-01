use crate::*;
use core::slice::from_raw_parts_mut;

pub const PAGE_SIZE     : u64 = 0x1000;
pub const PTE_PER_PAGE  : u64 = PAGE_SIZE / 8;
pub const SLOT_N_PAGE   : u64 = 128; // SLOT_N_PAGE * PAGE_SIZE * HW_N_CORE / (CONTEXT_N_REG * 8) <= 2^15
pub const STACK_N_PAGE  : u64 = 8;
pub const ECAPS_N_PAGE  : u64 = 8;
pub const BUFFER_N_PAGE : u64 = 512;
pub const HASH_SIZE     : u64 = 0x20;
pub const BLOCK_SIZE    : usize = 0x10;
pub const KEY_SIZE      : usize = 0x10;
pub const VPN_SHIFT     : usize = 9;
pub const MOD_DATA      : usize = 1;
pub const MOD_INIT      : usize = 4;
pub const MOD_VMA_NUM   : usize = 8;
pub const HASHMAC_KEY   : [u8; KEY_SIZE] = [0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
                                            0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
pub fn assign_mac_key() -> [u8; KEY_SIZE] { HASHMAC_KEY.clone() }   // use constant keys in assignment for simplicity
pub fn assign_enc_key() -> [u8; KEY_SIZE] { let mut key = HASHMAC_KEY.clone(); key.reverse(); key }

pub static mut ZERO_PADDR: u64 = 0;
pub static mut N_IT_VADDR: u64 = 0;
pub static mut S_IT_VADDR: u64 = 0;
pub static mut K_PT_PADDR: u64 = 0;
pub static mut K_PT: &'static mut [u64] = &mut [];
pub static mut G_PT: &'static mut [u64] = &mut [];
pub static mut STATUS: [*mut i16; HW_N_GB] = [0x0 as *mut i16; HW_N_GB];
pub static mut PTINFO: [*mut u64; HW_N_GB] = [0x0 as *mut u64; HW_N_GB];
pub static mut BUFFER: [*mut u64; HW_N_CORE] = [0x0 as *mut u64; HW_N_CORE];
pub static mut STACK_GADDR: u64 = 0;
pub static mut CTXT_GADDR: u64 = 0;

#[inline(always)]pub fn paddr_to_vaddr(paddr: u64) -> u64 { paddr + K_PAGE_OFFSET }
#[inline(always)]pub fn vaddr_to_paddr(vaddr: u64) -> u64 { vaddr - K_PAGE_OFFSET }
#[inline(always)]pub fn paddr_to_gaddr(paddr: u64) -> u64 { paddr + G_PAGE_OFFSET }
#[inline(always)]pub fn gaddr_to_paddr(gaddr: u64) -> u64 { gaddr - G_PAGE_OFFSET }
#[inline(always)]pub fn vaddr_to_gaddr(vaddr: u64) -> u64 { vaddr - K_PAGE_OFFSET + G_PAGE_OFFSET }
#[inline(always)]pub fn gaddr_to_vaddr(gaddr: u64) -> u64 { gaddr - G_PAGE_OFFSET + K_PAGE_OFFSET }
#[inline(always)]pub fn addr_to_slice<T>(addr: u64, n: u64) -> &'static mut [T] {
    unsafe { from_raw_parts_mut(addr as *mut T, n as usize) }
}
#[inline(always)]pub fn entry_to_paddr(entry: u64) -> u64 { entry & OA_MASK }
#[inline(always)]pub fn entry_wr_baddr(entry: u64, baddr: u64) -> u64 { (entry & !OA_MASK) | (baddr & OA_MASK) }
#[inline(always)]pub fn entry_to_gtable(entry: u64) -> &'static mut [u64] {
    addr_to_slice::<u64>(paddr_to_gaddr(entry_to_paddr(entry)), PTE_PER_PAGE)
}
#[inline(always)]pub fn entry_to_vtable(entry: u64) -> &'static mut [u64] {
    addr_to_slice::<u64>(paddr_to_vaddr(entry_to_paddr(entry)), PTE_PER_PAGE)
}
#[inline(always)]pub fn paddr_to_pfn(paddr: u64) -> usize {
    if paddr >= SIZE_DRAM { bf_log_strHex(L_ERROR, "paddr_to_pfn: error, paddr = 0x\0", paddr); }
    (paddr / PAGE_SIZE) as usize
}
#[inline(always)]pub fn vaddr_to_pfn(vaddr: u64) -> usize { paddr_to_pfn(vaddr_to_paddr(vaddr)) }
#[inline(always)]pub fn entry_to_pfn(entry: u64) -> (u64, usize) {
    let paddr = entry_to_paddr(entry);
    (paddr, paddr_to_pfn(paddr))
}
#[inline(always)]pub fn entry_to_flag(entry: u64) -> (u64, usize, u64) {
    let paddr = entry_to_paddr(entry);
    let pfn = paddr_to_pfn(paddr);
    (paddr, pfn, get_frame_flag(pfn))
}

pub const FLG:     isize = 0;
pub const USR:     isize = 1;
pub const KER:     isize = 2;
pub const PTP:     isize = 3;

pub const OP_INVA:    usize = 0;
pub const OP_VALI:    usize = 1;
pub const OP_ROLY:    usize = 2;
pub const OP_RDWR:    usize = 3;

pub const DEPTH_PGD: u64 = 0;
pub const DEPTH_PUD: u64 = 1;
pub const DEPTH_PMD: u64 = 2;
pub const DEPTH_PGT: u64 = 3;

pub const NORMAL: u64 = 0x000;
pub const SECURE: u64 = 0x010;
pub const RDONLY: u64 = 0x020;
pub const ITPAGE: u64 = 0x040;
pub const PTPAGE: u64 = 0x080;
pub const KERNEL: u64 = 0x008;
pub const USERPT: u64 = 0x000;
pub const SPECPT: u64 = 0x004;      // paired kernel PTP or sensitive user PTP
pub const SENSIT: u64 = 0x100;      // sensitive user code / data page

#[inline(always)]pub fn is_normal(flag: u64) -> bool { flag == NORMAL }
#[inline(always)]pub fn is_ptpage(flag: u64) -> bool { flag & PTPAGE == PTPAGE }
#[inline(always)]pub fn is_privilege(flag: u64) -> bool { flag & 0x00df != NORMAL }
#[inline(always)]pub fn is_sensi_page(flag: u64) -> bool { flag & SENSIT == SENSIT }
#[inline(always)]pub fn is_sensi_proc(flag: u64) -> bool { flag & 0xfffc == RDONLY | PTPAGE | USERPT | SPECPT }
#[inline(always)]pub fn is_ptp_flag(flag: u64, kernel: u64, depth: u64) -> bool { flag & 0xfffb == RDONLY | PTPAGE | kernel | depth }
#[inline(always)]pub fn get_flag_depth(flag: u64) -> u64 { flag & 0x0003 }
#[inline(always)]pub fn get_flag_kernel(flag: u64) -> u64 { flag & KERNEL }
#[inline(always)]pub fn kernel_to_ukp(kernel: u64) -> isize { if kernel == KERNEL { KER } else { USR } }
#[inline(always)]pub fn set_2mb_frame_secure(pfn: usize) {
    let (idx, off_base) = (pfn >> 18, ((pfn & 0x3_ffff) << 2) as isize);
    for i in 0..PTE_PER_PAGE as isize {
        unsafe { *STATUS[idx].offset(off_base + i * 4) = SECURE as i16; }
    }
}
#[inline(always)]pub fn set_4kb_frame_flag(pfn: usize, flag: u64) {
    unsafe { *STATUS[pfn >> 18].offset(((pfn & 0x3_ffff) << 2) as isize) = flag as i16;}
}
#[inline(always)]pub fn get_frame_flag(pfn: usize) -> u64 {
    unsafe { *STATUS[pfn >> 18].offset(((pfn & 0x3_ffff) << 2) as isize) as u64 }
}
#[inline(always)]pub fn get_frame_cnt(pfn: usize, ukp: isize) -> i16 {
    unsafe { *STATUS[pfn >> 18].offset(((pfn & 0x3_ffff) << 2) as isize | ukp) }
}
#[inline(always)]pub fn inc_frame_cnt(pfn: usize, ukp: isize, is_inc: bool) -> i16 {
    unsafe {
        let ptr = STATUS[pfn >> 18].offset(((pfn & 0x3_ffff) << 2) as isize | ukp);
        let cnt = if is_inc { atomic_inc_i16(ptr) } else { atomic_dec_i16(ptr) };
        if cnt < 0 || ukp == PTP && cnt > 1 { log_strHex(L_ERROR, "inc_frame_cnt: error, cnt = 0x\0", cnt as u64); }
        cnt
    }
}
#[inline(always)]pub fn set_ptp_vpn_pid(pfn: usize, vpn: usize, pid: u64) {
    unsafe { *PTINFO[pfn >> 18].offset((pfn & 0x3_ffff) as isize) = (paddr_to_pfn(pid) << 28 | vpn) as u64; }   // 28 = 9 * 3 + 1
}
#[inline(always)]pub fn get_ptp_vpn_pid(pfn: usize) -> (u64, u64) {
    let info = unsafe { *PTINFO[pfn >> 18].offset((pfn & 0x3_ffff) as isize) };
    (info & 0x7ff_ffff, (info >> 28) * PAGE_SIZE)
}
#[inline(always)]pub fn set_sensi_user_ptp(pfn: usize, flag: u64, depth: u64) {
    if !is_ptp_flag(flag, USERPT, depth) { log_strHex(L_ERROR, "set_sensi_user_ptp: error, flag = 0x\0", flag); }
    set_4kb_frame_flag(pfn, flag | SPECPT);
}
#[inline(always)]pub fn set_sensi_user_page(paddr: u64, pfn: usize, flag: u64, _vaddr: u64) {
    if paddr == unsafe { ZERO_PADDR } { return; }
    set_4kb_frame_flag(pfn, flag | SENSIT);
    let _pte_gaddr = get_kat_gaddr(paddr_to_vaddr(paddr), true);
//    set_pte_op(unsafe { &mut *(pte_gaddr as *mut u64) }, OP_INVA, vaddr);
}
#[inline(always)]pub fn unset_sensi_user_page(paddr: u64, pfn: usize, flag: u64, vaddr: u64) {
    set_4kb_frame_flag(pfn, flag & !SENSIT);
    let pte_gaddr = get_kat_gaddr(paddr_to_vaddr(paddr), true);
    set_pte_op(unsafe { &mut *(pte_gaddr as *mut u64) }, OP_VALI, vaddr);
}

// debug --------------------------------------------------------------------------------------------------------------------------------
pub const L_LEVEL	: u64 = L_ERROR;
pub const L_ERROR	: u64 = 10;
pub const L_DEBUG	: u64 = 9;
pub const L_CFLOW	: u64 = 8;
pub const L_LOG	    : u64 = 0;

extern {
    fn printHex(x: u64);
    fn printlnHex(x: u64);
    fn printStr(s: *const u8);
    fn printlnStrHex(s: *const u8, x: u64);
    fn bf_printHex(x: u64);
    fn bf_printlnHex(x: u64);
    fn bf_printStr(s: *const u8);
    fn bf_printlnStrHex(s: *const u8, x: u64);
}

static G_LOCK: RwLock<()> = RwLock::new(());
pub fn log_hex(l: u64, x: u64)                { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { printHex(x); } } }
pub fn log_Hex(l: u64, x: u64)                { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { printlnHex(x); } } }
pub fn log_str(l: u64, s: &str)               { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { printStr(s.as_ptr()); } } }
pub fn log_strHex(l: u64, s: &str, x: u64)    { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { printlnStrHex(s.as_ptr(), x); } } }
pub fn bf_log_hex(l: u64, x: u64)             { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { bf_printHex(x); } } }
pub fn bf_log_Hex(l: u64, x: u64)             { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { bf_printlnHex(x); } } }
pub fn bf_log_str(l: u64, s: &str)            { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { bf_printStr(s.as_ptr()); } } }
pub fn bf_log_strHex(l: u64, s: &str, x: u64) { if l >= L_LEVEL { let _l = G_LOCK.write(); unsafe { bf_printlnStrHex(s.as_ptr(), x); } } }

pub fn print_tables(level: u64, entry: u64, depth: u64, vpn: u64) {
	match depth {
		DEPTH_PGD => { },
		DEPTH_PUD => log_str(level, "  \0"),
		DEPTH_PMD => log_str(level, "    \0"),
		DEPTH_PGT => log_str(level, "      \0"),
		_		  => log_str(level, "        \0"),
	}
	log_hex(level, vpn);
	log_hex(level, entry);
	log_Hex(level, get_frame_flag(paddr_to_pfn(entry_to_paddr(entry))));
	if depth > DEPTH_PGT || is_block_entry(entry) && depth != DEPTH_TOP { return; }
	let (table, n_vpn) = (entry_to_gtable(entry), vpn * PTE_PER_PAGE);
	for idx in 0..PTE_PER_PAGE as usize {
        if is_valid_entry(table[idx]) { print_tables(level, table[idx], depth + 1, n_vpn + idx as u64); }
    }
}
pub fn print_ctxt(level: u64, ctxt: *const Context) {
    log_strHex(level, "print ctxt = 0x\0", ctxt as u64);
    for i in 0..CONTEXT_N_REG as usize {
        if i & 0x7 == 0x7 { log_Hex(level, get_ctxt_idx(ctxt, i)); }
        else { log_hex(level, get_ctxt_idx(ctxt, i)); }
    }
    log_str(level, "\n\0");
}
pub fn print_areas(level: u64, areas: &Vec<(u64, u64, u64)>) {
    for area in areas {
        log_strHex(level, "vm_start = 0x\0", area.0);
        log_strHex(level, "vm_end   = 0x\0", area.1);
        log_strHex(level, "vm_flags = 0x\0", area.2);
    }
}
pub fn print_code(addr: u64) {
    let page = addr_to_slice::<u8>(addr, PAGE_SIZE);
    for i in 0..PAGE_SIZE as usize {
        if i & 0x3 == 0x3 { log_Hex(L_DEBUG, page[i] as u64); }
        else { log_hex(L_DEBUG, page[i] as u64); }
    }
}
pub fn print_page(addr: u64) {
    let page = addr_to_slice::<u64>(addr, PTE_PER_PAGE);
    for i in 0..PTE_PER_PAGE as usize {
        if i & 0x7 == 0x7 { log_Hex(L_DEBUG, page[i] as u64); }
        else { log_hex(L_DEBUG, page[i] as u64); }
    }
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    bf_log_str(L_ERROR, "panic!\n\0");
    if let Some(location) = info.location() { bf_log_strHex(L_ERROR, location.file(), location.line() as u64); }
    loop { }
}