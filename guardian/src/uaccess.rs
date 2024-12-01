use crate::*;

const RDWR:             bool  = true;
const ROLY:             bool  = false;
const EFAULT:           i32   = 14;
const SIGFRAME_SIZE:    u64   = 0x1260;
const MAX_SIGFRAME:     u64   = 0x3;
const MAX_ARG_NUM:      u64   = 0x80000000;

#[inline(always)]fn scap_to_ecap(scap: &(u64, u64, u64, u8, bool)) -> (u64, u64, u64, u64) {
    (scap.0, scap.1, (scap.2 << 5) | ((scap.3 as u64) << 1) | (scap.4 as u64), 0x0)
}
#[inline(always)]fn ecap_to_scap(ecap: &(u64, u64, u64, u64)) -> (u64, u64, u64, u8, bool) {
    (ecap.0, ecap.1, ecap.2 >> 5, ((ecap.2 >> 1) & 0xf) as u8, (ecap.2 & 0x1) != 0x0)
}
#[inline(always)]fn do_extend(ctxt: *mut Context, vaddr: u64, scap: &(u64, u64, u64, u8, bool)) {
    match scap.3 {
        TY_SOCKOPT => { add_ecap(ctxt, &scap_to_ecap(&(scap.2 - 0x4,             get_base_idx_u32(vaddr, 0x0) as u64, 0x1, TY_SIZEOBJ, RDWR))); },
        TY_FHANDLE => { add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x1), get_base_idx_u32(vaddr, 0x0) as u64, 0x1, TY_SIZEOBJ, RDWR))); },
        TY_IOVLIST => { add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x0), get_base_idx(vaddr, 0x1),            0x1, TY_SIZEOBJ, RDWR))); },
        TY_MSGLIST => { add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x0), get_base_idx_u32(vaddr, 0x2) as u64, 0x1, TY_SIZEOBJ, RDWR)));
                        add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x4), get_base_idx_u32(vaddr, 0xa) as u64, 0x1, TY_SIZEOBJ, RDWR)));
                        add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x2), get_base_idx_u32(vaddr, 0x6) as u64 * 0x10, 0x10, TY_IOVLIST, RDWR)));},
        TY_STRLIST => { add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x0), 0x1,                                 0x1, TY_CSTRING, ROLY))); },
        TY_FTXLIST => { add_ecap(ctxt, &scap_to_ecap(&(get_base_idx(vaddr, 0x1), 0x4,                                 0x4, TY_SIZEOBJ, RDWR))); },
        _ => { },
    }
}
#[inline(always)]fn extend_short_cap(n_byte: u64, uvaddr: u64, ctxt: *mut Context, bp: u64, scap: &(u64, u64, u64, u8, bool), stored_ptr: u64) -> Option<u64> {
    if stored_ptr == 0x0 {
        let mut ptr = get_ctxt_idx(ctxt, CT_CAP);
        while ptr != 0x0 {
            let ecap = unsafe { &*(ptr as *const (u64, u64, u64, u64)) };   // found target capability and it is already extended
            if ecap.0 <= uvaddr && uvaddr < ecap.0 + ecap.1 && !ext_cap(((ecap.2 >> 1) & 0xf) as u8) {
                let m_byte = ecap.0 + ecap.1 - uvaddr;
                return Some(if m_byte < n_byte { m_byte } else { n_byte });
            }
            ptr = ecap.3;
        }
    }
    let (mut m_byte, is_null_ended) = if scap.3 == TY_STRLIST { (MAX_ARG_NUM * 0x8, true) } else { (scap.1, false) };
    if let Some(size) = check_present_pages(m_byte, scap.0, 0x8, scap.4, is_null_ended, bp) { m_byte = size; } else { return None; }
    if is_null_ended { m_byte += 0x8; }
    if stored_ptr != 0x0 {  // extend a capability that is already in the list so mark it as extended (depth > 1)
        let ecap = unsafe { &mut *(stored_ptr as *mut (u64, u64, u64, u64)) };
        ecap.2 = ((ecap.2 >> 5) << 5) | ((TY_SIZEOBJ as u64) << 1) | (ecap.2 & 0x1);
    } else {    // extend a capability that is not in the list so add it to the list
        add_ecap(ctxt, &scap_to_ecap(&(scap.0, m_byte, m_byte, TY_SIZEOBJ, scap.4)));
    }
    for vaddr in (scap.0..(scap.0 + m_byte)).step_by(scap.2 as usize) { do_extend(ctxt, vaddr, scap); }
    m_byte = scap.0 + m_byte - uvaddr;
    Some(if m_byte < n_byte { m_byte } else { n_byte })
}
#[inline(always)]fn extend_cstr_cap(n_byte: u64, uvaddr: u64, ctxt: *mut Context) {
    let temp = scap_to_ecap(&(uvaddr, n_byte + 0x1, n_byte + 0x1, TY_SIZEOBJ, ROLY));   // n_byte + 0x1 includes the null byte
    let mut ptr = get_ctxt_idx(ctxt, CT_CAP);
    while ptr != 0x0 {
        let ecap = unsafe { &*(ptr as *const (u64, u64, u64, u64)) };
        if ecap.0 == temp.0 && ecap.1 == temp.1 && ecap.2 == temp.2 { return; }         // avoid redundant extensible capability
        ptr = ecap.3;
    }
    add_ecap(ctxt, &temp);
}
#[inline(always)]fn examine_syscall_cap(n_byte: u64, uvaddr: u64, ctxt: *mut Context, is_write: bool, is_str: bool, bp: u64, scap: &(u64, u64, u64, u8, bool), m_byte: &mut u64, ptr: u64) -> (bool, Option<u64>) {
    if scap.0 == uvaddr && scap.3 == TY_CSTRING && is_str {
        extend_cstr_cap(n_byte, uvaddr, ctxt);
        return (true, Some(n_byte));
    }
    if (scap.4 || !is_write) && scap.0 <= uvaddr && uvaddr + *m_byte < scap.0 + scap.1 {
        if ext_cap(scap.3) { return (true, extend_short_cap(n_byte, uvaddr, ctxt, bp, scap, ptr)); }
        *m_byte = scap.0 + scap.1 - uvaddr;
        if *m_byte >= n_byte { return (true, Some(n_byte)); }
    }
    (false, None)
}
#[inline(always)]fn check_capability_ctxt(ctxt: *mut Context, tid: u64) -> bool {
    if ctxt as u64 == 0x0 { return false; }
    let sp = get_ctxt_idx(ctxt, CT_SP);
    sp == tid || sp > tid && (sp - tid) <= MAX_SIGFRAME * SIGFRAME_SIZE && (sp - tid) % SIGFRAME_SIZE == 0
}
#[inline(always)]fn get_capability_ctxt(tid: u64) -> (*mut Context, Option<Arc<RwLock<Task>>>) {
    let cid = get_cid();
    if cid != 0x0 {
        let ctxt = get_ctxt_from_cid(cid);
        if check_capability_ctxt(ctxt, tid) { return (ctxt, None); }
    }
    let task_arc = get_task_arc(get_pid(), tid);
    let task = task_arc.read();
    let ctxt = if check_capability_ctxt(task.ctxt, tid) { task.ctxt }
          else if check_capability_ctxt(task.vctx, tid) { task.vctx }
          else { log_str(L_ERROR, "get_capability_ctxt: error\n\0"); loop { } };
    drop(task);
    (ctxt, Some(task_arc))
}
fn check_capability(n_byte: u64, uvaddr: u64, tid: u64, is_write: bool, is_str: bool, bp: u64) -> Option<u64> {
    let (ctxt, task_arc_opt) = get_capability_ctxt(tid);
    if tid - SIGFRAME_SIZE <= uvaddr && uvaddr + n_byte <= tid { return Some(n_byte); }
    let (sp, mut m_byte, mut check_ext_caps) = (get_ctxt_idx(ctxt, CT_SP), 0x0, false);
    if sp != tid && tid <= uvaddr && uvaddr + n_byte <= tid + SIGFRAME_SIZE { return Some(n_byte); }
    if sp == tid && exp_is_syscall(get_ctxt_idx(ctxt, CT_CMD)) {
        let (start_idx, range) = get_syscall_cap_range(get_ctxt_idx(ctxt, CT_SYSCALL));
        for cap_idx in start_idx..(start_idx + range) {
            let scap = get_syscall_cap(cap_idx, ctxt);  // capability depth = 1
            if scap.3 == TY_NOLIMIT && scap.0 == uvaddr { return Some(n_byte); }
            if scap.3 == TY_CSTRING || ext_cap(scap.3) { check_ext_caps = true; }
            let (done, result) = examine_syscall_cap(n_byte, uvaddr, ctxt, is_write, is_str, bp, &scap, &mut m_byte, 0x0);
            if done { return result; }
        }
        if check_ext_caps {
            let mut ptr = get_ctxt_idx(ctxt, CT_CAP);
            while ptr != 0x0 {
                let ecap = unsafe { &*(ptr as *const (u64, u64, u64, u64)) };
                let (done, result) = examine_syscall_cap(n_byte, uvaddr, ctxt, is_write, is_str, bp, &ecap_to_scap(ecap), &mut m_byte, ptr);
                if done { return result; }
                ptr = ecap.3;
            }
        }
    }
    let task_arc = if let Some(arc) = task_arc_opt { arc } else { get_task_arc(get_pid(), tid) };
    let mut task = task_arc.write();
    if let Some((idx, lcap)) = task.lcap.iter().enumerate().find(|&(_, &lcap)| lcap.0 <= uvaddr && uvaddr + n_byte <= lcap.0 + lcap.1) {
        let new_cap = (get_base_idx(lcap.0, 0x0), lcap.1);
        if idx < CAP_ROBUST || new_cap.0 == 0x0 { return Some(n_byte); }
        if idx + 1 < task.lcap.len() {
            if task.lcap[idx + 1] == new_cap { return Some(n_byte); }
            else { task.lcap.truncate(idx + 1); }
        }
        task.lcap.insert(idx + 1, new_cap);
        return Some(n_byte);
    }
    if m_byte > 0x0 {
        log_strHex(L_DEBUG, "check_capability: warning, m_byte = 0x\0", m_byte);
        return Some(m_byte);
    }
    log_str(L_ERROR, "check_capability: error\n\0");
    loop { }
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------
fn check_present_pages(mut n_byte: u64, start: u64, step: usize, is_write: bool, is_null_ended: bool, bp: u64) -> Option<u64> {
    let mut start_addr: u64 = start;
    'outer: for vaddr in ((start & !(PAGE_SIZE - 1))..(start + n_byte)).step_by(PAGE_SIZE as usize) {
        if get_uat_paddr(vaddr, is_write).is_none() { dispatch_page_fault(vaddr, is_write, bp); return None; }
        if is_null_ended {
            let mut end_addr = vaddr + PAGE_SIZE;
            if end_addr > start + n_byte { end_addr = start + n_byte; }
            for null_vaddr in (start_addr..end_addr).step_by(step) {
                let null = if step == 0x1 { (unsafe { *(null_vaddr as *const u8) } == 0x0) } else { (unsafe { *(null_vaddr as *const u64) } == 0x0) };
                if null { n_byte = null_vaddr - start; break 'outer; }      // n_byte excludes the null byte / pointer
            }
            start_addr = end_addr;
        }
    }
    Some(n_byte)
}
fn check_availability(mut n_byte: u64, uvaddr: u64, tid: u64, is_write: bool, is_str: bool, bp: u64, _debug: u64) -> Option<u64> {
    if n_byte == 0x0 { return Some(n_byte); }
    if let Some(m_byte) = check_present_pages(n_byte, uvaddr, 0x1, is_write, is_str, bp) { n_byte = m_byte; } else { return None; }
    check_capability(n_byte, uvaddr, tid, is_write, is_str, bp)
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------
#[inline(always)]fn set_error(err_paddr: u64, err: i32) {
    if err_paddr != 0x0 { unsafe { *(paddr_to_gaddr(err_paddr) as *mut i32) = err; } } else { log_str(L_ERROR, "set_error: error\n\0"); }
}
#[inline(always)]fn set_n_byte(n_paddr: u64, n_byte: u64) {
    if n_paddr != 0x0 { unsafe { *(paddr_to_gaddr(n_paddr) as *mut u64) = n_byte; } } else { log_str(L_ERROR, "set_n_byte: error\n\0"); }
}
#[inline(always)]fn put_sized_user(uvaddr: u64, n_byte: u64, val: u64) {
    match n_byte {
        1 => unsafe { *(uvaddr as *mut u8)  = val as u8;  },
        2 => unsafe { *(uvaddr as *mut u16) = val as u16; },
        4 => unsafe { *(uvaddr as *mut u32) = val as u32; },
        8 => unsafe { *(uvaddr as *mut u64) = val as u64; },
        _ => log_strHex(L_ERROR, "put_sized_user: error, n_byte = \0", n_byte),
    }
}
pub fn put_user(n_byte: u64, uvaddr: u64, val: u64, tid: u64, err_paddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, RDWR, false, bp, 0x1) {
        if m_byte < n_byte { log_str(L_ERROR, "put_user: error, capability\n\0"); }
        put_sized_user(uvaddr, n_byte, val);
        NORMAL
    } else { KERNEL };
    set_error(err_paddr, if ret_val == KERNEL { -EFAULT } else { 0i32 });
    set_epd0();
    ret_val
}
pub fn clear_user(mut n_byte: u64, uvaddr: u64, tid: u64, n_paddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, RDWR, false, bp, 0x2) {
        memset(uvaddr, m_byte);
        n_byte -= m_byte;
        NORMAL
    } else { KERNEL };
    set_n_byte(n_paddr, n_byte);
    set_epd0();
    ret_val
}
pub fn strlen_user(n_byte: u64, uvaddr: u64, tid: u64, ret_paddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, ROLY, true, bp, 0x3) {
        set_n_byte(ret_paddr, m_byte);
        NORMAL
    } else {
        set_n_byte(ret_paddr, n_byte + 1);
        KERNEL
    };
    set_epd0();
    ret_val
}
#[inline(always)]fn get_sized_user(uvaddr: u64, n_byte: u64, kpaddr: u64) {
    if kpaddr == 0x0 || (kpaddr ^ (kpaddr + n_byte - 1)) >= PAGE_SIZE { log_str(L_ERROR, "get_sized_user: error\n\0"); }
    let kgaddr = paddr_to_gaddr(kpaddr);
    match n_byte {
        1 => unsafe { *(kgaddr as *mut u8)  = *(uvaddr as *const u8);  },
        2 => unsafe { *(kgaddr as *mut u16) = *(uvaddr as *const u16); },
        4 => unsafe { *(kgaddr as *mut u32) = *(uvaddr as *const u32); },
        8 => unsafe { *(kgaddr as *mut u64) = *(uvaddr as *const u64); },
        _ => log_strHex(L_ERROR, "get_sized_user: error, n_byte = \0", n_byte),
    }
}
pub fn get_user(n_byte: u64, uvaddr: u64, _kvaddr: u64, tid: u64, err_paddr: u64, kpaddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, ROLY, false, bp, 0x4) {
        if m_byte < n_byte { log_str(L_ERROR, "get_user: error, capability\n\0"); }
        get_sized_user(uvaddr, n_byte, kpaddr);
        NORMAL
    } else { KERNEL };
    set_error(err_paddr, if ret_val == KERNEL { -EFAULT } else { 0i32 });
    set_epd0();
    ret_val
}
pub fn copy_from_user(mut n_byte: u64, uvaddr: u64, kvaddr: u64, tid: u64, n_paddr: u64, kpaddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, ROLY, false, bp, 0x5) {
        memcpy(tmp_mapped_gaddr(kvaddr, kpaddr, m_byte, 0x5), uvaddr, m_byte);
        n_byte -= m_byte;
        tmp_unmap();
        NORMAL
    } else { KERNEL };
    set_n_byte(n_paddr, n_byte);
    set_epd0();
    ret_val
}
pub fn copy_to_user(mut n_byte: u64, uvaddr: u64, kvaddr: u64, tid: u64, n_paddr: u64, kpaddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, RDWR, false, bp, 0x6) {
        memcpy(uvaddr, tmp_mapped_gaddr(kvaddr, kpaddr, m_byte, 0x6), m_byte);
        n_byte -= m_byte;
        tmp_unmap();
        NORMAL
    } else { KERNEL };
    set_n_byte(n_paddr, n_byte);
    set_epd0();
    ret_val
}
pub fn strcpy_user(n_byte: u64, uvaddr: u64, kvaddr: u64, tid: u64, ret_paddr: u64, kpaddr: u64, bp: u64) -> u64 {
    unset_epd0();
    let ret_val = if let Some(m_byte) = check_availability(n_byte, uvaddr, tid, ROLY, true, bp, 0x7) {
        let length = if m_byte < n_byte { m_byte + 1 } else { m_byte };
        memcpy(tmp_mapped_gaddr(kvaddr, kpaddr, length, 0x7), uvaddr, length);
        set_n_byte(ret_paddr, m_byte);
        tmp_unmap();
        NORMAL
    } else {
        set_n_byte(ret_paddr, n_byte + 1);
        KERNEL
    };
    set_epd0();
    ret_val
}
#[inline(always)]fn tmp_mapped_gaddr(kvaddr: u64, kpaddr: u64, m_byte: u64, debug: u64) -> u64 {
    let end_vaddr = kvaddr + m_byte;
    if kpaddr == 0x0 || (kvaddr ^ (end_vaddr - 1)) >= PAGE_SIZE {
        log_strHex(L_ERROR, "tmp_mapped_gaddr: kpaddr = 0x\0", kpaddr);
        log_strHex(L_ERROR, "tmp_mapped_gaddr: kvaddr = 0x\0", kvaddr);
        log_strHex(L_ERROR, "tmp_mapped_gaddr: m_byte = 0x\0", m_byte);
        log_strHex(L_ERROR, "tmp_mapped_gaddr: debug = 0x\0", debug);
    }
    return paddr_to_gaddr(kpaddr);
//    let cpuid = get_cpuid();
//    let ptr = unsafe { BUFFER[cpuid] };
//    let n_page = (ptr as u64 - (ptr as u64 & !(PAGE_SIZE - 1))) / 8;
//    let start_gaddr = G_PAGE_OFFSET + SIZE_DRAM + PAGE_SIZE * (BUFFER_N_PAGE * cpuid as u64);
//    let mut m_page = 0;
//    for vaddr in ((kvaddr & !(PAGE_SIZE - 1))..end_vaddr).step_by(PAGE_SIZE as usize) {
//        let paddr = gaddr_to_paddr(get_kat_gaddr(vaddr, false));
//        set_entry(unsafe { &mut *ptr.offset(m_page as isize) }, (0x3 << 53) | paddr | 0xf03, start_gaddr + PAGE_SIZE * (n_page + m_page), true);
//        m_page += 1;
//    }
//    unsafe { BUFFER[cpuid] = ptr.offset(m_page as isize); }
//    (start_gaddr + PAGE_SIZE * n_page) | (kvaddr & (PAGE_SIZE - 1))
}
#[inline(always)]fn tmp_unmap() {
    let cpuid = get_cpuid();
    unsafe { BUFFER[cpuid] = (BUFFER[cpuid] as u64 & !(PAGE_SIZE - 1)) as *mut u64; }
}