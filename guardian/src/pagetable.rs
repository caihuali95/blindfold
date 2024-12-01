use crate::*;

pub fn idx_to_addr(idx_pud: usize, idx_pmd: usize, idx_pte: usize) -> u64 {
    ((idx_pud as u64) << 30) | ((idx_pmd as u64) << 21) | ((idx_pte as u64) << 12)
}
pub fn addr_to_idx(addr: u64) -> (usize, usize, usize) {
    (addr as usize >> 30 & 0x1ff, addr as usize >> 21 & 0x1ff, addr as usize >> 12 & 0x1ff)
}
pub fn get_uat_paddr(vaddr: u64, is_write: bool) -> Option<u64> {   // get user address translation paddr
    let par_el1: u64;
    if vaddr >> 48 != 0x0 { log_strHex(L_ERROR, "get_uat_paddr: illegal uvaddr = \0", vaddr); return None; }
    if is_write { unsafe { asm! ("at s1e1w, {0}\n mrs {1}, par_el1\n", in(reg) vaddr, out(reg) par_el1); } }
    else { unsafe { asm! ("at s1e1r, {0}\n mrs {1}, par_el1\n", in(reg) vaddr, out(reg) par_el1); } }
    if par_el1 & 0x1 == 0x1 { log_strHex(L_DEBUG, "get_uat_paddr: page fault, par_el1 = \0", par_el1); None }
    else { Some((par_el1 & OA_MASK) | (vaddr & (PAGE_SIZE - 1))) }
}
pub fn get_kat_gaddr(vaddr: u64, get_pte: bool) -> u64 {            // get kernel address translation pte / OA gaddr
    let (idx_pud, idx_pmd, idx_pte) = addr_to_idx(vaddr);
    let pud = unsafe { K_PT[idx_pud] };
    if !is_valid_pte(pud) { log_strHex(L_ERROR, "get_kat_gaddr: error A, vaddr = \0", vaddr); return 0; }
    let pmd = entry_to_gtable(pud)[idx_pmd];
    if !is_valid_pte(pmd) { log_strHex(L_ERROR, "get_kat_gaddr: error B, vaddr = \0", vaddr); return 0; }
    let paddr = if get_pte { entry_to_paddr(pmd) + (idx_pte << 3) as u64 } else { entry_to_paddr(entry_to_gtable(pmd)[idx_pte]) | (vaddr & (PAGE_SIZE - 1)) };
    paddr_to_gaddr(paddr)
}
fn check_page(entry: &mut u64, kernel: u64, is_inc: bool, seproc: &Option<Arc<RwLock<Task>>>, vpn: usize) {
    if !is_valid_pte(*entry) || entry_to_paddr(*entry) >= SIZE_DRAM { log_strHex(L_DEBUG, "check_page: warning A, entry = 0x\0", *entry); return; }
    let (paddr, pfn, flag) = entry_to_flag(*entry);
    if is_inc {
        if is_privilege(flag) { log_strHex(L_ERROR, "check_page: error A, flag = 0x\0", flag); }
        if seproc.is_none() && is_sensi_page(flag) {
            log_strHex(L_DEBUG, "check_page: warning B, entry = 0x\0", *entry);
            set_pte_op(entry, OP_INVA, vpn as u64 * PAGE_SIZE);
            return;
        }
        inc_frame_cnt(pfn, kernel_to_ukp(kernel), is_inc);
        if let Some(task_arc) = seproc { check_sensi_page(*entry, vpn, task_arc); }
    }
    else if inc_frame_cnt(pfn, kernel_to_ukp(kernel), is_inc) == 0 && is_sensi_page(flag) { unset_sensi_user_page(paddr, pfn, flag, vpn as u64 * PAGE_SIZE); }
}
fn check_table(pid: u64, entry: u64, kernel: u64, depth: u64, is_inc: bool, seproc: &Option<Arc<RwLock<Task>>>, vpn: usize) {
    let (paddr, pfn, flag) = entry_to_flag(entry);
    let (table_vaddr, cnt) = (paddr_to_vaddr(paddr), inc_frame_cnt(pfn, PTP, is_inc));
    if !is_inc {
        if !is_ptp_flag(flag, kernel, depth) { log_strHex(L_ERROR, "check_table: error A, flag = 0x\0", flag); return; }
        if cnt == 0 {
            set_4kb_frame_flag(pfn, NORMAL);
            let pte_gaddr = get_kat_gaddr(table_vaddr, true);
            set_pte_op(unsafe { &mut *(pte_gaddr as *mut u64) }, OP_RDWR, table_vaddr);
        }
    } else if cnt == 1 {
        if !is_normal(flag) { log_strHex(L_ERROR, "check_table: error B, flag = 0x\0", flag); return; }
        set_4kb_frame_flag(pfn, RDONLY | PTPAGE | kernel | depth);
        set_ptp_vpn_pid(pfn, vpn, pid);
        let pte_gaddr = get_kat_gaddr(table_vaddr, true);
        set_pte_op(unsafe { &mut *(pte_gaddr as *mut u64) }, OP_ROLY, table_vaddr);
        if seproc.is_some() { set_sensi_user_ptp(pfn, get_frame_flag(pfn), depth); }
    }
}
pub fn walk_page_table(pid: u64, entry: &mut u64, kernel: u64, depth: u64, is_inc: bool, seproc: &Option<Arc<RwLock<Task>>>, vpn: usize) { // walk page table
    if depth > DEPTH_PGT { check_page(entry, kernel, is_inc, seproc, vpn); return; }
    if depth > DEPTH_TOP && is_block_entry(*entry) { log_str(L_ERROR, "walk_page_table: error\n\0"); return; }
    check_table(pid, *entry, kernel, depth, is_inc, seproc, vpn);
    let table = entry_to_gtable(*entry);
    for i in 0..PTE_PER_PAGE as usize {
        if is_valid_entry(table[i]) { walk_page_table(pid, &mut table[i], kernel, depth + 1, is_inc, seproc, (vpn << VPN_SHIFT) | i); }
    }
}
pub fn update_page_table(mut n_pte: u64, mut pte_vaddr: u64, pte_val: u64, table_depth: u64) {
    let ptes = if n_pte == 0x0 { n_pte = 1; &[pte_vaddr, pte_val] } else { addr_to_slice::<u64>(vaddr_to_gaddr(pte_vaddr), n_pte * 2) as &[u64] };
    pte_vaddr = ptes[0];
    for i in 1..n_pte as usize { if (ptes[i * 2] ^ pte_vaddr) >= PAGE_SIZE { log_str(L_ERROR, "update_page_table: error A\n\0"); } }
    if !(K_PAGE_OFFSET <= pte_vaddr && pte_vaddr < K_PAGE_OFFSET + SIZE_DRAM) {
        log_strHex(L_DEBUG, "update_page_table: pte_vaddr = 0x\0", pte_vaddr);
        log_strHex(L_DEBUG, "update_page_table: pte_val = 0x\0", pte_val);
        set_entry_noflush(unsafe { &mut *(get_kat_gaddr(pte_vaddr, false) as *mut u64) }, pte_val);
        return;
    }
    let (_, table_pfn, table_flag) = entry_to_flag(pte_vaddr);
    if !is_normal(table_flag) && !is_ptpage(table_flag) { log_strHex(L_ERROR, "update_page_table: error B, flag = 0x\0", table_flag); }
    let (kernel, depth) = if is_normal(table_flag) { (USERPT, table_depth) } else { (get_flag_kernel(table_flag), get_flag_depth(table_flag)) };
    if depth != table_depth { log_str(L_ERROR, "update_page_table: error C\n\0"); }
    let (table_vpn, table_pid) = get_ptp_vpn_pid(table_pfn);
    let seproc = if is_sensi_proc(table_flag) { Some(get_task_arc(table_pid, 0x0)) } else { None };
    for i in 0..n_pte as usize {
        let pte_ref = unsafe { &mut *(vaddr_to_gaddr(ptes[i * 2]) as *mut u64) };
        if is_normal(table_flag) { set_entry_noflush(pte_ref, pte_val); continue; }
        let n_vpn = ((table_vpn << VPN_SHIFT) | ((ptes[i * 2] & (PAGE_SIZE - 1)) / 8)) as usize;
        if is_valid_entry(*pte_ref) { walk_page_table(table_pid, pte_ref, kernel, depth + 1, false, &seproc, n_vpn); }
        set_entry(pte_ref, pte_val, (n_vpn << (9 * (DEPTH_PGT - depth))) as u64 * PAGE_SIZE, table_depth == DEPTH_PGT);
        if is_valid_entry(*pte_ref) { walk_page_table(table_pid, pte_ref, kernel, depth + 1, true, &seproc, n_vpn); }
    }
}
pub fn update_ptbr(ptbr0: u64, ptbr1: u64, bp: u64) {
    if get_ptbr_asid(ptbr1) == 0x0 || entry_to_paddr(ptbr1) != unsafe { K_PT_PADDR } { log_strHex(L_ERROR, "update_ptbr: error A, ptbr1 = 0x\0", ptbr1); }
    if get_ptbr_asid(ptbr0) != 0x0 { log_strHex(L_ERROR, "update_ptbr: error B, ptbr0 = 0x\0", ptbr0); }
    let (mut paddr, _, flag) = entry_to_flag(ptbr0);
    if is_normal(flag) { walk_page_table(paddr, &mut paddr, USERPT, DEPTH_TOP, true, &None, 0x0); }
    else if !is_ptp_flag(flag, USERPT, DEPTH_TOP) { log_strHex(L_ERROR, "update_ptbr: error C, flag = 0x\0", flag); }
    set_ptbr(ptbr0, ptbr1, bp);
    unsafe { asm!("tlbi vmalle1\n dsb ish\n isb\n"); }
    if is_sensi_proc(flag) { set_epd0(); } else { unset_epd0(); }
}
pub fn free_pgd(pgd_vaddr: u64) {
    let (mut paddr, _, flag) = entry_to_flag(pgd_vaddr);
    if is_normal(flag) { return; }
    if !is_ptp_flag(flag, USERPT, DEPTH_TOP) { log_strHex(L_ERROR, "free_pgd: error, flag = 0x\0", flag); return; }
    let seproc = if is_sensi_proc(flag) {
        log_strHex(L_DEBUG, "free_pgd: sensitive pid = 0x\0", paddr);
        if get_pid() == paddr { unset_epd0(); }
        let task_arc = get_task_arc(paddr, 0x0);
        remove_tasks(paddr);
        Some(task_arc)
    } else { None };
    walk_page_table(paddr, &mut paddr, USERPT, DEPTH_TOP, false, &seproc, 0x0);
}
pub fn setup_sensi_proc(pid: u64, entry: u64, depth: u64, vpn: usize, task_arc: &Arc<RwLock<Task>>) {
    let (paddr, pfn, flag) = entry_to_flag(entry);
    set_sensi_user_ptp(pfn, flag, depth);
    let table = addr_to_slice::<u64>(paddr_to_gaddr(paddr), PTE_PER_PAGE);
    for i in 0..PTE_PER_PAGE as usize {
        if !is_valid_pte(table[i]) { continue; }
        if depth == DEPTH_PGT { check_sensi_page(table[i], (vpn << VPN_SHIFT) | i, task_arc); }
        else { setup_sensi_proc(pid, table[i], depth + 1, (vpn << VPN_SHIFT) | i, task_arc); }
    }
}
fn check_sensi_page(entry: u64, vpn: usize, task_arc: &Arc<RwLock<Task>>) {
    let (paddr, pfn, flag) = entry_to_flag(entry);
    let vaddr = vpn as u64 * PAGE_SIZE;
    let task = task_arc.read();
    let areas = task.vmareas.read();
    let heap_id = get_heap_id(&*areas);
    let hash_vaddr = task.sign_va + (vaddr - areas[TEXT_VMA_IDX].0) / PAGE_SIZE * HASH_SIZE;
    let idx = areas.iter().position(|area| vaddr < area.1).unwrap();
    if idx < heap_id { check_hash(paddr, PAGE_SIZE, &task.mac_key, hash_vaddr); }
    if areas[idx].0 <= vaddr {
        if !is_shared(areas[idx].2) {
            if idx < heap_id { crypto_page(paddr, &task.aes_key, false); }
            set_sensi_user_page(paddr, pfn, flag, vaddr);
        }
    } else if areas[idx].2 & VM_STACK != 0x0 {
        drop(areas);
        task.vmareas.write()[idx].0 = vaddr;
        set_sensi_user_page(paddr, pfn, flag, vaddr);
    } else { log_strHex(L_ERROR, "check_sensi_page: error, vaddr = 0x\0", vaddr); }
}
