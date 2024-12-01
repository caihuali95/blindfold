use crate::*;

pub const SIZE_2MB: u64 = 2 * 1024 * 1024;
pub const SIZE_1GB: u64 = 1024 * 1024 * 1024;
#[global_allocator] static GLOBAL: LockedHeap = LockedHeap::empty();

fn init_pt(mut vaddr: u64, k_pt_paddr: u64) {
    unsafe {
        STACK_GADDR = vaddr_to_gaddr(vaddr + STACK_N_PAGE * PAGE_SIZE);
        vaddr += (STACK_N_PAGE + ECAPS_N_PAGE) * PAGE_SIZE * HW_N_CORE as u64;
        G_PT = addr_to_slice::<u64>(vaddr, PTE_PER_PAGE);
        K_PT = addr_to_slice::<u64>(paddr_to_vaddr(k_pt_paddr), PTE_PER_PAGE);
        K_PT_PADDR = k_pt_paddr;
    }
    bf_log_strHex(L_DEBUG, "g_pt_vaddr = 0x\0", vaddr);
    bf_log_strHex(L_DEBUG, "k_pt_paddr = 0x\0", k_pt_paddr);
}
fn init_status(vaddr_2mb: u64, frame_vaddr: u64, zero_paddr: u64) {
    let frame = addr_to_slice::<u64>(frame_vaddr, HW_N_GB as u64 * 2 + 1);
    unsafe {
        for i in 0..HW_N_GB {
            STATUS[i] = frame[i] as *mut i16;
            PTINFO[i] = frame[HW_N_GB + i] as *mut u64;
        }
        CTXT_GADDR = vaddr_to_gaddr(frame[HW_N_GB * 2]);
        ZERO_PADDR = zero_paddr;
    }
    let (mut vaddr, n_slot) = (frame[HW_N_GB * 2], (SLOT_N_PAGE * PAGE_SIZE) / (CONTEXT_N_REG as u64 * 8));
    let (ecaps_base, ecaps_n_slot) = (vaddr_2mb + STACK_N_PAGE * PAGE_SIZE * HW_N_CORE as u64, ECAPS_N_PAGE * PAGE_SIZE / (4 * 8));
    for i in 0..HW_N_CORE {
        unsafe { SLOTS[i] = vaddr_to_gaddr(vaddr + CONTEXT_N_REG as u64 * 8); }
        for _ in 1..n_slot {
            vaddr += CONTEXT_N_REG as u64 * 8;
            unsafe { *(vaddr as *mut u64) = vaddr_to_gaddr(vaddr + CONTEXT_N_REG as u64 * 8); }
        }
        unsafe { *(vaddr as *mut u64) = 0x0; }
        vaddr += CONTEXT_N_REG as u64 * 8;
        let ecaps_vaddr = ecaps_base + ECAPS_N_PAGE * PAGE_SIZE * i as u64;
        for j in 1..ecaps_n_slot { set_base_idx(ecaps_vaddr, (j * 4 - 1) as usize, vaddr_to_gaddr(ecaps_vaddr + j * 4 * 8)); }
        unsafe { ECAPS[i] = vaddr_to_gaddr(ecaps_vaddr); }
    }
    set_2mb_frame_secure(vaddr_to_pfn(vaddr_2mb));
    for i in 0..=HW_N_GB * 2 { set_2mb_frame_secure(vaddr_to_pfn(frame[i])); }
    set_4kb_frame_flag(paddr_to_pfn(zero_paddr), RDONLY);
}
fn mark_kernel_page_table(k_pt_paddr: u64, first: bool) {   // walk kernel page table for twice
    let pfn = paddr_to_pfn(k_pt_paddr);                     // first to mark PTP flag and second to count references
    if first { set_4kb_frame_flag(pfn, RDONLY | PTPAGE | KERNEL | DEPTH_PUD); }
    else { inc_frame_cnt(pfn, PTP, true); set_ptp_vpn_pid(pfn, 0x1, k_pt_paddr); }
    for i in 0..PTE_PER_PAGE as usize {
        let k_pud_ref = unsafe { &mut K_PT[i] };
        if is_block_entry(*k_pud_ref) { if first { bf_log_str(L_LOG, "1GB HP\n\0"); } else { log_str(L_LOG, "1GB HP\n\0"); } }
        if !is_valid_pte(*k_pud_ref) { continue; }
        let (paddr, pfn) = entry_to_pfn(*k_pud_ref);
        if first { set_4kb_frame_flag(pfn, RDONLY | PTPAGE | KERNEL | DEPTH_PMD); }
        else { inc_frame_cnt(pfn, PTP, true); set_ptp_vpn_pid(pfn, (0x1 << VPN_SHIFT) | i, k_pt_paddr); }
        let k_pmdt_addr = if first { paddr_to_vaddr(paddr) } else { paddr_to_gaddr(paddr) };
        let k_pmdt = addr_to_slice::<u64>(k_pmdt_addr, PTE_PER_PAGE);
        for j in 0..PTE_PER_PAGE as usize {
            if is_block_entry(k_pmdt[j]) { if first { bf_log_str(L_LOG, "2MB HP\n\0"); } else { log_str(L_LOG, "2MB HP\n\0"); } }
            if !is_valid_pte(k_pmdt[j]) { continue; }
            let (paddr, pfn) = entry_to_pfn(k_pmdt[j]);
            if first { set_4kb_frame_flag(pfn, RDONLY | PTPAGE | KERNEL | DEPTH_PGT); continue; }
            inc_frame_cnt(pfn, PTP, true);
            set_ptp_vpn_pid(pfn, (((0x1 << VPN_SHIFT) | i) << VPN_SHIFT) | j, k_pt_paddr);
            let k_pt = addr_to_slice::<u64>(paddr_to_gaddr(paddr), PTE_PER_PAGE);
            for k in 0..PTE_PER_PAGE as usize {
                if !is_valid_pte(k_pt[k]) || entry_to_paddr(k_pt[k]) >= SIZE_DRAM { continue; }
                let (_, pfn, flag) = entry_to_flag(k_pt[k]);
                let vaddr = K_PAGE_OFFSET | idx_to_addr(i, j, k);
                if flag & SECURE != 0 { set_pte_op(&mut k_pt[k], OP_INVA, vaddr); continue; }
                if flag & RDONLY != 0 {
                    if vaddr >= K_PAGE_OFFSET | SIZE_DRAM { log_strHex(L_DEBUG, "non-kdm RDONLY vaddr = 0x\0", vaddr); continue; }
                    set_pte_op(&mut k_pt[k], OP_ROLY, vaddr);
                }
                if flag & ITPAGE != 0 { set_table_exec(k_pud_ref, &mut k_pmdt[j], &mut k_pt[k], vaddr); }
                inc_frame_cnt(pfn, KER, true);
            }
        }
    }
}
fn extend_buffer_mapping(gaddr: u64, base: u64, n_page: &mut u64) -> *mut u64 {
    let (idx_pud, idx_pmd, _) = addr_to_idx(gaddr);
    let G_PUD = unsafe { &mut G_PT[idx_pud] };
    if *G_PUD == 0 { set_entry_noflush(G_PUD, vaddr_to_paddr(base + *n_page * PAGE_SIZE) | 0x3); *n_page += 1; }
    let G_PMD = &mut entry_to_vtable(*G_PUD)[idx_pmd];
    if *G_PMD == 0 { set_entry_noflush(G_PMD, vaddr_to_paddr(base + *n_page * PAGE_SIZE) | 0x3); *n_page += 1; }
    paddr_to_gaddr(entry_to_paddr(*G_PMD)) as *mut u64
}
fn extend_direct_mapping(gaddr: u64, xor_flags: u64, or_flags: u64, base: u64, n_page: &mut u64) {
    let (idx_pud, idx_pmd, idx_pte) = addr_to_idx(gaddr);
    let G_PUD = unsafe { &mut G_PT[idx_pud] };
    let G_PMD = if is_block_entry(*G_PUD) {
        let pmdt_vaddr = base + *n_page * PAGE_SIZE;
        *n_page += 1;
        let pmdt = addr_to_slice::<u64>(pmdt_vaddr, PTE_PER_PAGE);
        for i in 0..PTE_PER_PAGE as usize {
            set_entry_noflush(&mut pmdt[i], *G_PUD + i as u64 * SIZE_2MB);         // 2MB huge page, non-global
        }
        set_entry_noflush(G_PUD, vaddr_to_paddr(pmdt_vaddr) | 0x3);
        &mut pmdt[idx_pmd]
    } else {
        &mut entry_to_vtable(*G_PUD)[idx_pmd]
    };
    let G_PTE = if is_block_entry(*G_PMD) {
        let pt_vaddr = base + *n_page * PAGE_SIZE;
        *n_page += 1;
        let pt = addr_to_slice::<u64>(pt_vaddr, PTE_PER_PAGE);
        for i in 0..PTE_PER_PAGE as usize {
            set_entry_noflush(&mut pt[i], (*G_PMD + i as u64 * PAGE_SIZE) | 0x2);  // 4KB small page, non-global
        }
        set_entry_noflush(G_PMD, vaddr_to_paddr(pt_vaddr) | 0x3);
        &mut pt[idx_pte]
    } else {
        &mut entry_to_vtable(*G_PMD)[idx_pte]
    };
    set_entry_noflush(G_PTE, (*G_PTE ^ xor_flags) | or_flags);
}
fn mimic_page_table(g_entry: &mut u64, k_entry: u64, base: u64, n_page: &mut u64) {
    if *g_entry != 0 { return; }
    if !is_valid_pte(k_entry) { bf_log_str(L_ERROR, "invalid k_entry\n\0"); return; }
    let vaddr_page = base + *n_page * PAGE_SIZE;
    *n_page += 1;
    set_entry_noflush(g_entry, entry_wr_baddr(k_entry, vaddr_to_paddr(vaddr_page)));
}
fn extend_vma_mapping(vaddr_4kb: u64, base: u64, n_page: &mut u64, gate: bool) -> u64 {
    let (idx_pud, idx_pmd, idx_pte) = addr_to_idx(vaddr_4kb);
    let (g_pud_ref, k_pud_ref) = unsafe { (&mut G_PT[idx_pud], &K_PT[idx_pud]) };
    mimic_page_table(g_pud_ref, *k_pud_ref, base, n_page);
    let (g_pmdt, k_pmdt) = (entry_to_vtable(*g_pud_ref), entry_to_vtable(*k_pud_ref));
    mimic_page_table(&mut g_pmdt[idx_pmd], k_pmdt[idx_pmd], base, n_page);
    let (g_pt, k_pt) = (entry_to_vtable(g_pmdt[idx_pmd]), entry_to_vtable(k_pmdt[idx_pmd]));
    set_entry_noflush(&mut g_pt[idx_pte], k_pt[idx_pte] | 0x800);                       // 4KB small page, non-global
    if gate { set_table_exec(g_pud_ref, &mut g_pmdt[idx_pmd], &mut g_pt[idx_pte], vaddr_4kb); }
    g_pt[idx_pte]
}
fn create_guardian_page_table(base: u64, gate_vaddr: u64, segs_vaddr: u64) -> u64 {     // no need to flush TLB as PT is not active
    for paddr_1gb in (0..SIZE_DRAM).step_by(SIZE_1GB as usize) {                        // direct mapping
        let idx_pud = ((paddr_to_gaddr(paddr_1gb) >> 30) & 0x1ff) as usize;
        set_entry_noflush(unsafe { &mut G_PT[idx_pud] }, (0x3 << 53) | paddr_1gb | 0xf01); // 1GB huge page, non-global
    }
    let mut n_page = (STACK_N_PAGE + ECAPS_N_PAGE) * HW_N_CORE as u64 + 1;
    let segs = addr_to_slice::<u64>(segs_vaddr, MOD_VMA_NUM as u64 * 2);                // module binary
    for i in 0..MOD_VMA_NUM as usize {
        let (start, end) = (segs[i * 2], segs[i * 2 + 1]);
        for vaddr_4kb in (start..end).step_by(PAGE_SIZE as usize) {
            let entry = extend_vma_mapping(vaddr_4kb, base, &mut n_page, false);
            if i < MOD_INIT && (i != MOD_DATA || vaddr_4kb != start) {                  // Lazy to do: struct module
                set_4kb_frame_flag(paddr_to_pfn(entry_to_paddr(entry)), SECURE);
            }
        }
    }
    extend_vma_mapping(gate_vaddr, base, &mut n_page, true);                            // gate mapped as executable
    extend_direct_mapping(UART_GADDR, 0x0, 0xc, base, &mut n_page);                     // uart mapped as device memory
    for i in 0..HW_N_CORE {                                                             // reserve vm areas for temporary mapping in uaccess
        unsafe { BUFFER[i] = extend_buffer_mapping(G_PAGE_OFFSET + SIZE_DRAM + PAGE_SIZE * BUFFER_N_PAGE * i as u64, base, &mut n_page); }
    }
    return n_page;
}
fn update_stored_pointers() {
    unsafe {
        G_PT = addr_to_slice::<u64>(vaddr_to_gaddr(G_PT.as_ptr() as u64), PTE_PER_PAGE);
        K_PT = addr_to_slice::<u64>(vaddr_to_gaddr(K_PT.as_ptr() as u64), PTE_PER_PAGE);
        for i in 0..HW_N_GB { STATUS[i] = vaddr_to_gaddr(STATUS[i] as u64) as *mut i16; }
        for i in 0..HW_N_GB { PTINFO[i] = vaddr_to_gaddr(PTINFO[i] as u64) as *mut u64; }
        *G_TASK.write() = Some(BTreeMap::new());
    }
}

#[no_mangle]
pub extern "C" fn rsG_secboot(vaddr_2mb: u64, k_pt_paddr: u64, frame_vaddr: u64, segs_vaddr: u64, zero_paddr: u64) {
    bf_log_strHex(L_DEBUG, "gate_vaddr = 0x\0", frame_vaddr);       // use bf_XXX when kernel PT is active
    bf_log_strHex(L_DEBUG, "zero_paddr = 0x\0", zero_paddr);
    init_pt(vaddr_2mb, k_pt_paddr);
    init_status(vaddr_2mb, frame_vaddr, zero_paddr);
    init_interrupt_table(frame_vaddr);
    init_syscall_cap_table();
    mark_kernel_page_table(k_pt_paddr, true);
    let used_size = create_guardian_page_table(vaddr_2mb, frame_vaddr, segs_vaddr) * PAGE_SIZE;
    switch_g_ptbr();                                // not until we (1) switch to use Guardian PT
    unsafe { GLOBAL.lock().init((vaddr_to_gaddr(vaddr_2mb) + used_size) as *mut u8, (SIZE_2MB - used_size) as usize); }
    update_stored_pointers();                       // and (2) update stored pointers that work with Guardian PT
    mark_kernel_page_table(k_pt_paddr, false);      // then we can hide sensitive pages from kernel page table
}