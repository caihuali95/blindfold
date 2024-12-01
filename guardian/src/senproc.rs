use crate::*;
use crate::aes::cipher::KeyInit;

const MAP_FIXED:            u64 = 0x10;
const MAP_FIXED_NOREPLACE:  u64 = 0x100000;
const MINUS_ONE:            u64 = 0xffff_ffff_ffff_ffff;

pub static G_TASK: RwLock<Option<BTreeMap<(u64, u64), Arc<RwLock<Task>>>>> = RwLock::new(None);
fn dealloc_task_ctxt(task_arc: &Arc<RwLock<Task>>) {
    let mut task = task_arc.write();
    dealloc_ctxt(&mut task.ctxt);
    dealloc_ctxt(&mut task.vctx);
}
fn insert_task_arc(pid: u64, tid: u64, task_arc: Arc<RwLock<Task>>, new_proc: bool) {
    if tid == 0x0 { log_str(L_ERROR, "insert_task_arc: error A\n\0"); }
    if let Some(ref mut map) = *G_TASK.write() {
        if new_proc { map.insert((pid, 0x0), Arc::new(RwLock::new(task_arc.read().proc()))); }
        if let Some(old_task_arc) = map.insert((pid, tid), task_arc) {
            if get_ctxt_idx(old_task_arc.read().ctxt, CT_CMD) == EXP_SYSEXEC { dealloc_task_ctxt(&old_task_arc); }
            else { log_str(L_ERROR, "insert_task_arc: error B\n\0"); }
        }
    }
}
fn remove_task(pid: u64, tid: u64) {
    if let Some(ref mut map) = *G_TASK.write() {
        if let Some(task_arc) = map.remove(&(pid, tid)) { dealloc_task_ctxt(&task_arc); }
        else { log_str(L_ERROR, "remove_task: error\n\0"); }
    }
}
pub fn remove_tasks(pid: u64) {
    if let Some(ref mut map) = *G_TASK.write() {
        loop {
            let tid = if let Some((key, _)) = map.upper_bound(Bound::Excluded(&(pid, 0))).peek_next() {
                if key.0 == pid { key.1 } else { return; }
            } else { return; };
            if let Some(task_arc) = map.remove(&(pid, tid)) { dealloc_task_ctxt(&task_arc); }
            else { log_str(L_ERROR, "remove_tasks: error\n\0"); }
        }
    }
}
pub fn get_task_arc(pid: u64, tid: u64) -> Arc<RwLock<Task>> {
    if let Some(ref map) = *G_TASK.read() {
        if let Some((key, val)) = map.upper_bound(Bound::Excluded(&(pid, tid))).peek_next() {
            if key.0 == pid { return val.clone(); }
        }
    }
    log_strHex(L_ERROR, "get_task_arc: error, tid = 0x\0", tid);
    loop { }
}

pub struct Task {
    pub tid: u64,                                   // thread identifier
    pub ctxt: *mut Context,                         // execution context
    pub vctx: *mut Context,                         // execution context for vfork
    pub sigh: Arc<RwLock<BTreeMap<u64,u64>>>,       // signal handlers, may be shared among threads
    pub lcap: Vec<(u64, u64)>,                      // long-lived capabilities
    pub sign_va: u64,                               // signature starting address, read-only
    pub aes_key: Arc<Aes128>,                       // per-process encryption key, read-only
    pub mac_key: Arc<HmacSha256>,                   // per-process signature key, read-only
    pub vmareas: Arc<RwLock<Vec<(u64, u64, u64)>>>, // per-process virtual memory areas
}
impl Task {
    fn new(regs_vaddr: u64, vmas_vaddr: u64, brk: u64) -> Task {
        let (ctxt, vmas_gaddr) = (alloc_ctxt(), get_kat_gaddr(vmas_vaddr, false));
        read_ctxt(ctxt, get_kat_gaddr(regs_vaddr, false), EXP_EMULATE);
        let mut areas = Vec::from(addr_to_slice::<(u64, u64, u64)>(vmas_gaddr + 0x8 * 3, get_base_idx(vmas_gaddr, 0x0)));
        let (n_vma, idx) = (areas.len(), areas.iter().position(|&area| area.1 == brk).unwrap());
        for fid in (idx + 1)..(n_vma - 1) { areas[fid].2 |= VM_SHARED; }
        areas.insert(idx + 1, (brk, brk, VM_READ | VM_WRITE | VM_HEAP));
        Task {
            tid: get_ctxt_idx(ctxt, CT_SP), ctxt: ctxt, vctx: 0x0 as *mut Context,
            sigh: Arc::new(RwLock::new(BTreeMap::new())), lcap: Vec::from(&[(0, 0); 3]),
            sign_va: get_base_idx(vmas_gaddr, 0x2) + get_base_idx(vmas_gaddr, 0x1),
            aes_key: Arc::new(Aes128::new(GenericArray::from_slice(&assign_enc_key()))),
            mac_key: Arc::new(HmacSha256::new_from_slice(&assign_mac_key()).expect("HMAC")),
            vmareas: Arc::new(RwLock::new(areas)),
        }
    }
    fn fork(&self) -> Task {
        if get_ctxt_idx(self.ctxt, CT_CMD) != EXP_SYSFORK { log_str(L_ERROR, "Task::fork: error\n\0"); }
        set_ctxt_idx(self.ctxt, CT_CMD, EXP_SYSCALL);
        let ctxt = alloc_ctxt();
        copy_ctxt(ctxt, self.ctxt, CONTEXT_N_REG);
        let mut tid = get_ctxt_idx(ctxt, CT_A1);
        if tid == 0x0 { tid = self.tid; } else { set_ctxt_idx(ctxt, CT_SP, tid); }
        Task {
            tid: tid, ctxt: ctxt, vctx: 0x0 as *mut Context, sigh: clone_sighand(ctxt, &self.sigh),
            lcap: Vec::from(&[(get_ctxt_idx(ctxt, CT_A4), 0x4), self.lcap[CAP_RSEQ], (0, 0)]),
            sign_va: self.sign_va, aes_key: self.aes_key.clone(), mac_key: self.mac_key.clone(), 
            vmareas: Arc::new(RwLock::new(self.vmareas.read().clone())),
        }
    }
    fn clone(&self) -> Task {
        if get_ctxt_idx(self.ctxt, CT_CMD) != EXP_SYSCLONE { log_str(L_ERROR, "Task::clone: error\n\0"); }
        let ctxt = alloc_ctxt();
        copy_ctxt(ctxt, self.ctxt, CONTEXT_N_REG);
        let tid = get_ctxt_idx(ctxt, CT_A1);
        set_ctxt_idx(ctxt, CT_SP, tid);
        Task {
            tid: tid, ctxt: ctxt, vctx: 0x0 as *mut Context, sigh: clone_sighand(ctxt, &self.sigh),
            lcap: Vec::from(&[(get_ctxt_idx(ctxt, CT_A4), 0x4), self.lcap[CAP_RSEQ], (0, 0)]),
            sign_va: self.sign_va, aes_key: self.aes_key.clone(), mac_key: self.mac_key.clone(), 
            vmareas: self.vmareas.clone(),
        }
    }
    fn signal(&self, ctxt: *mut Context) -> Task {
        Task {
            tid: get_ctxt_idx(ctxt, CT_SP), ctxt: ctxt, vctx: 0x0 as *mut Context,
            sigh: clone_sighand(ctxt, &self.sigh), lcap: self.lcap.clone(),
            sign_va: self.sign_va, aes_key: self.aes_key.clone(), mac_key: self.mac_key.clone(), 
            vmareas: self.vmareas.clone(),
        }
    }
    fn proc(&self) -> Task {
        Task {
            tid: 0x0, ctxt: 0x0 as *mut Context, vctx: 0x0 as *mut Context,
            sigh: Arc::new(RwLock::new(BTreeMap::new())), lcap: Vec::with_capacity(0),
            sign_va: self.sign_va, aes_key: self.aes_key.clone(), mac_key: self.mac_key.clone(),
            vmareas: self.vmareas.clone(),
        }
    }
}
fn clone_sighand(ctxt: *const Context, sigh: &Arc<RwLock<BTreeMap<u64,u64>>>) -> Arc<RwLock<BTreeMap<u64,u64>>> {
    let flags = get_ctxt_idx(ctxt, CT_A0);
    if flags & CLONE_CLEAR_SIGHAND != 0x0 { return Arc::new(RwLock::new(BTreeMap::new())); }
    if flags & CLONE_SIGHAND != 0x0 { return sigh.clone(); }
    Arc::new(RwLock::new(sigh.read().clone()))
}
pub fn create_process(pgd_vaddr: u64, regs_vaddr: u64, vmas_vaddr: u64, brk: u64) {
    let (pid, _, flag) = entry_to_flag(pgd_vaddr);
    log_strHex(L_DEBUG, "create_process: pid = 0x\0", pid);
    if !is_ptp_flag(flag, USERPT, DEPTH_TOP) || is_sensi_proc(flag) { log_strHex(L_ERROR, "create_process: error, flag = 0x\0", flag); }
    let task = Task::new(regs_vaddr, vmas_vaddr, brk);
    let (tid, task_arc) = (task.tid, Arc::new(RwLock::new(task)));
    setup_sensi_proc(pid, pid, DEPTH_TOP, 0x0, &task_arc);
    insert_task_arc(pid, tid, task_arc, true);
    set_epd0();
}
pub fn forked_process(pgd_vaddr: u64, f_pgd_vaddr: u64, f_sp: u64) {
    let (mut pid, _, flag) = entry_to_flag(pgd_vaddr);
    log_strHex(L_DEBUG, "forked_process: pid = 0x\0", pid);
    if !is_normal(flag) { log_strHex(L_ERROR, "forked_process: error, flag = 0x\0", flag); }
    let f_pid = entry_to_paddr(f_pgd_vaddr);
    log_strHex(L_DEBUG, "forked_process: f_pid = 0x\0", f_pid);
    let f_task_arc = get_task_arc(f_pid, f_sp);
    let task = { f_task_arc.read().fork() };
    let (tid, task_arc) = (task.tid, Arc::new(RwLock::new(task)));
    walk_page_table(pid, &mut pid, USERPT, DEPTH_TOP, true, &Some(task_arc.clone()), 0x0);
    setup_sensi_proc(pid, pid, DEPTH_TOP, 0x0, &task_arc);
    insert_task_arc(pid, tid, task_arc, true);
    set_epd0();
}
fn get_resume_ctxt(sp: u64) -> Option<*mut Context> {
    let cid = get_cid();
    if cid == 0x0 { return None; }
    let ctxt = get_ctxt_from_cid(cid);
    return if get_ctxt_idx(ctxt, CT_SP) != sp || exp_resume(get_ctxt_idx(ctxt, CT_CMD)) { None } else { Some(ctxt) };
}
fn check_resume_ctxt(ctxt: *mut Context, elr: u64) -> u64 {
    let (ct_elr, cmd) = (get_ctxt_idx(ctxt, CT_ELR), get_ctxt_idx(ctxt, CT_CMD));
    if ct_elr == elr + 4 && exp_is_syscall(cmd) { set_ctxt_idx(ctxt, CT_ELR, elr); return EXP_SYNC; }
    else if ct_elr != elr { log_str(L_ERROR, "check_resume_ctxt: error\n\0"); }
    cmd
}
pub fn resume_process(sp: u64, ret: u64, elr: u64, spsr: u64, regs_vaddr: u64) -> u64 {
    if let Some(ctxt) = get_resume_ctxt(sp) {
        if exp_is_syscall(check_resume_ctxt(ctxt, elr)) {
            let ecap = get_ctxt_idx(ctxt, CT_CAP);
            if ecap != 0x0 { recycle_ecap(ecap); set_ctxt_idx(ctxt, CT_CAP, 0x0); }
            set_ctxt_idx(ctxt, CT_A0, ret);
            log_strHex(L_DEBUG, "resume_process: fast, syscall = 0x\0", get_ctxt_idx(ctxt, CT_SYSCALL));
        }
        if get_ctxt_idx(ctxt, CT_CMD) == EXP_FAULT { log_str(L_DEBUG, "resume_process: fast, fault\n\0"); }
    } else {
        let pid = get_pid();
        log_strHex(L_DEBUG, "resume_process: slow, pid = 0x\0", pid);
        log_strHex(L_DEBUG, "resume_process: slow, sp = 0x\0", sp);
        let task_arc = get_task_arc(pid, sp);
        let task = task_arc.read();
        let ctxt = unsafe { &mut *task.ctxt };
        if ctxt[CT_SP] == sp {
            let cmd = check_resume_ctxt(task.ctxt, elr);
            if cmd == EXP_FAULT { log_str(L_DEBUG, "resume_process: slow, fault\n\0"); }
            if exp_is_syscall(cmd) {
                log_strHex(L_DEBUG, "resume_process: slow, syscall = 0x\0", ctxt[CT_SYSCALL]);
                log_strHex(L_DEBUG, "resume_process: slow, ret = 0x\0", ret);
                if cmd == EXP_SYSBRK { check_brk(&task.vmareas, task.ctxt, ret); }
                if cmd == EXP_SYSMMAP { check_mmap(&task.vmareas, task.ctxt, ret); }
                if cmd == EXP_SYSMUNMAP { check_munmap(&task.vmareas, task.ctxt, ret); }
                if cmd == EXP_SYSMPROT && ret == 0x0 { do_mprot(&task.vmareas, task.ctxt); }
                drop(task);
                let mut task = task_arc.write();
                if cmd == EXP_SYSVFORK {
                    task.vctx = alloc_ctxt();
                    ctxt[CT_CMD] = EXP_SYSCALL;
                    copy_ctxt(task.vctx, task.ctxt, CONTEXT_N_REG);
                }
                if exp_have_lcap(cmd) && (ret == 0x0 || cmd == EXP_SYSTID) {
                    if cmd == EXP_SYSTID { task.lcap[CAP_TID] = (ctxt[CT_A0], 0x4); }
                    else { task.lcap[CAP_RSEQ + (cmd - EXP_SYSRSEQ) as usize] = (ctxt[CT_A0], ctxt[CT_A1]); }
                }
                if cmd == EXP_SYSBRK || cmd == EXP_SYSMMAP { ctxt[CT_TMP] = 0x0; }
                else if ctxt[CT_CAP] != 0x0 { recycle_ecap(ctxt[CT_CAP]); ctxt[CT_CAP] = 0x0; }
                ctxt[CT_A0] = ret;
            }
            set_cid(ctxt as *mut Context);
        } else if elr == EXP_SIGNAL {
            let hdl = { *task.sigh.read().get(&ret).unwrap() };
            let (sig_ctxt, regs_gaddr) = (alloc_ctxt(), get_kat_gaddr(regs_vaddr, false));
            read_ctxt(sig_ctxt, regs_gaddr, EXP_SIGNAL);
            set_ctxt_idx(sig_ctxt, CT_SPSR, spsr);
            set_ctxt_idx(sig_ctxt, CT_ELR, hdl);
            let c_task = task.signal(sig_ctxt);
            let (c_tid, c_task_arc) = (c_task.tid, Arc::new(RwLock::new(c_task)));
            insert_task_arc(pid, c_tid, c_task_arc, false);
            set_cid(sig_ctxt);
        } else if task.vctx as u64 != 0x0 && get_ctxt_idx(task.vctx, CT_SP) == sp {
            if get_ctxt_idx(task.ctxt, CT_CMD) != EXP_SYSEXEC { log_str(L_ERROR, "resume_process: error, vfork\n\0"); }
            drop(task);
            let mut task = task_arc.write();
            copy_ctxt(task.ctxt, task.vctx, CONTEXT_N_REG);
            set_ctxt_idx(task.ctxt, CT_A0, ret);
            dealloc_ctxt(&mut task.vctx);
            set_cid(task.ctxt);
        } else { log_strHex(L_ERROR, "resume_process: ctxt not found, sp = 0x\0", sp); }
        log_strHex(L_DEBUG, "resume_process: done, sp = 0x\0", sp);
    }
    switch_vbar(SECURE);
    unset_epd0();
    SECURE
}
fn finish_interrupt(idx: u64, bp: u64) {
    set_base_idx(bp, BP_LR, ith_IT_entry(idx));
    switch_vbar(NORMAL);
    set_epd0();
}
pub fn interrupt_process(ctxt_addr: u64, idx: u64, bp: u64) -> u64 {
    let ctxt = ctxt_addr as *mut Context;
    let cmd = analyze_exception(ctxt, idx);
    if cmd == EXP_EMULATE { return SECURE; } else { set_ctxt_idx(ctxt, CT_CMD, cmd); }
    if exp_interrupt(cmd) {
        let (pid, sp) = (get_pid(), get_ctxt_idx(ctxt, CT_SP));
        log_strHex(L_DEBUG, "interrupt_process: pid = 0x\0", pid);
        log_strHex(L_DEBUG, "interrupt_process: sp  = 0x\0", sp);
        let task_arc = get_task_arc(pid, sp);
        match cmd {
            EXP_SYSBRK => do_brk(task_arc, ctxt),
            EXP_SYSMMAP => do_mmap(task_arc, ctxt),
            EXP_SYSMUNMAP => {
                let task = task_arc.read();
                do_munmap(&mut task.vmareas.write(), get_ctxt_idx(ctxt, CT_A0), get_ctxt_idx(ctxt, CT_A1));
            },
            EXP_SYSCLONE => {
                let c_task = { task_arc.read().clone() };
                let (c_tid, c_task_arc) = (c_task.tid, Arc::new(RwLock::new(c_task)));
                insert_task_arc(pid, c_tid, c_task_arc, false);
            }
            EXP_SYSSIGACT => do_sigact(task_arc, ctxt),
            EXP_SYSSIGRET => {
                copy_ctxt(get_cpu_ctxt(), ctxt, SYSCALL_N_REG);
                let tid = { task_arc.read().tid };
                remove_task(pid, tid);
                finish_interrupt(idx, bp);
                set_cid(0x0 as *mut Context);
                return KERNEL;
            }
            EXP_SYSEXIT => {
                let mut task = task_arc.write();
                if task.vctx as u64 != 0x0 {
                    copy_ctxt(get_cpu_ctxt(), ctxt, SYSCALL_N_REG);
                    copy_ctxt(task.ctxt, task.vctx, CONTEXT_N_REG);
                    dealloc_ctxt(&mut task.vctx);
                    finish_interrupt(idx, bp);
                    return KERNEL;
                } else {
                    set_cid(0x0 as *mut Context);
                }
            },
            _ => log_strHex(L_ERROR, "interrupt_process: error, cmd = 0x\0", cmd),
        }
    }
    finish_interrupt(idx, bp);
    if exp_is_syscall(cmd) {
        log_strHex(L_DEBUG, "interrupt_process: syscall = 0x\0", get_ctxt_idx(ctxt, CT_SYSCALL));
        copy_ctxt(get_cpu_ctxt(), ctxt, SYSCALL_N_REG);
        KERNEL
    } else { NORMAL }
}
fn do_sigact(task_arc: Arc<RwLock<Task>>, ctxt: *const Context) {
    let (num, act) = (get_ctxt_idx(ctxt, CT_A0), get_ctxt_idx(ctxt, CT_A1));
    let hdl = if act == 0x0 || get_uat_paddr(act, false).is_none() { return; } else { get_base_idx(act, 0x0) };
    let sigh_arc = { task_arc.read().sigh.clone() };
    let mut sigh = sigh_arc.write();
    if hdl <= 1 { sigh.remove(&num); }
    else {
        sigh.insert(num, hdl);
        set_base_idx(act, 0x0, EXP_SIGNAL);
    }
}
fn do_brk(task_arc: Arc<RwLock<Task>>, ctxt: *mut Context) {
    let task = task_arc.read();
    let (ctx_ref, mut areas) = (unsafe { &mut *ctxt }, task.vmareas.write());
    let idx = get_heap_id(&*areas);
    if ctx_ref[CT_A0] < areas[idx].0 { return; }
	ctx_ref[CT_TMP] = areas[idx].1;
	areas[idx].1 = ctx_ref[CT_A0];
}
fn check_brk(vmareas: &Arc<RwLock<Vec<(u64, u64, u64)>>>, ctxt: *mut Context, ret: u64) {
    let (ctx_ref, mut areas) = (unsafe { &mut *ctxt }, vmareas.write());
    let idx = get_heap_id(&*areas);
    if ctx_ref[CT_A0] < areas[idx].0 {
        if ret != areas[idx].1 { log_str(L_ERROR, "check_brk: error A\n\0"); }
        return;
    }
    if ret == ctx_ref[CT_TMP] { areas[idx].1 = ctx_ref[CT_TMP]; return; }
    if ret != ctx_ref[CT_A0] { log_str(L_ERROR, "check_brk: error B\n\0"); }
}
fn do_mmap(task_arc: Arc<RwLock<Task>>, ctxt: *mut Context) {
    let ctx_ref = unsafe { &mut *ctxt };
    if (ctx_ref[CT_A0] & (PAGE_SIZE - 1)) != 0x0 || ctx_ref[CT_A1] == 0x0 { return; }
    let length = (ctx_ref[CT_A1] - 1) / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE;
    let task = task_arc.read();
    let mut areas = task.vmareas.write();
    let mut idx = get_heap_id(&*areas);
    let (vm_start, vm_end, flags) = if ctx_ref[CT_A0] == 0x0 || ctx_ref[CT_A3] & (MAP_FIXED | MAP_FIXED_NOREPLACE) == 0x0 {
        if areas[idx + 1].0 - length < areas[idx].1 { ctx_ref[CT_TMP] = 0x1; return; }
        (areas[idx + 1].0 - PAGE_SIZE - length, areas[idx + 1].0 - PAGE_SIZE, MAP_FIXED)
    } else {
        do_munmap(&mut areas, ctx_ref[CT_A0], length);
        idx = areas.iter().position(|&area| ctx_ref[CT_A0] < area.1).unwrap() - 1;
        (ctx_ref[CT_A0], ctx_ref[CT_A0] + length, 0x0)
    };
    let vm_flag = (ctx_ref[CT_A2] & VM_RWX) | if ctx_ref[CT_A3] & VM_STACK != 0x0 { VM_STACK } else { VM_SHARED };
    areas.insert(idx + 1, (vm_start, vm_end, vm_flag));
    ctx_ref[CT_A0] = vm_start;
    ctx_ref[CT_A3] |= flags;
    ctx_ref[CT_TMP] = 0x0;
}
fn check_mmap(vmareas: &Arc<RwLock<Vec<(u64, u64, u64)>>>, ctxt: *mut Context, ret: u64) {
    let ctx_ref = unsafe { &mut *ctxt };
    if (ctx_ref[CT_A0] & (PAGE_SIZE - 1)) != 0x0 || ctx_ref[CT_A1] == 0x0 || ctx_ref[CT_TMP] == 0x1 {
        if ret != MINUS_ONE { log_str(L_DEBUG, "check_mmap: warning\n\0"); }
        return;
    }
    if ret == MINUS_ONE {
        let mut areas = vmareas.write();
        do_munmap(&mut areas, ctx_ref[CT_A0], ctx_ref[CT_A1]);
    }
}
fn do_munmap(areas: &mut Vec<(u64, u64, u64)>, addr: u64, length: u64) {
    if (addr & (PAGE_SIZE - 1)) != 0x0 || length == 0x0 { return; }
    let length = (length - 1) / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE;
    let heap_id = get_heap_id(&*areas);
    if addr < areas[heap_id].1 || areas[areas.len() - 1].0 < addr + length { log_str(L_ERROR, "do_munmap: error\n\0"); }
    areas.retain(|&area| !(addr <= area.0 && area.1 <= addr + length));
    let idx = areas.iter().position(|&area| addr < area.1).unwrap();
    if areas[idx].0 < addr && addr + length < areas[idx].1 {
        areas.insert(idx + 1, (addr + length, areas[idx].1, areas[idx].2));
        areas[idx].1 = addr;
    } else if addr + length < areas[idx].1 { areas[idx].0 = addr + length; }
    else if areas[idx].0 < addr { areas[idx].1 = addr; }
}
fn check_munmap(_areas: &Arc<RwLock<Vec<(u64, u64, u64)>>>, ctxt: *mut Context, ret: u64) {
    let ctx_ref = unsafe { &mut *ctxt };
    if (ctx_ref[CT_A0] & (PAGE_SIZE - 1)) != 0x0 || ctx_ref[CT_A1] == 0x0 {
        if ret == 0x0 { log_str(L_ERROR, "check_munmap: error A\n\0"); }
    } else if ret != 0x0 { log_str(L_ERROR, "check_munmap: error B\n\0"); }
}
fn do_mprot(vmareas: &Arc<RwLock<Vec<(u64, u64, u64)>>>, ctxt: *mut Context) {
    let (ctx_ref, mut areas) = (unsafe { &mut *ctxt }, vmareas.write());
    if (ctx_ref[CT_A0] & (PAGE_SIZE - 1)) != 0x0 { log_str(L_ERROR, "do_mprot: error A\n\0"); }
    let length = (ctx_ref[CT_A1] - 1) / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE;
    let len = areas.len();
    if ctx_ref[CT_A0] < areas[TEXT_VMA_IDX].1 || areas[len - 1].0 < ctx_ref[CT_A0] + length { log_str(L_ERROR, "do_mprot: error B\n\0"); }
    for i in (TEXT_VMA_IDX + 1)..(len - 1) {
        if ctx_ref[CT_A0] <= areas[i].0 && areas[i].1 <= ctx_ref[CT_A0] + length {
            areas[i].2 = (areas[i].2 & !VM_RWX) | (ctx_ref[CT_A2] & VM_RWX);
        }
    }
    if let Some(idx) = areas.iter().position(|&area| area.0 <= ctx_ref[CT_A0] && ctx_ref[CT_A0] + length <= area.1) {
        if ctx_ref[CT_A0] + length < areas[idx].1 { let vma = (ctx_ref[CT_A0] + length, areas[idx].1, areas[idx].2); areas.insert(idx + 1, vma); }
        let vma = (ctx_ref[CT_A0], ctx_ref[CT_A0] + length, (areas[idx].2 & !VM_RWX) | (ctx_ref[CT_A2] & VM_RWX)); areas.insert(idx + 1, vma);
        if areas[idx].0 < ctx_ref[CT_A0] { areas[idx].1 = ctx_ref[CT_A0]; } else { areas.remove(idx); }
    } else {
        if let Some(idx) = areas.iter().position(|&area| area.0 < ctx_ref[CT_A0] && ctx_ref[CT_A0] < area.1 && area.1 < ctx_ref[CT_A0] + length) {
            let vma = (ctx_ref[CT_A0], areas[idx].1, (areas[idx].2 & !VM_RWX) | (ctx_ref[CT_A2] & VM_RWX)); areas.insert(idx + 1, vma);
            areas[idx].1 = ctx_ref[CT_A0];
        }
        if let Some(idx) = areas.iter().position(|&area| ctx_ref[CT_A0] < area.0 && area.0 < ctx_ref[CT_A0] + length && ctx_ref[CT_A0] + length < area.1) {
            let vma = (areas[idx].0, ctx_ref[CT_A0] + length, (areas[idx].2 & !VM_RWX) | (ctx_ref[CT_A2] & VM_RWX)); areas.insert(idx, vma);
            areas[idx + 1].0 = ctx_ref[CT_A0] + length;
        }
    }
}
pub fn get_heap_id(areas: &Vec<(u64, u64, u64)>) -> usize {
    areas.iter().position(|&area| area.2 & VM_HEAP != 0x0).unwrap()
}