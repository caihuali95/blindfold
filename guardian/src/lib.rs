#![no_std]
#![allow(unused_imports)]
#![allow(non_snake_case)]
#![feature(btree_cursors)]

extern crate alloc;
pub use alloc::{ vec::Vec, sync::Arc, collections::BTreeMap };
pub use core::{ arch::asm, alloc::{ Layout, GlobalAlloc }, ops::Bound };
pub use linked_list_allocator::LockedHeap;
pub use synctools::rwlock::RwLock;

extern crate aes;
extern crate sha2;
extern crate hmac;
use aes::{ Aes128, cipher::{ BlockEncrypt, BlockDecrypt, generic_array::GenericArray } };
use sha2::Sha256;
use hmac::Hmac;
type HmacSha256 = Hmac<Sha256>;

pub mod secboot;
pub use secboot::*;

pub mod pagetable;
pub use pagetable::*;

pub mod senproc;
pub use senproc::*;

pub mod senctxt;
pub use senctxt::*;

pub mod uaccess;
pub use uaccess::*;

pub mod knowledge;
pub use knowledge::*;

pub mod util;
pub use util::*;

pub mod aarch64;
pub use aarch64::*;

pub mod crypto;
pub use crypto::*;

const GCALL_SET_PT:     u64 = 0xCA0;
const GCALL_SET_PTBR:   u64 = 0xCA1;
const GCALL_FREE_PGD:   u64 = 0xCA2;
const GCALL_CREATE_P:   u64 = 0xCA3;
const GCALL_FORKED_P:   u64 = 0xCA4;
const GCALL_RESUME_P:   u64 = 0xCA5;
const GCALL_INTRPT_P:   u64 = 0xCA6;
const GCALL_PUT_U:      u64 = 0xCA7;
const GCALL_CLR_U:      u64 = 0xCA8;
const GCALL_STL_U:      u64 = 0xCA9;
const GCALL_GET_U:      u64 = 0xCAA;
const GCALL_CFM_U:      u64 = 0xCAB;
const GCALL_CTO_U:      u64 = 0xCAC;
const GCALL_STC_U:      u64 = 0xCAD;

#[no_mangle]
pub extern "C" fn rsG_entry(cmd: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, ex: u64, bp: u64) -> u64 {
    match cmd {
        GCALL_SET_PT    => update_page_table(a1, a2, a3, a4),
        GCALL_SET_PTBR  => update_ptbr(a1, a2, bp),
        GCALL_FREE_PGD  => free_pgd(a1),
        GCALL_CREATE_P  => create_process(a1, a2, a3, a4),
        GCALL_FORKED_P  => forked_process(a1, a2, a3),
        GCALL_RESUME_P  => return resume_process(a1, a2, a3, a4, a5),           // return value decides how to return to sensitive process
        GCALL_INTRPT_P  => return interrupt_process(a1, ex, bp),                // return value decides how to return to kernel
        GCALL_PUT_U     => return put_user(a1, a2, a3, a4, a5, bp),             // succeed and continue, or page fault and retry
        GCALL_CLR_U     => return clear_user(a1, a2, a4, a5, bp),               // succeed and continue, or page fault and retry
        GCALL_STL_U     => return strlen_user(a1, a2, a4, a5, bp),              // succeed and continue, or page fault and retry
        GCALL_GET_U     => return get_user(a1, a2, a3, a4, a5, ex, bp),         // succeed and continue, or page fault and retry
        GCALL_CFM_U     => return copy_from_user(a1, a2, a3, a4, a5, ex, bp),   // succeed and continue, or page fault and retry
        GCALL_CTO_U     => return copy_to_user(a1, a2, a3, a4, a5, ex, bp),     // succeed and continue, or page fault and retry
        GCALL_STC_U     => return strcpy_user(a1, a2, a3, a4, a5, ex, bp),      // succeed and continue, or page fault and retry
        _ => log_strHex(L_ERROR, "rsG_entry: unknown cmd = 0x\0", cmd),
    }
    NORMAL
}