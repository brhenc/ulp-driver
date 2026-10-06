//! # libpatch_pgrust: Runtime Livepatch for pgrust Daemon
//!
//! Provides replacement machine code functions for:
//! 1. `pgrust_get_version` -> returns updated livepatch banner
//! 2. `pgrust_process_query` -> dynamically attaches & increments ShadowMetrics

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[repr(C)]
pub struct PgConnection {
    pub id: u32,
    pub user_id: u32,
    pub created_at: u64,
}

#[repr(C)]
pub struct ShadowMetrics {
    pub query_counter: AtomicU64,
    pub is_rate_limited: AtomicBool,
}

extern "C" {
    pub fn ulp_shadow_alloc(
        obj: *const (),
        id: u64,
        size: usize,
        init_data: *const u8,
    ) -> *mut u8;

    pub fn ulp_shadow_get(
        obj: *const (),
        id: u64,
    ) -> *mut u8;
}

#[no_mangle]
#[inline(never)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn patch_pgrust_get_version() -> &'static str {
    "pgrust 17.0.0-LIVEPATCHED (Rust 1.98 SMP ULP)"
}

#[no_mangle]
#[inline(never)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn patch_pgrust_process_query(conn: &PgConnection, query: &str) -> u32 {
    let key = conn as *const PgConnection as *const ();
    let mut ptr = unsafe { ulp_shadow_get(key, 0x2001) };
    if ptr.is_null() {
        ptr = unsafe {
            ulp_shadow_alloc(
                key,
                0x2001,
                std::mem::size_of::<ShadowMetrics>(),
                std::ptr::null(),
            )
        };
    }

    if !ptr.is_null() {
        let metrics = unsafe { &*(ptr as *const ShadowMetrics) };
        let count = metrics.query_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if count > 50 {
            metrics.is_rate_limited.store(true, Ordering::Relaxed);
        }
    }

    // Patched return code (+1000 signifies livepatched execution)
    (query.len() as u32) + 1000
}
