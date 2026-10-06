//! # libpatch_pgrust_v2: Generation 2 Runtime Livepatch for pgrust Daemon
//!
//! Hotfix: Dynamic Shadow Metrics & Adaptive Rate Limiting
//! - `pgrust_get_version` -> returns "pgrust 17.0.2-v2-shadow-metrics"
//! - `pgrust_process_query` -> enforces quota, flags rate limiting if count > 20, returns length + 2000

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
    let s = std::hint::black_box("pgrust 17.0.2-v2-shadow-metrics (Rust 1.85 ULP-Gen2)");
    std::hint::black_box(s);
    std::hint::black_box(s);
    s
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
        if count > 20 {
            metrics.is_rate_limited.store(true, Ordering::Relaxed);
        }
    }

    // Gen2 patched execution code (+2000)
    (query.len() as u32) + 2000
}
