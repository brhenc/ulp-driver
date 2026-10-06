//! # ULP Shadow Variables Library for Rust & C Userspace Livepatching
//!
//! Provides thread-safe, lock-striped dynamic shadow variables that attach
//! arbitrary extra fields, state, and metadata to existing heap-allocated structures
//! at runtime without altering their physical memory layout, alignment, or size.
//! Fully C ABI compatible with `ulp_shadow.h`.

use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use parking_lot::RwLock;

/// Number of striped buckets for concurrent, low-contention access
const NUM_BUCKETS: usize = 256;

#[derive(Debug)]
struct ShadowNode {
    id: u64,
    size: usize,
    ptr: *mut u8,
    layout: Layout,
}

unsafe impl Send for ShadowNode {}
unsafe impl Sync for ShadowNode {}

pub struct UlpShadowRegistry {
    buckets: Vec<RwLock<HashMap<usize, Vec<ShadowNode>>>>,
}

impl UlpShadowRegistry {
    pub fn new() -> Self {
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(RwLock::new(HashMap::new()));
        }
        Self { buckets }
    }

    #[inline]
    fn get_bucket_index(ptr_val: usize, field_id: u64) -> usize {
        let h = ptr_val ^ (field_id.wrapping_mul(0x9e3779b97f4a7c15) as usize);
        (h ^ (h >> 16)) % NUM_BUCKETS
    }

    /// Allocates or retrieves an existing shadow variable for an object address.
    pub unsafe fn alloc(
        &self,
        obj: usize,
        id: u64,
        size: usize,
        init_data: *const u8,
    ) -> *mut u8 {
        if obj == 0 || size == 0 {
            return std::ptr::null_mut();
        }

        let bucket_idx = Self::get_bucket_index(obj, id);
        let mut bucket = self.buckets[bucket_idx].write();
        let entries = bucket.entry(obj).or_insert_with(Vec::new);

        for node in entries.iter() {
            if node.id == id {
                return node.ptr;
            }
        }

        // Align to 16 bytes for safe atomic/SIMD operations
        let layout = match Layout::from_size_align(size, 16) {
            Ok(l) => l,
            Err(_) => match Layout::from_size_align(size, 8) {
                Ok(l) => l,
                Err(_) => return std::ptr::null_mut(),
            },
        };

        let mem = alloc(layout);
        if mem.is_null() {
            return std::ptr::null_mut();
        }

        if !init_data.is_null() {
            std::ptr::copy_nonoverlapping(init_data, mem, size);
        } else {
            std::ptr::write_bytes(mem, 0, size);
        }

        entries.push(ShadowNode {
            id,
            size,
            ptr: mem,
            layout,
        });

        mem
    }

    /// Retrieves an attached shadow variable pointer by object address and field ID.
    pub unsafe fn get(&self, obj: usize, id: u64) -> *mut u8 {
        if obj == 0 {
            return std::ptr::null_mut();
        }

        let bucket_idx = Self::get_bucket_index(obj, id);
        let bucket = self.buckets[bucket_idx].read();
        if let Some(entries) = bucket.get(&obj) {
            for node in entries.iter() {
                if node.id == id {
                    return node.ptr;
                }
            }
        }

        std::ptr::null_mut()
    }

    /// Frees a specific shadow variable on an object.
    pub unsafe fn free(&self, obj: usize, id: u64) {
        if obj == 0 {
            return;
        }

        let bucket_idx = Self::get_bucket_index(obj, id);
        let mut bucket = self.buckets[bucket_idx].write();
        if let Some(entries) = bucket.get_mut(&obj) {
            if let Some(pos) = entries.iter().position(|e| e.id == id) {
                let node = entries.remove(pos);
                dealloc(node.ptr, node.layout);
            }
            if entries.is_empty() {
                bucket.remove(&obj);
            }
        }
    }

    /// Clears all shadow variables attached to an object (typically called in Drop/free).
    pub unsafe fn clear_all(&self, obj: usize) {
        if obj == 0 {
            return;
        }

        for bucket in &self.buckets {
            let mut b = bucket.write();
            if let Some(entries) = b.remove(&obj) {
                for node in entries {
                    dealloc(node.ptr, node.layout);
                }
            }
        }
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_SHADOW: UlpShadowRegistry = UlpShadowRegistry::new();
}

// ----------------------------------------------------------------------------
// Exported C ABI Functions (Identical to ulp_shadow.h)
// ----------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ulp_shadow_alloc(
    obj: *const (),
    id: u64,
    size: usize,
    init_data: *const u8,
) -> *mut u8 {
    GLOBAL_SHADOW.alloc(obj as usize, id, size, init_data)
}

#[no_mangle]
pub unsafe extern "C" fn ulp_shadow_get(
    obj: *const (),
    id: u64,
) -> *mut u8 {
    GLOBAL_SHADOW.get(obj as usize, id)
}

#[no_mangle]
pub unsafe extern "C" fn ulp_shadow_free(
    obj: *const (),
    id: u64,
) {
    GLOBAL_SHADOW.free(obj as usize, id);
}

#[no_mangle]
pub unsafe extern "C" fn ulp_shadow_clear_all(
    obj: *const (),
) {
    GLOBAL_SHADOW.clear_all(obj as usize);
}

// ----------------------------------------------------------------------------
// Canonical Shadow Structure Example
// ----------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug)]
pub struct ShadowMetrics {
    pub query_counter: AtomicU64,
    pub is_rate_limited: AtomicBool,
}

impl Default for ShadowMetrics {
    fn default() -> Self {
        Self {
            query_counter: AtomicU64::new(0),
            is_rate_limited: AtomicBool::new(false),
        }
    }
}

// ----------------------------------------------------------------------------
// Ergonomic Rust Trait Extension
// ----------------------------------------------------------------------------

pub trait UlpShadowExt {
    fn shadow_addr(&self) -> usize;

    unsafe fn shadow_alloc<T>(&self, id: u64, init: Option<T>) -> *mut T {
        let size = std::mem::size_of::<T>();
        if let Some(val) = init {
            let val_box = Box::new(val);
            let ptr = ulp_shadow_alloc(
                self.shadow_addr() as *const (),
                id,
                size,
                Box::into_raw(val_box) as *const u8,
            );
            ptr as *mut T
        } else {
            let ptr = ulp_shadow_alloc(
                self.shadow_addr() as *const (),
                id,
                size,
                std::ptr::null(),
            );
            ptr as *mut T
        }
    }

    unsafe fn shadow_get<T>(&self, id: u64) -> Option<&'static T> {
        let ptr = ulp_shadow_get(self.shadow_addr() as *const (), id);
        if ptr.is_null() {
            None
        } else {
            Some(&*(ptr as *const T))
        }
    }

    unsafe fn shadow_get_mut<T>(&self, id: u64) -> Option<&'static mut T> {
        let ptr = ulp_shadow_get(self.shadow_addr() as *const (), id);
        if ptr.is_null() {
            None
        } else {
            Some(&mut *(ptr as *mut T))
        }
    }

    unsafe fn shadow_free(&self, id: u64) {
        ulp_shadow_free(self.shadow_addr() as *const (), id);
    }

    unsafe fn shadow_clear_all(&self) {
        ulp_shadow_clear_all(self.shadow_addr() as *const ());
    }
}

impl<T: ?Sized> UlpShadowExt for Arc<T> {
    fn shadow_addr(&self) -> usize {
        Arc::as_ptr(self) as *const () as usize
    }
}

impl<T: ?Sized> UlpShadowExt for &T {
    fn shadow_addr(&self) -> usize {
        (*self) as *const T as *const () as usize
    }
}

impl<T: ?Sized> UlpShadowExt for &mut T {
    fn shadow_addr(&self) -> usize {
        (*self) as *const T as *const () as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::thread;

    struct DummyConn {
        id: u32,
    }

    #[test]
    fn test_concurrent_shadow_allocation() {
        let conn = Arc::new(DummyConn { id: 101 });
        let num_threads = 16;
        let iters = 1000;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let c = conn.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..iters {
                    unsafe {
                        let ptr = c.shadow_alloc::<ShadowMetrics>(0x2001, None);
                        let metrics = &*(ptr as *const ShadowMetrics);
                        metrics.query_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        unsafe {
            let metrics = conn.shadow_get::<ShadowMetrics>(0x2001).expect("Shadow not found");
            assert_eq!(metrics.query_counter.load(Ordering::Relaxed), (num_threads * iters) as u64);
            conn.shadow_clear_all();
            assert!(conn.shadow_get::<ShadowMetrics>(0x2001).is_none());
        }
    }
}
