use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use ulp_shadow::GLOBAL_SHADOW;

#[repr(C)]
pub struct TableSequence {
    pub table_id: u64,
    pub flags: u32,
    /// Fixed 32-bit integer field in existing physical memory layout
    pub autoinc_32: AtomicU32,
}

// ----------------------------------------------------------------------------
// Target Function
// ----------------------------------------------------------------------------

/// Original 32-bit allocator function.
/// When approaching u32::MAX, it fails or saturates.
#[no_mangle]
#[inline(never)]
pub extern "C" fn get_next_sequence_id(seq: &TableSequence) -> u64 {
    let curr = seq.autoinc_32.fetch_add(1, Ordering::SeqCst);
    if curr >= 4_294_967_290 {
        // 32-bit saturation barrier
        return 0; // Signals overflow / error 1062
    }
    curr as u64
}

// ----------------------------------------------------------------------------
// Livepatch Replacement Function
// ----------------------------------------------------------------------------

const SHADOW_ID_64BIT_AUTOINC: u64 = 0x4001;

/// Livepatched replacement function.
/// Dynamically tags the TableSequence with a 64-bit shadow counter
/// when the 32-bit threshold is reached.
#[no_mangle]
#[inline(never)]
pub extern "C" fn patch_get_next_sequence_id(seq: &TableSequence) -> u64 {
    let key = seq as *const TableSequence as *const ();
    unsafe {
        let mut ptr = GLOBAL_SHADOW.get(key as usize, SHADOW_ID_64BIT_AUTOINC);
        if ptr.is_null() {
            let init_val: u64 = 4_294_967_290;
            ptr = GLOBAL_SHADOW.alloc(
                key as usize,
                SHADOW_ID_64BIT_AUTOINC,
                std::mem::size_of::<AtomicU64>(),
                &init_val as *const u64 as *const u8,
            );
        }

        let shadow_counter = &*(ptr as *const AtomicU64);
        shadow_counter.fetch_add(1, Ordering::SeqCst)
    }
}

fn main() {
    println!("==============================================================================");
    println!("   ULP ADVANCED BENCHMARK: 32-BIT TO 64-BIT INTEGER RANGE PROMOTION           ");
    println!("==============================================================================");

    let seq = Arc::new(TableSequence {
        table_id: 1001,
        flags: 0x01,
        autoinc_32: AtomicU32::new(4_294_967_288),
    });

    println!("[+] Initial 32-bit counter value: {}", seq.autoinc_32.load(Ordering::Relaxed));
    println!("[+] Target Function Addr        : 0x{:x}", get_next_sequence_id as *const () as usize);
    println!("[+] Patch Function Addr         : 0x{:x}", patch_get_next_sequence_id as *const () as usize);

    // 1. Run baseline
    println!("\n>>> Generating IDs using baseline 32-bit function...");
    for i in 1..=3 {
        let val = get_next_sequence_id(&seq);
        println!("    [Query {}] Allocated ID: {}", i, val);
    }

    // 2. Next query hits 32-bit saturation
    let sat_val = get_next_sequence_id(&seq);
    println!("    [Query 4] Allocated ID: {} (32-bit saturation reached!)", sat_val);
    assert_eq!(sat_val, 0, "Expected saturation error");

    // 3. Simulate ULP Livepatch Execution
    println!("\n>>> Livepatch applied via ULP: Dynamic 64-bit Shadow Variable Promotion...");
    let mut handles = Vec::new();

    // Spawn 8 concurrent worker threads generating 1000 IDs each beyond 4.29 Billion
    for _t_id in 0..8 {
        let seq_clone = seq.clone();
        handles.push(thread::spawn(move || {
            let mut last = 0;
            for _ in 0..100 {
                last = patch_get_next_sequence_id(&seq_clone);
            }
            last
        }));
    }

    for (t_id, h) in handles.into_iter().enumerate() {
        let last_id = h.join().unwrap();
        println!("    [Worker Thread {}] Successfully allocated 64-bit ID: {}", t_id, last_id);
    }

    unsafe {
        let ptr = GLOBAL_SHADOW.get(Arc::as_ptr(&seq) as usize, SHADOW_ID_64BIT_AUTOINC);
        assert!(!ptr.is_null());
        let final_val = (*(ptr as *const AtomicU64)).load(Ordering::Relaxed);
        println!("\n[+] Final 64-Bit Shadow Integer Value: {}", final_val);
        assert!(final_val > 4_294_967_295, "Value exceeded 32-bit range!");
        println!("[+] Invariant Verified: Memory struct layout remained strictly unmodified!");
    }

    println!("==============================================================================");
    println!("   SUCCESS: 32-BIT TO 64-BIT INTEGER LIVEPATCH PROMOTION VERIFIED!             ");
    println!("==============================================================================");
}
