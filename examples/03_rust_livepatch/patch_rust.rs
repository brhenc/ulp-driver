/*
 * ulp-driver: ULP Example 3 - Rust Livepatch Payload (cdylib)
 *
 * Implements the hotpatch replacement function in Rust.
 */

/*
 * REPLACEMENT FUNCTION: livepatch_rust_get_rate_limit
 *
 * Intercepts calls intended for rust_get_rate_limit().
 */
#[no_mangle]
#[inline(never)]
pub extern "C" fn livepatch_rust_get_rate_limit() -> u32 {
    5000
}
